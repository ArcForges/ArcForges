# SPDX-License-Identifier: AGPL-3.0-only
"""Bounded, non-executing inspection of the six admitted native runtime formats.

Inspection describes bytes, not their trust or provenance. Consumers separately
bind source, signatures, legal material and the complete dependency closure.
"""
from dataclasses import dataclass
from bisect import bisect_right
from pathlib import Path
import struct

MAX_FILE = 256 * 1024 * 1024
MAX_TABLE = 100000
MAX_NAME = 4096
MAX_SEGMENTS = 8192
RIDS = {
    "win-x64": ("PE32+", "x86_64"), "win-arm64": ("PE32+", "aarch64"),
    "linux-x64": ("ELF64", "x86_64"), "linux-arm64": ("ELF64", "aarch64"),
    "osx-x64": ("Mach-O64", "x86_64"), "osx-arm64": ("Mach-O64", "aarch64"),
}


def require(condition, message):
    if not condition:
        raise ValueError(message)


@dataclass(frozen=True)
class BinaryInfo:
    format: str
    machine: str
    exports: tuple[str, ...]
    imports: tuple[str, ...]
    identity: str | None
    runpaths: tuple[str, ...] = ()
    forwarded_exports: tuple[str, ...] = ()
    data_exports: tuple[str, ...] = ()
    unnamed_exports: int = 0
    absolute_exports: tuple[str, ...] = ()
    version_requirements: tuple[str, ...] = ()
    minimum_os: str | None = None

    def as_manifest(self):
        return {
            "format": self.format, "machine": self.machine,
            "exports": list(self.exports), "imports": list(self.imports),
            "identity": self.identity, "runpaths": list(self.runpaths),
            "forwardedExports": list(self.forwarded_exports),
            "dataExports": list(self.data_exports), "unnamedExports": self.unnamed_exports,
            "absoluteExports": list(self.absolute_exports),
            "versionRequirements": list(self.version_requirements), "minimumOs": self.minimum_os,
        }


class Reader:
    def __init__(self, data):
        require(isinstance(data, bytes) and 0 < len(data) <= MAX_FILE, "Unbounded or empty native file.")
        self.data = data
        self.view = memoryview(data)

    def span(self, start, size):
        require(type(start) is int and type(size) is int and start >= 0 and size >= 0 and
                start <= len(self.data) and size <= len(self.data) - start, "Native range escapes file.")
        return self.view[start:start + size]

    def unpack(self, fmt, offset):
        self.span(offset, struct.calcsize(fmt))
        return struct.unpack_from(fmt, self.data, offset)

    def string(self, start, limit=None):
        self.span(start, 1)
        end_limit = min(len(self.data), start + MAX_NAME, limit if limit is not None else len(self.data))
        end = self.data.find(b"\0", start, end_limit)
        require(end >= start, "Unterminated or unbounded native name.")
        try:
            value = self.data[start:end].decode("ascii")
        except UnicodeDecodeError as error:
            raise ValueError("Native linkage name is not ASCII.") from error
        require(value and all(32 <= ord(c) < 127 for c in value), "Invalid native linkage name.")
        return value


def _sorted(values):
    require(len(values) <= MAX_TABLE, "Unbounded native linkage inventory.")
    return tuple(sorted(set(values)))


class AddressIndex:
    """Nonoverlapping half-open mappings, with logarithmic lookup work."""
    def __init__(self, ranges):
        require(len(ranges) <= MAX_SEGMENTS, "Unbounded native mapped ranges.")
        self.ranges = sorted(ranges)
        self.starts = [row[0] for row in self.ranges]
        previous_end = 0
        for start, size, *_ in self.ranges:
            require(start >= previous_end and size > 0 and start + size <= 1 << 64,
                    "Overlapping or invalid native mapped ranges.")
            previous_end = start + size

    def find(self, address, size=1):
        require(address >= 0 and size > 0 and address + size <= 1 << 64,
                "Invalid native virtual range.")
        index = bisect_right(self.starts, address) - 1
        if index >= 0:
            row = self.ranges[index]
            if size <= row[1] - (address - row[0]):
                return row
        return None


def inspect(path, rid):
    path = Path(path)
    require(not path.is_symlink() and path.is_file(), "Native input must be a regular, non-link file.")
    with path.open("rb") as stream:
        data = stream.read(MAX_FILE + 1)
    return inspect_bytes(data, rid)


def inspect_bytes(data, rid):
    require(rid in RIDS, "Native RID is not admitted.")
    reader = Reader(data)
    if data[:2] == b"MZ":
        result = _pe(reader)
    elif data[:4] == b"\x7fELF":
        result = _elf(reader)
    elif data[:4] == b"\xcf\xfa\xed\xfe":
        result = _mach(reader)
    else:
        raise ValueError("Native file is not admitted PE32+, ELF64 or thin little-endian Mach-O64.")
    require((result.format, result.machine) == RIDS[rid], "Native format/architecture differs from RID.")
    return result


def _pe(r):
    header = r.unpack("<I", 0x3c)[0]
    require(header >= 0x40 and r.span(header, 4) == b"PE\0\0", "Invalid PE signature.")
    machine, count, _, _, _, optional_size, characteristics = r.unpack("<HHIIIHH", header + 4)
    require(machine in (0x8664, 0xaa64) and 0 < count <= 96 and characteristics & 0x2000,
            "PE input must be an admitted shared library.")
    optional = header + 24
    require(optional_size >= 112 and r.unpack("<H", optional)[0] == 0x20b, "Native PE is not PE32+.")
    r.span(optional, optional_size)
    image_base = r.unpack("<Q", optional + 24)[0]
    header_size = r.unpack("<I", optional + 60)[0]
    directories = r.unpack("<I", optional + 108)[0]
    require(directories <= 16 and 112 + directories * 8 <= optional_size, "Invalid PE data directories.")
    table = optional + optional_size
    r.span(table, count * 40)
    require(table + count * 40 <= header_size <= len(r.data), "Invalid PE header size.")
    sections = []
    for index in range(count):
        virtual_size, address, raw_size, raw = r.unpack("<IIII", table + index * 40 + 8)
        flags = r.unpack("<I", table + index * 40 + 36)[0]
        require(address > 0 and address + max(virtual_size, raw_size) <= 0x100000000, "Invalid PE section address.")
        if raw_size:
            require(raw >= header_size, "PE section overlaps headers.")
            r.span(raw, raw_size)
        for old_address, old_virtual, old_raw, old_size, _ in sections:
            require(not (address < old_address + old_virtual and old_address < address + max(virtual_size, raw_size)),
                    "Overlapping PE virtual sections.")
            require(not raw_size or not old_size or not (raw < old_raw + old_size and old_raw < raw + raw_size),
                    "Overlapping PE raw sections.")
        sections.append((address, max(virtual_size, raw_size), raw, raw_size, flags))

    def mapped(address, size=1):
        if address < header_size:
            require(size <= header_size - address, "PE header RVA escapes header.")
            return address, header_size, 0
        found = [(raw + address - start, raw + raw_size, flags)
                 for start, _, raw, raw_size, flags in sections
                 if start <= address and address - start < raw_size and size <= raw_size - (address - start)]
        require(len(found) == 1, "Unmapped or ambiguous PE RVA.")
        return found[0]

    def name(address):
        begin, limit, _ = mapped(address)
        return r.string(begin, limit)

    def export_flags(address):
        matches = [flags for start, virtual_size, _, _, flags in sections
                   if start <= address < start + virtual_size]
        require(len(matches) == 1, "Unmapped or ambiguous PE export address.")
        return matches[0]

    def directory(index):
        if index >= directories:
            return 0, 0
        address, size = r.unpack("<II", optional + 112 + index * 8)
        require(bool(address) == bool(size), "Incomplete PE directory.")
        if address:
            mapped(address, size)
        return address, size

    imports = []
    for number, stride, name_offset in ((1, 20, 12), (13, 32, 4)):
        address, size = directory(number)
        if not address:
            continue
        begin, _, _ = mapped(address, size)
        require(stride <= size and size // stride <= MAX_TABLE, "Unbounded PE import table.")
        terminated = False
        for index in range(size // stride):
            entry = r.span(begin + index * stride, stride)
            if not any(entry):
                terminated = True
                break
            name_address = struct.unpack_from("<I", entry, name_offset)[0]
            if number == 13:
                attributes = struct.unpack_from("<I", entry)[0]
                require(attributes in (0, 1), "Unknown PE delay import attributes.")
                if attributes == 0:
                    require(name_address >= image_base, "Invalid PE delay import address.")
                    name_address -= image_base
            imports.append(name(name_address))
        require(terminated, "Unterminated PE import table.")
    exports, forwarded, data = [], [], []
    unnamed = 0
    identity = None
    address, size = directory(0)
    if address:
        require(size >= 40, "Truncated PE export directory.")
        begin, _, _ = mapped(address, 40)
        identity = name(r.unpack("<I", begin + 12)[0])
        functions, names, functions_address, names_address, ordinals_address = r.unpack("<IIIII", begin + 20)
        require(0 < functions <= MAX_TABLE and names <= functions, "Unbounded PE export tables.")
        fbegin = mapped(functions_address, functions * 4)[0]
        nbegin = mapped(names_address, names * 4)[0] if names else 0
        obegin = mapped(ordinals_address, names * 2)[0] if names else 0
        used = set()
        all_names = set()
        for index in range(names):
            export_name = name(r.unpack("<I", nbegin + index * 4)[0])
            ordinal = r.unpack("<H", obegin + index * 2)[0]
            require(ordinal < functions and export_name not in all_names, "Invalid or duplicate PE export.")
            all_names.add(export_name)
            used.add(ordinal)
            target = r.unpack("<I", fbegin + ordinal * 4)[0]
            require(target != 0, "Named PE export is absent.")
            if address <= target < address + size:
                name(target)  # Bound the forwarding string, too.
                forwarded.append(export_name)
            elif export_flags(target) & 0x20000000:
                mapped(target)  # Callable code must have actual bytes, unlike zero-fill data.
                exports.append(export_name)
            else:
                data.append(export_name)
        unnamed = sum(r.unpack("<I", fbegin + index * 4)[0] != 0 and index not in used for index in range(functions))
    return BinaryInfo("PE32+", "x86_64" if machine == 0x8664 else "aarch64", _sorted(exports),
                      _sorted(imports), identity, forwarded_exports=_sorted(forwarded),
                      data_exports=_sorted(data), unnamed_exports=unnamed)


def _elf(r):
    require(r.span(0, 7) == b"\x7fELF\x02\x01\x01", "Native ELF must be 64-bit little-endian version1.")
    kind, machine, version = r.unpack("<HHI", 16)
    require(kind == 3 and machine in (62, 183) and version == 1, "ELF input is not an admitted shared library.")
    program, sections = r.unpack("<QQ", 32)
    header_size, program_size, program_count, section_size, section_count, _ = r.unpack("<HHHHHH", 52)
    require(header_size == 64 and program_size == 56 and 0 < program_count <= 8192 and
            section_size == 64 and 0 < section_count <= 8192, "Invalid or unbounded ELF tables.")
    r.span(program, program_count * program_size)
    r.span(sections, section_count * section_size)
    loads, dynamic = [], []
    for index in range(program_count):
        tag, flags, offset, address, _, file_size, memory_size, _ = r.unpack("<IIQQQQQQ", program + index * 56)
        require(file_size <= memory_size, "Invalid ELF segment size.")
        r.span(offset, file_size)
        if tag == 1:
            if file_size:
                loads.append((address, file_size, offset, flags))
        elif tag == 2:
            dynamic.append((offset, address, file_size))
    require(loads and len(dynamic) == 1, "ELF shared library has no unique dynamic table.")
    load_index = AddressIndex(loads)

    def mapped(address, size=1):
        row = load_index.find(address, size)
        require(row is not None, "Unmapped ELF virtual address.")
        start, _, offset, flags = row
        return offset + address - start, flags

    begin, dynamic_address, length = dynamic[0]
    require(length >= 16 and length % 16 == 0 and length // 16 <= MAX_TABLE, "Unbounded ELF dynamic table.")
    require(mapped(dynamic_address, length)[0] == begin, "ELF dynamic virtual/file mapping differs.")
    tags = {}
    terminated = False
    for index in range(length // 16):
        tag, value = r.unpack("<qQ", begin + index * 16)
        if tag == 0:
            terminated = True
            break
        tags.setdefault(tag, []).append(value)
    require(terminated, "Unterminated ELF dynamic table.")

    def single(tag, default=None):
        values = tags.get(tag, [])
        require(len(values) <= 1, "Duplicate singleton ELF dynamic tag.")
        return values[0] if values else default

    strings, string_size = single(5), single(10)
    require(strings is not None and string_size and string_size <= MAX_FILE, "Missing ELF dynamic strings.")
    string_begin = mapped(strings, string_size)[0]

    def name(offset):
        require(0 <= offset < string_size, "ELF string offset escapes table.")
        return r.string(string_begin + offset, string_begin + string_size)

    imports = [name(value) for value in tags.get(1, [])]
    identity = name(single(14)) if single(14) is not None else None
    paths = []
    for tag in (15, 29):
        value = single(tag)
        if value is not None:
            paths.extend(name(value).split(":"))
    exports, data, absolute, forwarded = [], [], [], []
    symbol_address, symbol_stride = single(6), single(11)
    require(symbol_address is not None and symbol_stride == 24, "Invalid ELF dynamic symbol contract.")
    symbol_offset = mapped(symbol_address, 24)[0]
    symbol_sections = []
    for index in range(section_count):
        _, section_kind, _, _, offset, size, link, _, _, stride = r.unpack("<IIQQQQIIQQ", sections + index * 64)
        if section_kind != 8:
            r.span(offset, size)
        if section_kind == 11:
            require(stride == 24 and size % stride == 0 and size // stride <= MAX_TABLE and link < section_count,
                    "Invalid ELF dynamic symbol table.")
            linked = r.unpack("<IIQQQQIIQQ", sections + link * 64)
            require(linked[1] == 3 and linked[4] == string_begin and linked[5] == string_size,
                    "ELF linked symbol strings differ from dynamic strings.")
            symbol_sections.append((offset, size))
    require(len(symbol_sections) == 1 and symbol_sections[0][0] == symbol_offset,
            "ELF dynamic symbols differ from the file table.")
    require(mapped(symbol_address, symbol_sections[0][1])[0] == symbol_offset,
            "ELF dynamic symbols escape their load mapping.")
    for index in range(symbol_sections[0][1] // 24):
        name_offset, info, other, section, address, _ = r.unpack("<IBBHQQ", symbol_offset + index * 24)
        if not name_offset or section == 0 or info >> 4 not in (1, 2) or other & 3 in (1, 2):
            continue
        symbol_name = name(name_offset)
        if section == 0xfff1:
            absolute.append(symbol_name)
        elif info & 15 in (2, 10):
            require(mapped(address)[1] & 1, "ELF callable export is not executable.")
            (forwarded if info & 15 == 10 else exports).append(symbol_name)
        else:
            data.append(symbol_name)
    requirements = []
    need_address, need_count = single(0x6ffffffe), single(0x6fffffff, 0)
    require(bool(need_address) == bool(need_count) and need_count <= 4096, "Invalid ELF version requirements.")
    visited = set()
    for index in range(need_count):
        require(need_address not in visited, "Cyclic ELF version requirements.")
        visited.add(need_address)
        offset = mapped(need_address, 16)[0]
        version, auxiliary_count, file_name, auxiliary, next_need = r.unpack("<HHIII", offset)
        require(version == 1 and 0 < auxiliary_count <= 4096, "Invalid ELF version need record.")
        name(file_name)
        auxiliary_address = need_address + auxiliary
        seen = set()
        for auxiliary_index in range(auxiliary_count):
            require(auxiliary_address not in seen, "Cyclic ELF auxiliary version requirements.")
            seen.add(auxiliary_address)
            aux_offset = mapped(auxiliary_address, 16)[0]
            _, _, _, version_name, next_aux = r.unpack("<IHHII", aux_offset)
            require(len(requirements) < MAX_TABLE, "Unbounded ELF version requirement inventory.")
            requirements.append(name(version_name))
            require((auxiliary_index + 1 < auxiliary_count) == bool(next_aux), "Invalid ELF auxiliary version chain.")
            auxiliary_address += next_aux
        require((index + 1 < need_count) == bool(next_need), "Invalid ELF version chain.")
        need_address += next_need
    return BinaryInfo("ELF64", "x86_64" if machine == 62 else "aarch64", _sorted(exports),
                      _sorted(imports), identity, tuple(paths), forwarded_exports=_sorted(forwarded), data_exports=_sorted(data),
                      absolute_exports=_sorted(absolute), version_requirements=_sorted(requirements))


def _mach(r):
    _, cpu, _, kind, count, command_size, _, _ = r.unpack("<IIIIIIII", 0)
    require(cpu in (0x01000007, 0x0100000c) and kind == 6 and 0 < count <= 8192,
            "Mach-O input is not an admitted thin shared library.")
    r.span(32, command_size)
    cursor, imports, paths, executable = 32, [], [], []
    identity = minimum_os = None
    symbol_table = trie = None
    bases = []
    total_sections = 0
    for _ in range(count):
        command, length = r.unpack("<II", cursor)
        require(length >= 8 and length % 8 == 0 and cursor + length <= 32 + command_size,
                "Invalid Mach-O load command.")
        if command in (0xc, 0xd, 0x80000018, 0x8000001f, 0x80000023):
            require(length >= 24, "Truncated Mach-O dylib command.")
            offset = r.unpack("<I", cursor + 8)[0]
            require(24 <= offset < length, "Invalid Mach-O dylib name offset.")
            value = r.string(cursor + offset, cursor + length)
            if command == 0xd:
                require(identity is None, "Duplicate Mach-O install identity.")
                identity = value
            else:
                imports.append(value)
        elif command == 0x8000001c:
            require(length >= 16, "Truncated Mach-O runpath command.")
            offset = r.unpack("<I", cursor + 8)[0]
            require(12 <= offset < length, "Invalid Mach-O runpath offset.")
            paths.append(r.string(cursor + offset, cursor + length))
        elif command == 0x19:
            require(length >= 72, "Truncated Mach-O segment command.")
            address, memory_size, offset, file_size, _, protections, section_count, _ = r.unpack("<QQQQIIII", cursor + 24)
            require(file_size <= memory_size and address + memory_size <= 1 << 64,
                    "Invalid Mach-O segment size.")
            r.span(offset, file_size)
            if file_size and offset == 0:
                bases.append(address)
            require(section_count <= 8192 and length == 72 + section_count * 80, "Invalid Mach-O sections.")
            total_sections += section_count
            require(total_sections <= MAX_SEGMENTS, "Unbounded aggregate Mach-O sections.")
            for index in range(section_count):
                section = cursor + 72 + index * 80
                section_address, section_size, raw = r.unpack("<QQI", section + 32)
                flags = r.unpack("<I", section + 64)[0]
                # Zero-fill sections have no file bytes; executable sections never are zero-fill.
                zero_fill = flags & 0xff in (1, 12, 18)
                require(address <= section_address and section_size <= memory_size and
                        section_address - address <= memory_size - section_size,
                        "Mach-O section escapes segment memory.")
                if not zero_fill:
                    require(section_size <= file_size and section_address - address <= file_size - section_size and
                            raw == offset + section_address - address,
                            "Mach-O section virtual/file mapping differs.")
                    r.span(raw, section_size)
                if flags & 0x80000400:
                    require(not zero_fill and protections & 4,
                            "Invalid Mach-O executable section.")
                    if section_size:
                        executable.append((section_address, section_size))
        elif command == 2:
            require(length == 24 and symbol_table is None, "Invalid Mach-O symbol command.")
            symbol_table = r.unpack("<IIII", cursor + 8)
        elif command in (0x22, 0x80000022):
            require(length == 48, "Invalid Mach-O dyld info command.")
            offset, size = r.unpack("<II", cursor + 40)
            if size:
                require(trie is None, "Duplicate Mach-O export trie.")
                trie = (offset, size)
        elif command == 0x80000033:
            require(length == 16 and trie is None, "Invalid Mach-O export trie command.")
            trie = r.unpack("<II", cursor + 8)
        elif command == 0x32:
            require(length >= 24 and minimum_os is None, "Invalid Mach-O build version.")
            platform, minimum, _, tools = r.unpack("<IIII", cursor + 8)
            require(platform == 1 and tools <= 4096 and length == 24 + tools * 8, "Unknown Mach-O platform.")
            minimum_os = f"{minimum >> 16}.{(minimum >> 8) & 255}.{minimum & 255}"
        elif command == 0x24:
            require(length == 16 and minimum_os is None, "Invalid Mach-O minimum version.")
            minimum = r.unpack("<I", cursor + 8)[0]
            minimum_os = f"{minimum >> 16}.{(minimum >> 8) & 255}.{minimum & 255}"
        cursor += length
    require(cursor == 32 + command_size and identity and len(bases) == 1, "Incomplete Mach-O shared library.")
    executable_index = AddressIndex(executable)
    exports, forwarded, data, absolute = [], [], [], []

    def classify(name, address, flags=0):
        require(name.startswith("_") and len(name) > 1, "Invalid Mach-O exported C name.")
        name = name[1:]
        if flags & (8 | 16):
            forwarded.append(name)
        elif flags & 3 == 2:
            absolute.append(name)
        elif flags & 3 == 1 or executable_index.find(address) is None:
            data.append(name)
        else:
            exports.append(name)

    if trie is not None:
        begin, size = trie
        r.span(begin, size)
        require(0 < size <= 16 * 1024 * 1024, "Unbounded Mach-O export trie.")
        end = begin + size

        def uleb(cursor, limit):
            value = 0
            for shift in range(0, 70, 7):
                require(cursor < limit, "Truncated Mach-O variable integer.")
                byte = r.data[cursor]
                cursor += 1
                require(shift < 63 or byte <= 1, "Overflowing Mach-O variable integer.")
                value |= (byte & 127) << shift
                if byte < 128:
                    return value, cursor
            raise ValueError("Unbounded Mach-O variable integer.")

        pending, visited, names = [(0, "", 0)], set(), set()
        while pending:
            offset, prefix, depth = pending.pop()
            require(offset < size and offset not in visited and len(visited) < MAX_TABLE and depth <= 256,
                    "Cyclic, duplicate or unbounded Mach-O export trie.")
            visited.add(offset)
            cursor = begin + offset
            terminal, cursor = uleb(cursor, end)
            require(terminal <= end - cursor, "Mach-O export terminal escapes trie.")
            terminal_end = cursor + terminal
            if terminal:
                require(prefix not in names, "Duplicate Mach-O export name.")
                names.add(prefix)
                flags, value_cursor = uleb(cursor, terminal_end)
                require(flags & ~0x3f == 0 and flags & 3 != 3, "Unknown Mach-O export flags.")
                address, value_cursor = uleb(value_cursor, terminal_end)
                if flags & 8:
                    # Empty re-export name means the same name. Bound non-empty spellings.
                    require(value_cursor < terminal_end, "Missing Mach-O forwarded name.")
                    if r.data[value_cursor] == 0:
                        value_cursor += 1
                    else:
                        forwarded_name = r.string(value_cursor, terminal_end)
                        value_cursor += len(forwarded_name) + 1
                elif flags & 16:
                    _, value_cursor = uleb(value_cursor, terminal_end)
                require(value_cursor == terminal_end, "Unexpected Mach-O terminal bytes.")
                classify(prefix, bases[0] + address, flags)
            cursor = terminal_end
            require(cursor < end, "Missing Mach-O trie children.")
            children = r.data[cursor]
            cursor += 1
            for _ in range(children):
                edge = r.string(cursor, end)
                cursor += len(edge) + 1
                child, cursor = uleb(cursor, end)
                require(len(prefix) + len(edge) < MAX_NAME, "Unbounded Mach-O export name.")
                require(len(pending) + len(visited) < MAX_TABLE, "Unbounded Mach-O export work queue.")
                pending.append((child, prefix + edge, depth + 1))
    else:
        require(symbol_table is not None, "Mach-O shared library has no export information.")
        offset, count, string_begin, string_size = symbol_table
        require(count <= MAX_TABLE and 0 < string_size <= MAX_FILE, "Unbounded Mach-O symbol table.")
        r.span(offset, count * 16)
        r.span(string_begin, string_size)
        for index in range(count):
            name_offset, flags, _, _, address = r.unpack("<IBBHQ", offset + index * 16)
            if flags & 0xe0 or not flags & 1 or flags & 0xe == 0:
                continue
            require(0 < name_offset < string_size, "Mach-O symbol string escapes table.")
            value = r.string(string_begin + name_offset, string_begin + string_size)
            if flags & 0xe == 0xa:
                forwarded.append(value.removeprefix("_"))
            else:
                classify(value, address, 2 if flags & 0xe == 2 else 0)
    all_exports = exports + forwarded + data + absolute
    require(len(all_exports) == len(set(all_exports)), "Duplicate Mach-O linkage export.")
    return BinaryInfo("Mach-O64", "x86_64" if cpu == 0x01000007 else "aarch64", _sorted(exports),
                      _sorted(imports), identity, tuple(paths), _sorted(forwarded), _sorted(data),
                      absolute_exports=_sorted(absolute), minimum_os=minimum_os)
