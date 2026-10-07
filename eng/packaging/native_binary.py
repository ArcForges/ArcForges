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
    kind: str = "shared-library"
    entrypoint: int | None = None

    def as_manifest(self):
        result = {
            "format": self.format, "machine": self.machine,
            "exports": list(self.exports), "imports": list(self.imports),
            "identity": self.identity, "runpaths": list(self.runpaths),
            "forwardedExports": list(self.forwarded_exports),
            "dataExports": list(self.data_exports), "unnamedExports": self.unnamed_exports,
            "absoluteExports": list(self.absolute_exports),
            "versionRequirements": list(self.version_requirements), "minimumOs": self.minimum_os,
        }
        if self.kind == "executable":
            result.update(kind=self.kind, entryPoint=self.entrypoint)
        return result


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


def inspect_executable(path, rid):
    """Describe a native executable, never compiler provenance, authorization or OS execution.

    EntryPoint is the PE RVA or ELF/Mach virtual address declared by the input.
    The existing shared-library entry points and manifests remain unchanged.
    """
    path = Path(path)
    require(not path.is_symlink() and path.is_file(), "Native input must be a regular, non-link file.")
    with path.open("rb") as stream:
        data = stream.read(MAX_FILE + 1)
    return _inspect_bytes(data, rid, executable=True)


def inspect_bytes(data, rid):
    return _inspect_bytes(data, rid, executable=False)


def _macho_signature_layout(data, rid):
    """Extract only transformation boundaries; the ordinary inspector validates code mappings."""
    info = _inspect_bytes(data, rid, executable=True)
    r = Reader(data)
    count, size = r.unpack("<II", 16)
    commands, signature, linkedit, occupied = [], None, None, []
    cursor = 32

    def payload(offset, length):
        if length:
            r.span(offset, length)
            occupied.append((offset, offset + length))

    for _ in range(count):
        tag, length = r.unpack("<II", cursor)
        command = bytes(r.span(cursor, length))
        if tag == 0x1d:
            require(length == 16 and signature is None, "Duplicate or invalid Mach signature command.")
            signature = (cursor, *r.unpack("<II", cursor + 8))
        else:
            commands.append((cursor, tag, command))
        if tag == 0x19:
            name = command[8:24].rstrip(b"\0")
            address, memory, offset, extent, maximum, protections, sections, _ = r.unpack("<QQQQIIII", cursor + 24)
            if name == b"__LINKEDIT":
                require(linkedit is None and length == 72 and sections == 0 and
                        not (maximum | protections) & 4 and extent > 0 and
                        offset >= 32 + size and offset + extent == len(data),
                        "Mach signature requires a unique nonexecutable tail LINKEDIT.")
                linkedit = (cursor, address, memory, offset, extent)
            for index in range(sections):
                section = cursor + 72 + 80 * index
                section_size = r.unpack("<Q", section + 40)[0]
                raw = r.unpack("<I", section + 48)[0]
                flags = r.unpack("<I", section + 64)[0]
                if flags & 0xff not in (1, 12, 18):
                    payload(raw, section_size)
                relocation, relocations = r.unpack("<II", section + 56)
                payload(relocation, relocations * 8)
        elif tag == 2:
            symbol, symbols, strings, string_size = r.unpack("<IIII", cursor + 8)
            payload(symbol, symbols * 16)
            payload(strings, string_size)
        elif tag == 0xb:
            require(length == 80, "Invalid Mach dynamic symbol command.")
            for field, width in ((32, 8), (40, 56), (48, 4), (56, 4), (64, 8), (72, 8)):
                offset, elements = r.unpack("<II", cursor + field)
                payload(offset, elements * width)
        elif tag in (0x22, 0x80000022):
            for field in range(8, 48, 8):
                payload(*r.unpack("<II", cursor + field))
        elif tag in (0x1e, 0x26, 0x29, 0x2b, 0x2e, 0x80000033, 0x80000034):
            require(length == 16, "Invalid Mach linkedit payload command.")
            payload(*r.unpack("<II", cursor + 8))
        elif tag not in (0xc, 0x80000018, 0x8000001f, 0x80000023, 0x8000001c,
                         0x32, 0x24, 0x80000028, 4, 5, 0x1b, 0x2a, 0x1d):
            raise ValueError("Mach signing transformation has an unexamined load command.")
        cursor += length
    require(linkedit is not None, "Mach signing transformation lacks LINKEDIT.")
    tail = signature[1] if signature is not None else len(data)
    require(linkedit[3] <= tail and all(end <= tail for _, end in occupied),
            "Mach signature overlaps nonsignature payload.")
    require(all(start >= 32 + size for start, end in occupied if end > start),
            "Mach payload overlaps load command bytes.")
    if signature is not None:
        require(signature[2] > 0 and tail + signature[2] == len(data),
                "Mach signature allocation is not the unique file tail.")
    return info, commands, signature, linkedit, occupied, 32 + size


def _validate_macho_superblob(data, offset, allocation, original=False):
    """Validate bounded embedded signature structure, without authenticating any publisher."""
    require(12 <= allocation <= 16 * 1024 * 1024, "Unbounded Mach signature allocation.")
    r = Reader(data)
    r.span(offset, allocation)
    magic, length, count = r.unpack(">III", offset)
    require(magic == 0xfade0cc0 and 0 < count <= 64 and
            12 + 8 * count <= length <= allocation,
            "Invalid Mach signature SuperBlob.")
    require(not any(r.span(offset + length, allocation - length)),
            "Mach signature has nonzero allocation padding.")
    ranges, slots, directories = [], set(), []
    for index in range(count):
        slot, begin = r.unpack(">II", offset + 12 + index * 8)
        require(slot not in slots and (slot in (0, 2, 5, 7, 0x10000) or 0x1000 <= slot < 0x1005),
                "Duplicate or unexamined Mach signature slot.")
        slots.add(slot)
        require(12 + count * 8 <= begin <= length - 8, "Mach signature blob overlaps its index.")
        blob_magic, extent = r.unpack(">II", offset + begin)
        require(8 <= extent <= length - begin, "Mach signature subblob escapes allocation.")
        ranges.append((begin, begin + extent))
        if slot == 0 or 0x1000 <= slot < 0x1005:
            require(blob_magic == 0xfade0c02 and extent >= 44, "Invalid Mach CodeDirectory.")
            base = offset + begin
            version, flags, hashes, identifier, special, codes, limit = r.unpack(">IIIIIII", base + 8)
            require(0x20001 <= version <= 0x20500, "Unexamined Mach CodeDirectory version.")
            header = (96 if version >= 0x20500 else 88 if version >= 0x20400 else
                      64 if version >= 0x20300 else 52 if version >= 0x20200 else
                      48 if version >= 0x20100 else 44)
            require(extent >= header, "Truncated Mach CodeDirectory header.")
            width, algorithm, _, page = r.unpack("BBBB", base + 36)
            require(algorithm in (1, 2, 3, 4) and width == {1: 20, 2: 32, 3: 20, 4: 48}[algorithm] and
                    page <= 16 and special <= 11 and codes <= MAX_TABLE and
                    r.unpack(">I", base + 40)[0] == 0, "Invalid Mach CodeDirectory hash layout.")
            if version >= 0x20100:
                require(r.unpack(">I", base + 44)[0] == 0, "Mach scatter signing is outside the closed recipe.")
            if version >= 0x20300:
                require(r.unpack(">I", base + 52)[0] == 0, "Invalid Mach CodeDirectory reserved field.")
                wide_limit = r.unpack(">Q", base + 56)[0]
                limit = wide_limit or limit
            require(limit == offset and codes == (1 if page == 0 else (limit + (1 << page) - 1) >> page),
                    "Mach CodeDirectory does not cover the exact nonsignature prefix.")
            hash_begin = hashes - special * width
            require(header <= hash_begin <= hashes <= extent and codes * width <= extent - hashes,
                    "Mach CodeDirectory hash slots escape its blob.")
            require(hashes + codes * width == extent,
                    "Mach CodeDirectory has unexamined trailing bytes.")
            require(header <= identifier < hash_begin and
                    data.find(b"\0", base + identifier, base + hash_begin) > base + identifier,
                    "Mach CodeDirectory identifier is not bounded.")
            if version >= 0x20200:
                team = r.unpack(">I", base + 48)[0]
                require(team == 0 or header <= team < hash_begin and
                        data.find(b"\0", base + team, base + hash_begin) >= base + team,
                        "Mach CodeDirectory team string is not bounded.")
            if version >= 0x20500:
                require(r.unpack(">I", base + 92)[0] == 0,
                        "Mach pre-encrypt signing is outside the closed recipe.")
            directories.append(flags)
        else:
            require(blob_magic == {2: 0xfade0c01, 5: 0xfade7171, 7: 0xfade7172,
                                   0x10000: 0xfade0b01}[slot], "Mach signature slot/blob kind differs.")
    require(0 in slots and directories, "Mach signature lacks its primary CodeDirectory.")
    if original:
        require(all(flags & 2 for flags in directories) and 0x10000 not in slots,
                "Original Mach signature is not linker/ad-hoc.")
    previous = 12 + 8 * count
    for begin, end in sorted(ranges):
        require(begin >= previous and not any(r.span(offset + previous, begin - previous)),
                "Overlapping Mach signature blobs or hidden gap.")
        previous = end
    require(not any(r.span(offset + previous, length - previous)), "Hidden Mach signature tail.")


def verify_macho_signature_transform(original: bytes, signed: bytes, rid: str) -> BinaryInfo:
    """Prove the closed signing byte transformation, never OS trust or signing authorization."""
    require(rid in ("osx-x64", "osx-arm64"), "Mach signing RID is not admitted.")
    old = _macho_signature_layout(original, rid)
    new = _macho_signature_layout(signed, rid)
    old_info, old_commands, old_signature, old_link, occupied, old_end = old
    new_info, new_commands, new_signature, new_link, _, new_end = new
    require(new_signature is not None, "Signed Mach executable lacks a signature.")
    if old_signature is not None:
        _validate_macho_superblob(original, old_signature[1], old_signature[2], original=True)
    _validate_macho_superblob(signed, new_signature[1], new_signature[2])
    require(old_info == new_info and len(old_commands) == len(new_commands),
            "Mach signing changed executable identity or command inventory.")
    insertion = old_signature is None
    if insertion:
        require(new_end == old_end + 16 and new_signature[0] == old_end and
                not any(original[old_end:old_end + 16]) and len(original[old_end:old_end + 16]) == 16 and
                all(end <= old_end or start >= old_end + 16 for start, end in occupied),
                "Mach signature insertion lacks original zero header padding.")
    else:
        require(new_end == old_end and new_signature[0] == old_signature[0],
                "Mach signature command moved.")
    old_tail = old_signature[1] if old_signature is not None else len(original)
    new_tail = new_signature[1]
    require(new_tail == (old_tail + 15) & ~15 and not any(signed[old_tail:new_tail]),
            "Mach signing relocated the body or added hidden alignment bytes.")
    require(old_link[:2] == new_link[:2] and old_link[3] == new_link[3] and
            new_link[4] == len(signed) - new_link[3], "Mach LINKEDIT mapping changed.")
    alignment = 4096 if rid == "osx-x64" else 16384
    require(old_link[2] == (old_link[4] + alignment - 1) & -alignment and
            new_link[2] == (new_link[4] + alignment - 1) & -alignment,
            "Mach LINKEDIT memory extent differs from architecture alignment.")
    masks = [(16, 24), (old_link[0] + 32, old_link[0] + 40),
             (old_link[0] + 48, old_link[0] + 56),
             (new_signature[0], new_signature[0] + 16)]
    previous = 0
    for begin, end in sorted(masks):
        require(begin >= previous and end <= old_tail and original[previous:begin] == signed[previous:begin],
                "Mach signing changed nonsignature bytes.")
        previous = end
    require(original[previous:old_tail] == signed[previous:old_tail],
            "Mach signing changed nonsignature body bytes.")
    require(struct.unpack_from("<II", signed, 16) ==
            tuple(value + (1 if index == 0 else 16) * insertion for index, value in
                  enumerate(struct.unpack_from("<II", original, 16))),
            "Mach signature insertion changed header counters unexpectedly.")
    for (old_offset, old_tag, old_command), (new_offset, new_tag, new_command) in zip(old_commands, new_commands):
        require(old_offset == new_offset and old_tag == new_tag,
                "Mach signing reordered existing load commands.")
        if old_offset == old_link[0]:
            require(old_command[:32] == new_command[:32] and old_command[40:48] == new_command[40:48] and
                    old_command[56:] == new_command[56:], "Mach signing changed LINKEDIT protections/layout.")
        else:
            require(old_command == new_command, "Mach signing changed a load command.")
    return new_info


def _inspect_bytes(data, rid, executable):
    require(rid in RIDS, "Native RID is not admitted.")
    reader = Reader(data)
    if data[:2] == b"MZ":
        result = _pe(reader, executable)
    elif data[:4] == b"\x7fELF":
        result = _elf(reader, executable)
    elif data[:4] == b"\xcf\xfa\xed\xfe":
        result = _mach(reader, executable)
    else:
        raise ValueError("Native file is not admitted PE32+, ELF64 or thin little-endian Mach-O64.")
    require((result.format, result.machine) == RIDS[rid], "Native format/architecture differs from RID.")
    return result


def _pe(r, executable=False):
    header = r.unpack("<I", 0x3c)[0]
    require(header >= 0x40 and r.span(header, 4) == b"PE\0\0", "Invalid PE signature.")
    machine, count, _, _, _, optional_size, characteristics = r.unpack("<HHIIIHH", header + 4)
    require(machine in (0x8664, 0xaa64) and 0 < count <= 96 and
            (bool(characteristics & 2) and not characteristics & 0x2000 if executable else characteristics & 0x2000),
            "PE input must be an admitted native executable." if executable else
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

    entrypoint = None
    if executable:
        require(directory(14) == (0, 0), "Managed CLR executable is not an admitted native helper.")
        entrypoint = r.unpack("<I", optional + 16)[0]
        require(entrypoint > 0 and mapped(entrypoint)[2] & 0x20000000,
                "PE executable entrypoint lacks file-backed executable code.")

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
                      data_exports=_sorted(data), unnamed_exports=unnamed,
                      kind="executable" if executable else "shared-library", entrypoint=entrypoint)


def _elf(r, executable=False):
    require(r.span(0, 7) == b"\x7fELF\x02\x01\x01", "Native ELF must be 64-bit little-endian version1.")
    kind, machine, version = r.unpack("<HHI", 16)
    require((kind in (2, 3) if executable else kind == 3) and machine in (62, 183) and version == 1,
            "ELF input is not an admitted native executable." if executable else
            "ELF input is not an admitted shared library.")
    program, sections = r.unpack("<QQ", 32)
    header_size, program_size, program_count, section_size, section_count, _ = r.unpack("<HHHHHH", 52)
    require(header_size == 64 and program_size == 56 and 0 < program_count <= 8192 and
            section_size == 64 and 0 < section_count <= 8192, "Invalid or unbounded ELF tables.")
    r.span(program, program_count * program_size)
    r.span(sections, section_count * section_size)
    loads, dynamic, interpreters, memory_loads = [], [], [], []
    for index in range(program_count):
        tag, flags, offset, address, _, file_size, memory_size, _ = r.unpack("<IIQQQQQQ", program + index * 56)
        require(file_size <= memory_size, "Invalid ELF segment size.")
        r.span(offset, file_size)
        if tag == 1:
            if executable and memory_size:
                memory_loads.append((address, memory_size))
            if file_size:
                loads.append((address, file_size, offset, flags))
        elif tag == 2:
            dynamic.append((offset, address, file_size))
        elif tag == 3 and executable:
            require(0 < file_size <= MAX_NAME, "Unbounded ELF interpreter.")
            interpreters.append((offset, address, file_size))
    require(loads and len(dynamic) == 1, "ELF shared library has no unique dynamic table.")
    load_index = AddressIndex(loads)
    if executable:
        AddressIndex(memory_loads)  # A zero-fill remapping cannot shadow the declared file-backed code.

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

    entrypoint = None
    if executable:
        require(len(interpreters) == 1, "ELF executable needs one closed dynamic interpreter.")
        offset, address, size = interpreters[0]
        interpreter = r.string(offset, offset + size)
        require(len(interpreter) + 1 == size and mapped(address, size)[0] == offset,
                "ELF interpreter virtual/file mapping differs.")
        require(interpreter == ({62: "/lib64/ld-linux-x86-64.so.2", 183: "/lib/ld-linux-aarch64.so.1"}[machine]),
                "ELF executable interpreter is not admitted.")
        flags1 = single(0x6ffffffb, 0)
        require(bool(flags1 & 0x08000000) == (kind == 3), "ELF ET_DYN executable lacks genuine PIE identity.")
        entrypoint = r.unpack("<Q", 24)[0]
        require(entrypoint > 0 and mapped(entrypoint)[1] & 1,
                "ELF executable entrypoint lacks file-backed executable code.")

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
                      absolute_exports=_sorted(absolute), version_requirements=_sorted(requirements),
                      kind="executable" if executable else "shared-library", entrypoint=entrypoint)


def _mach(r, executable=False):
    _, cpu, _, kind, count, command_size, _, _ = r.unpack("<IIIIIIII", 0)
    require(cpu in (0x01000007, 0x0100000c) and kind == (2 if executable else 6) and 0 < count <= 8192,
            "Mach-O input is not an admitted native executable." if executable else
            "Mach-O input is not an admitted thin shared library.")
    r.span(32, command_size)
    cursor, imports, paths, executable_ranges = 32, [], [], []
    identity = minimum_os = None
    symbol_table = trie = None
    bases, file_loads, memory_loads, entries = [], [], [], []
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
            if executable:
                if file_size:
                    file_loads.append((offset, file_size, address, protections))
                if memory_size:
                    memory_loads.append((address, memory_size))
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
                        executable_ranges.append((section_address, section_size))
        elif command == 0x80000028 and executable:
            require(length == 24 and not entries, "Invalid or duplicate Mach-O entrypoint.")
            entries.append(("file", r.unpack("<Q", cursor + 8)[0]))
        elif command in (4, 5) and executable:
            require(length >= 16 and not entries, "Invalid or duplicate Mach-O thread entrypoint.")
            flavor, words = r.unpack("<II", cursor + 8)
            expected_flavor, expected_words, pc_offset = ((4, 42, 128) if cpu == 0x01000007 else (6, 68, 256))
            require(flavor == expected_flavor and words == expected_words and length == 16 + words * 4,
                    "Mach-O thread state is not admitted for this architecture.")
            entries.append(("virtual", r.unpack("<Q", cursor + 16 + pc_offset)[0]))
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
    require(cursor == 32 + command_size and len(bases) == 1 and
            (identity is None if executable else bool(identity)),
            "Incomplete Mach-O executable." if executable else "Incomplete Mach-O shared library.")
    executable_index = AddressIndex(executable_ranges)
    entrypoint = None
    if executable:
        AddressIndex(memory_loads)
        file_index = AddressIndex(file_loads)
        require(len(entries) == 1, "Mach-O executable has no unique entrypoint.")
        entry_kind, entrypoint = entries[0]
        if entry_kind == "file":
            row = file_index.find(entrypoint)
            require(row is not None and row[3] & 4, "Mach-O entrypoint lacks executable file mapping.")
            entrypoint = row[2] + entrypoint - row[0]
        require(entrypoint > 0 and executable_index.find(entrypoint) is not None,
                "Mach-O executable entrypoint lacks file-backed executable code.")
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
                      absolute_exports=_sorted(absolute), minimum_os=minimum_os,
                      kind="executable" if executable else "shared-library", entrypoint=entrypoint)
