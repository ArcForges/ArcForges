# SPDX-License-Identifier: AGPL-3.0-only
"""Offline structural negatives plus explicitly supplied real upstream bytes.

Generated fixtures exercise format parsing only. They never certify a native
implementation, trusted producer, package, deployment or operating-system test.
"""
import hashlib
import os
from pathlib import Path
import struct
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "eng/packaging"))
import native_binary as binary


def put(data, offset, fmt, *values):
    struct.pack_into(fmt, data, offset, *values)


def pe(machine=0x8664, target=0x1400):
    data = bytearray(0x1000)
    data[:2] = b"MZ"
    put(data, 0x3c, "<I", 0x80)
    data[0x80:0x84] = b"PE\0\0"
    put(data, 0x84, "<HHIIIHH", machine, 1, 0, 0, 0, 240, 0x2000)
    put(data, 0x98, "<H", 0x20b)
    put(data, 0x98 + 24, "<Q", 0x180000000)
    put(data, 0x98 + 60, "<I", 0x200)
    put(data, 0x98 + 108, "<I", 16)
    put(data, 0x98 + 112, "<II", 0x1100, 0x100)
    put(data, 0x98 + 120, "<II", 0x1300, 40)
    put(data, 0x188 + 8, "<IIII", 0xe00, 0x1000, 0xe00, 0x200)
    put(data, 0x188 + 36, "<I", 0x60000020)
    put(data, 0x300 + 12, "<I", 0x1180)
    put(data, 0x300 + 20, "<IIIII", 1, 1, 0x1140, 0x1148, 0x1150)
    put(data, 0x340, "<I", target)
    put(data, 0x348, "<I", 0x1190)
    put(data, 0x350, "<H", 0)
    data[0x380:0x388] = b"Own.dll\0"
    data[0x390:0x394] = b"fn\0\0"
    data[0x360:0x36d] = b"engine.other\0"
    put(data, 0x500 + 12, "<I", 0x1350)
    data[0x550:0x55d] = b"KERNEL32.dll\0"
    return data


def elf(machine=62):
    data = bytearray(0x1000)
    data[:7] = b"\x7fELF\x02\x01\x01"
    put(data, 16, "<HHI", 3, machine, 1)
    put(data, 32, "<QQ", 64, 0x800)
    put(data, 52, "<HHHHHH", 64, 56, 2, 64, 3, 0)
    put(data, 64, "<IIQQQQQQ", 1, 5, 0, 0, 0, len(data), len(data), 4096)
    put(data, 120, "<IIQQQQQQ", 2, 4, 0x200, 0x200, 0, 128, 128, 8)
    strings = b"\0libOwn.so\0libc.so.6\0fn\0ARCFORGES_1.0\0$ORIGIN\0"
    data[0x400:0x400 + len(strings)] = strings
    tags = [(5, 0x400), (10, len(strings)), (6, 0x500), (11, 24),
            (14, 1), (1, strings.index(b"libc")), (29, strings.index(b"$ORIGIN")), (0, 0)]
    for index, tag in enumerate(tags):
        put(data, 0x200 + index * 16, "<qQ", *tag)
    put(data, 0x500 + 24, "<IBBHQQ", strings.index(b"fn"), 0x12, 0, 1, 0x600, 16)
    put(data, 0x500 + 48, "<IBBHQQ", strings.index(b"ARCFORGES"), 0x11, 0, 0xfff1, 0, 0)
    put(data, 0x800 + 64, "<IIQQQQIIQQ", 0, 3, 0, 0x400, 0x400, len(strings), 0, 0, 1, 0)
    put(data, 0x800 + 128, "<IIQQQQIIQQ", 0, 11, 0, 0x500, 0x500, 72, 1, 0, 8, 24)
    return data


def mach(cpu=0x01000007, trie=True):
    data = bytearray(0x1000)
    commands = []
    segment = bytearray(152)
    put(segment, 0, "<II", 0x19, 152)
    segment[8:14] = b"__TEXT"
    put(segment, 24, "<QQQQIIII", 0, len(data), 0, len(data), 5, 5, 1, 0)
    segment[72:78] = b"__text"
    segment[88:94] = b"__TEXT"
    put(segment, 104, "<QQI", 0x800, 16, 0x800)
    put(segment, 136, "<I", 0x80000400)
    commands.append(segment)
    for tag, name in ((0xd, b"@rpath/libOwn.dylib"), (0xc, b"@loader_path/libengine.dylib")):
        length = (24 + len(name) + 1 + 7) & ~7
        command = bytearray(length)
        put(command, 0, "<IIIIII", tag, length, 24, 0, 0, 0)
        command[24:24 + len(name)] = name
        commands.append(command)
    command = bytearray(24)
    put(command, 0, "<IIIIII", 0x32, 24, 1, 0x000d0000, 0x001a0000, 0)
    commands.append(command)
    if trie:
        blob = b"\0\x01_fn\0\x07\x03\0\x80\x10\0"
        data[0x600:0x600 + len(blob)] = blob
        commands.append(struct.pack("<IIII", 0x80000033, 16, 0x600, len(blob)))
    else:
        commands.append(struct.pack("<IIIIII", 2, 24, 0x700, 1, 0x720, 5))
        put(data, 0x700, "<IBBHQ", 1, 0xf, 1, 0, 0x800)
        data[0x720:0x725] = b"\0_fn\0"
    put(data, 0, "<IIIIIIII", 0xfeedfacf, cpu, 0, 6, len(commands), sum(map(len, commands)), 0, 0)
    cursor = 32
    for command in commands:
        data[cursor:cursor + len(command)] = command
        cursor += len(command)
    return data


class NativeBinaryTests(unittest.TestCase):
    def test_six_closed_architectures(self):
        for rid, data in (("win-x64", pe()), ("win-arm64", pe(0xaa64)),
                          ("linux-x64", elf()), ("linux-arm64", elf(183)),
                          ("osx-x64", mach()), ("osx-arm64", mach(0x0100000c))):
            with self.subTest(rid=rid):
                info = binary.inspect_bytes(bytes(data), rid)
                self.assertEqual(("fn",), info.exports)
                self.assertEqual([], info.as_manifest()["forwardedExports"])
                with self.assertRaises(ValueError):
                    binary.inspect_bytes(bytes(data), "unreviewed-rid")
                wrong = rid.replace("arm64", "x64") if "arm64" in rid else rid.replace("x64", "arm64")
                with self.assertRaisesRegex(ValueError, "architecture"):
                    binary.inspect_bytes(bytes(data), wrong)

    def test_truncated_headers_fail_as_contract_errors(self):
        for rid, data in (("win-x64", pe()), ("linux-x64", elf()), ("osx-x64", mach())):
            for length in (0, 1, 4, 31, 63, 127):
                with self.subTest(rid=rid, length=length), self.assertRaises(ValueError):
                    binary.inspect_bytes(bytes(data[:length]), rid)

    def test_pe_forwarded_data_and_ordinal_exports_are_described(self):
        self.assertEqual(("fn",), binary.inspect_bytes(bytes(pe(target=0x1160)), "win-x64").forwarded_exports)
        data = pe()
        put(data, 0x188 + 36, "<I", 0x40000040)
        self.assertEqual(("fn",), binary.inspect_bytes(bytes(data), "win-x64").data_exports)
        data = pe()
        put(data, 0x300 + 24, "<I", 0)
        info = binary.inspect_bytes(bytes(data), "win-x64")
        self.assertEqual(1, info.unnamed_exports)
        self.assertEqual((), info.exports)

    def test_pe_delay_imports_are_included(self):
        data = pe()
        put(data, 0x98 + 112 + 13 * 8, "<II", 0x1600, 64)
        put(data, 0x800, "<II", 1, 0x1650)
        data[0x850:0x85b] = b"engine.dll\0"
        self.assertEqual(("KERNEL32.dll", "engine.dll"), binary.inspect_bytes(bytes(data), "win-x64").imports)

    def test_pe_zero_fill_data_exports_are_metadata_and_callable_code_requires_bytes(self):
        data = pe(target=0x1f00)
        put(data, 0x188 + 8, "<I", 0x1000)
        put(data, 0x188 + 36, "<I", 0x40000040)
        self.assertEqual(("fn",), binary.inspect_bytes(bytes(data), "win-x64").data_exports)
        put(data, 0x188 + 36, "<I", 0x60000020)
        with self.assertRaisesRegex(ValueError, "Unmapped"):
            binary.inspect_bytes(bytes(data), "win-x64")

    def test_pe_unterminated_import_invalid_ordinal_and_unmapped_exports_fail(self):
        for offset, fmt, value in ((0x98 + 120 + 4, "<I", 20), (0x350, "<H", 2), (0x340, "<I", 0xf000)):
            data = pe()
            put(data, offset, fmt, value)
            with self.subTest(offset=offset), self.assertRaises(ValueError):
                binary.inspect_bytes(bytes(data), "win-x64")

    def test_pe_unbounded_and_overlapping_sections_fail(self):
        data = pe()
        put(data, 0x84 + 2, "<H", 97)
        with self.assertRaises(ValueError):
            binary.inspect_bytes(bytes(data), "win-x64")
        data = pe()
        put(data, 0x84 + 2, "<H", 2)
        data[0x1b0:0x1d8] = data[0x188:0x1b0]
        with self.assertRaisesRegex(ValueError, "Overlapping"):
            binary.inspect_bytes(bytes(data), "win-x64")

    def test_elf_identity_searchpath_and_absolute_version_metadata(self):
        info = binary.inspect_bytes(bytes(elf()), "linux-x64")
        self.assertEqual("libOwn.so", info.identity)
        self.assertEqual(("libc.so.6",), info.imports)
        self.assertEqual(("$ORIGIN",), info.runpaths)
        self.assertEqual(("ARCFORGES_1.0",), info.absolute_exports)
        self.assertEqual((), info.data_exports)

    def test_elf_data_export_and_nonexecutable_callable(self):
        data = elf()
        data[0x500 + 24 + 4] = 0x11
        self.assertEqual(("fn",), binary.inspect_bytes(bytes(data), "linux-x64").data_exports)
        data = elf()
        data[0x500 + 24 + 4] = 0x1a
        self.assertEqual(("fn",), binary.inspect_bytes(bytes(data), "linux-x64").forwarded_exports)
        data = elf()
        put(data, 64 + 4, "<I", 4)
        with self.assertRaisesRegex(ValueError, "executable"):
            binary.inspect_bytes(bytes(data), "linux-x64")

    def test_elf_dynamic_and_linked_strings_must_match(self):
        data = elf()
        put(data, 0x800 + 64 + 32, "<Q", 0x410)
        with self.assertRaisesRegex(ValueError, "linked"):
            binary.inspect_bytes(bytes(data), "linux-x64")

    def test_elf_dynamic_virtual_file_mapping_and_complete_symbol_mapping_are_bound(self):
        data = elf()
        put(data, 120 + 16, "<Q", 0x700)
        with self.assertRaisesRegex(ValueError, "dynamic virtual/file"):
            binary.inspect_bytes(bytes(data), "linux-x64")
        data = elf()
        put(data, 64 + 32, "<Q", 0x520)
        with self.assertRaisesRegex(ValueError, "Unmapped"):
            binary.inspect_bytes(bytes(data), "linux-x64")

    def test_elf_overlapping_load_ranges_are_refused_before_mapping_queries(self):
        data = elf()
        put(data, 56, "<H", 3)
        put(data, 176, "<IIQQQQQQ", 1, 5, 0x600, 0x600, 0, 16, 16, 1)
        with self.assertRaisesRegex(ValueError, "Overlapping"):
            binary.inspect_bytes(bytes(data), "linux-x64")

    def test_elf_endianness_unbounded_sections_and_bad_dynamic_strings_fail(self):
        for offset, fmt, value in ((5, "<B", 2), (60, "<H", 9000), (0x200 + 16 + 8, "<Q", 0x1001),
                                   (0x800 + 128 + 56, "<Q", 23)):
            data = elf()
            put(data, offset, fmt, value)
            with self.subTest(offset=offset), self.assertRaises(ValueError):
                binary.inspect_bytes(bytes(data), "linux-x64")

    def test_elf_unterminated_and_duplicate_dynamic_table_fail(self):
        data = elf()
        put(data, 0x200 + 7 * 16, "<qQ", 1, 1)
        with self.assertRaisesRegex(ValueError, "Unterminated"):
            binary.inspect_bytes(bytes(data), "linux-x64")
        data = elf()
        put(data, 0x200 + 5 * 16, "<qQ", 14, 1)
        with self.assertRaisesRegex(ValueError, "Duplicate"):
            binary.inspect_bytes(bytes(data), "linux-x64")

    def test_mach_trie_and_symbol_fallback_report_actual_install_names(self):
        for trie in (True, False):
            info = binary.inspect_bytes(bytes(mach(trie=trie)), "osx-x64")
            self.assertEqual(("fn",), info.exports)
            self.assertEqual("@rpath/libOwn.dylib", info.identity)
            self.assertEqual(("@loader_path/libengine.dylib",), info.imports)
            self.assertEqual("13.0.0", info.minimum_os)

    def test_mach_data_absolute_and_forwarded_trie_exports_are_distinct(self):
        data = mach()
        put(data, 32 + 136, "<I", 0)
        self.assertEqual(("fn",), binary.inspect_bytes(bytes(data), "osx-x64").data_exports)
        data = mach()
        data[0x608] = 2
        self.assertEqual(("fn",), binary.inspect_bytes(bytes(data), "osx-x64").absolute_exports)
        data = mach()
        data[0x608:0x60b] = b"\x08\x01\0"
        self.assertEqual(("fn",), binary.inspect_bytes(bytes(data), "osx-x64").forwarded_exports)

    def test_mach_sections_bind_virtual_and_file_offsets_and_refuse_executable_zero_fill(self):
        for offset, fmt, value, message in (
                (32 + 72 + 48, "<I", 0x900, "virtual/file"),
                (32 + 72 + 64, "<I", 0x80000401, "executable"),
                (32 + 32, "<Q", 0x800, "segment size"),
                (32 + 72 + 40, "<Q", 0x900, "segment memory")):
            data = mach()
            put(data, offset, fmt, value)
            with self.subTest(offset=offset), self.assertRaisesRegex(ValueError, message):
                binary.inspect_bytes(bytes(data), "osx-x64")

    def test_mach_aggregate_section_work_is_capped_across_commands(self):
        commands = []
        for count in (4096, 4097):
            command = bytearray(72 + count * 80)
            put(command, 0, "<II", 0x19, len(command))
            put(command, 24, "<QQQQIIII", 0, 0, 0, 0, 0, 0, count, 0)
            for index in range(count):
                put(command, 72 + index * 80 + 64, "<I", 1)
            commands.append(command)
        data = bytearray(32) + b"".join(commands)
        put(data, 0, "<IIIIIIII", 0xfeedfacf, 0x01000007, 0, 6, 2, len(data) - 32, 0, 0)
        with self.assertRaisesRegex(ValueError, "aggregate"):
            binary.inspect_bytes(bytes(data), "osx-x64")

    def test_mach_overlapping_executable_sections_are_refused(self):
        data = mach()
        commands_size = struct.unpack_from("<I", data, 20)[0]
        data[32 + 152 + 80:32 + commands_size + 80] = data[32 + 152:32 + commands_size]
        data[32 + 152:32 + 232] = data[32 + 72:32 + 152]
        put(data, 32 + 4, "<I", 232)
        put(data, 32 + 64, "<I", 2)
        put(data, 20, "<I", commands_size + 80)
        with self.assertRaisesRegex(ValueError, "Overlapping"):
            binary.inspect_bytes(bytes(data), "osx-x64")

    def test_mach_cycle_overflow_unknown_flags_and_out_of_range_terminal_fail(self):
        for offset, value in ((0x606, 0), (0x607, 127), (0x608, 64), (0x60a, 255)):
            data = mach()
            data[offset] = value
            with self.subTest(offset=offset), self.assertRaises(ValueError):
                binary.inspect_bytes(bytes(data), "osx-x64")

    def test_mach_unbounded_invalid_command_and_fat_formats_fail(self):
        for offset, fmt, value in ((16, "<I", 9000), (36, "<I", 7), (12, "<I", 2), (0, "<I", 0xcafebabe)):
            data = mach()
            put(data, offset, fmt, value)
            with self.subTest(offset=offset), self.assertRaises(ValueError):
                binary.inspect_bytes(bytes(data), "osx-x64")

    def test_file_contract_and_immutable_inventory(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "test.dll"
            path.write_bytes(pe())
            info = binary.inspect(path, "win-x64")
            self.assertEqual("PE32+", info.format)
            with self.assertRaises(AttributeError):
                info.exports = ("other",)
            with self.assertRaises(ValueError):
                binary.inspect(Path(temporary), "win-x64")


class NativeExecutableTests(unittest.TestCase):
    """Structural executable fixtures are file-format checks, never runtime or AOT proof."""

    @staticmethod
    def inspect(data, rid):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "fixture"
            path.write_bytes(data)
            return binary.inspect_executable(path, rid)

    @staticmethod
    def pe_executable(machine=0x8664):
        data = pe(machine)
        put(data, 0x84 + 18, "<H", 2)
        put(data, 0x98 + 16, "<I", 0x1400)
        return data

    @staticmethod
    def elf_executable(machine=62, pie=True):
        data = elf(machine)
        put(data, 16, "<H", 3 if pie else 2)
        put(data, 24, "<Q", 0x600)
        put(data, 56, "<H", 3)
        interpreter = (b"/lib64/ld-linux-x86-64.so.2" if machine == 62 else b"/lib/ld-linux-aarch64.so.1") + b"\0"
        data[0x700:0x700 + len(interpreter)] = interpreter
        put(data, 176, "<IIQQQQQQ", 3, 4, 0x700, 0x700, 0, len(interpreter), len(interpreter), 1)
        if pie:
            put(data, 0x270, "<qQ", 0x6ffffffb, 0x08000000)
            put(data, 0x280, "<qQ", 0, 0)
            put(data, 120 + 32, "<QQ", 144, 144)
        return data

    @staticmethod
    def mach_executable(cpu=0x01000007, thread=False):
        data = mach(cpu)
        count = struct.unpack_from("<I", data, 16)[0]
        cursor, commands = 32, []
        for _ in range(count):
            tag, size = struct.unpack_from("<II", data, cursor)
            if tag != 0xd:
                commands.append(bytes(data[cursor:cursor + size]))
            cursor += size
        if thread:
            flavor, words, pc_offset = (4, 42, 128) if cpu == 0x01000007 else (6, 68, 256)
            entry = bytearray(16 + words * 4)
            put(entry, 0, "<IIII", 5, len(entry), flavor, words)
            put(entry, 16 + pc_offset, "<Q", 0x800)
        else:
            entry = struct.pack("<IIQQ", 0x80000028, 24, 0x800, 0)
        commands.append(entry)
        put(data, 12, "<III", 2, len(commands), sum(map(len, commands)))
        cursor = 32
        for command in commands:
            data[cursor:cursor + len(command)] = command
            cursor += len(command)
        return data

    def test_six_native_executable_architectures_and_legacy_shared_compatibility(self):
        cases = (("win-x64", self.pe_executable()), ("win-arm64", self.pe_executable(0xaa64)),
                 ("linux-x64", self.elf_executable()), ("linux-arm64", self.elf_executable(183)),
                 ("osx-x64", self.mach_executable()), ("osx-arm64", self.mach_executable(0x0100000c)))
        for rid, data in cases:
            with self.subTest(rid=rid):
                info = self.inspect(data, rid)
                self.assertEqual("executable", info.kind)
                self.assertGreater(info.entrypoint, 0)
                self.assertEqual(info.entrypoint, info.as_manifest()["entryPoint"])
                self.assertEqual(("fn",), info.exports)
                if rid.startswith("linux"):
                    # Historical shared inspection accepts ET_DYN; preserve its byte contract exactly.
                    # Only inspect_executable establishes the additional interpreter/PIE/entrypoint checks.
                    self.assertNotIn("entryPoint", binary.inspect_bytes(bytes(data), rid).as_manifest())
                    with self.assertRaises(ValueError):
                        binary.inspect_bytes(bytes(self.elf_executable(183 if rid.endswith("arm64") else 62, pie=False)), rid)
                else:
                    with self.assertRaises(ValueError):
                        binary.inspect_bytes(bytes(data), rid)
                wrong = rid.replace("arm64", "x64") if rid.endswith("arm64") else rid.replace("x64", "arm64")
                with self.assertRaisesRegex(ValueError, "architecture"):
                    self.inspect(data, wrong)
                with self.assertRaises(ValueError):
                    self.inspect(data, "unreviewed-rid")

    def test_shared_serialization_does_not_gain_executable_metadata(self):
        for rid, data in (("win-x64", pe()), ("linux-x64", elf()), ("osx-x64", mach())):
            info = binary.inspect_bytes(bytes(data), rid)
            self.assertEqual("shared-library", info.kind)
            self.assertIsNone(info.entrypoint)
            self.assertNotIn("kind", info.as_manifest())
            self.assertNotIn("entryPoint", info.as_manifest())
            with self.assertRaises(ValueError):
                self.inspect(data, rid)

    def test_pe_clr_entrypoint_kind_and_code_bounds_refuse(self):
        mutations = ((0x98 + 112 + 14 * 8, "<II", (0x1700, 72)),
                     (0x98 + 16, "<I", (0,)), (0x98 + 16, "<I", (0x1f00,)),
                     (0x98 + 16, "<I", (0x100,)), (0x188 + 36, "<I", (0x40000040,)),
                     (0x84 + 18, "<H", (0x2002,)), (0x84 + 18, "<H", (0,)))
        for offset, fmt, values in mutations:
            data = self.pe_executable()
            put(data, offset, fmt, *values)
            with self.subTest(offset=offset, values=values), self.assertRaises(ValueError):
                self.inspect(data, "win-x64")

    def test_elf_exec_and_pie_are_distinct_and_closed_interpreter_is_mapped(self):
        self.assertEqual(0x600, self.inspect(self.elf_executable(pie=False), "linux-x64").entrypoint)
        mutations = ((0x270 + 8, "<Q", 0), (56, "<H", 2), (24, "<Q", 0),
                     (24, "<Q", 0x1100), (64 + 4, "<I", 4), (176 + 16, "<Q", 0x710),
                     (176 + 32, "<Q", 4097))
        for offset, fmt, value in mutations:
            data = self.elf_executable()
            put(data, offset, fmt, value)
            with self.subTest(offset=offset), self.assertRaises(ValueError):
                self.inspect(data, "linux-x64")
        data = self.elf_executable()
        data[0x700:0x706] = b"/evil/"
        with self.assertRaisesRegex(ValueError, "interpreter"):
            self.inspect(data, "linux-x64")
        data = self.elf_executable()
        put(data, 56, "<H", 4)
        data[232:288] = data[176:232]
        with self.assertRaisesRegex(ValueError, "one closed"):
            self.inspect(data, "linux-x64")

    def test_mach_main_and_architecture_bound_thread_states_require_executable_bytes(self):
        for cpu, rid in ((0x01000007, "osx-x64"), (0x0100000c, "osx-arm64")):
            self.assertEqual(0x800, self.inspect(self.mach_executable(cpu, thread=True), rid).entrypoint)
        data = self.mach_executable(thread=True)
        end = 32 + struct.unpack_from("<I", data, 20)[0]
        put(data, end - 184 + 8, "<I", 6)
        with self.assertRaisesRegex(ValueError, "thread state"):
            self.inspect(data, "osx-x64")
        data = self.mach_executable()
        end = 32 + struct.unpack_from("<I", data, 20)[0]
        for entry in (0, 0x700, 0x810, 0x1100):
            mutated = bytearray(data)
            put(mutated, end - 24 + 8, "<Q", entry)
            with self.subTest(entry=entry), self.assertRaises(ValueError):
                self.inspect(mutated, "osx-x64")
        duplicated = bytearray(data)
        duplicated[end:end + 24] = data[end - 24:end]
        put(duplicated, 16, "<II", struct.unpack_from("<I", data, 16)[0] + 1, end - 32 + 24)
        with self.assertRaisesRegex(ValueError, "duplicate"):
            self.inspect(duplicated, "osx-x64")
        data = self.mach_executable()
        put(data, 32 + 104 + 16, "<I", 0x900)
        with self.assertRaisesRegex(ValueError, "mapping"):
            self.inspect(data, "osx-x64")

    def test_executable_zero_fill_and_raw_segment_overlays_refuse_ambiguous_loader_mapping(self):
        data = self.elf_executable()
        put(data, 56, "<H", 4)
        put(data, 232, "<IIQQQQQQ", 1, 4, 0, 0x600, 0, 0, 32, 1)
        with self.assertRaisesRegex(ValueError, "Overlapping"):
            self.inspect(data, "linux-x64")
        for thread in (False, True):
            data = self.mach_executable(thread=thread)
            end = 32 + struct.unpack_from("<I", data, 20)[0]
            command = bytearray(72)
            put(command, 0, "<II", 0x19, 72)
            put(command, 24, "<QQQQIIII", 0x800, 16, 0, 0, 1, 1, 0, 0)
            data[end:end + 72] = command
            put(data, 16, "<II", struct.unpack_from("<I", data, 16)[0] + 1, end - 32 + 72)
            with self.subTest(thread=thread), self.assertRaisesRegex(ValueError, "Overlapping"):
                self.inspect(data, "osx-x64")

    def test_native_executable_input_is_bounded_regular_and_immutable(self):
        for data in (b"", b"MZ", bytes(self.pe_executable()[:127])):
            with self.assertRaises(ValueError):
                self.inspect(data, "win-x64")
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaises(ValueError):
                binary.inspect_executable(Path(temporary), "win-x64")
        info = self.inspect(self.pe_executable(), "win-x64")
        with self.assertRaises(AttributeError):
            info.entrypoint = 0


@unittest.skipUnless(os.environ.get("ARCFORGES_NATIVE_EXECUTABLE_ROOT"), "Actual AOT executable bytes require explicit local input.")
class ActualNativeExecutableTests(unittest.TestCase):
    def test_owned_actual_win_x64_aot_helper_is_native_code_metadata_only(self):
        path = Path(os.environ["ARCFORGES_NATIVE_EXECUTABLE_ROOT"]) / "ArcForges.ContentSandbox.exe"
        self.assertEqual("827489c6cf37c6ccfba863965f0069ddc50cb315929baf4fda31b419e783bd89", hashlib.sha256(path.read_bytes()).hexdigest())
        info = binary.inspect_executable(path, "win-x64")
        self.assertEqual(("PE32+", "x86_64", "executable", 0x654280), (info.format, info.machine, info.kind, info.entrypoint))
        self.assertIn("KERNEL32.dll", info.imports)
        self.assertIn("CRYPT32.dll", info.imports)
        self.assertNotIn("mscoree.dll", tuple(name.lower() for name in info.imports))
        with self.assertRaises(ValueError):
            binary.inspect(path, "win-x64")


@unittest.skipUnless(os.environ.get("ARCFORGES_NATIVE_INSPECTION_ROOT"), "Actual upstream bytes require explicit local input.")
class ActualUpstreamBinaryTests(unittest.TestCase):
    def test_five_real_signed_archive_members_match_format_linkage_and_callable_exports(self):
        directory = Path(os.environ["ARCFORGES_NATIVE_INSPECTION_ROOT"])
        rows = {
            "linux-x64": ("libpdfium.so", "b0361f8ba0bc6ffeb2325949a88f08b09356f46abe257ffdf846202999daa27b"),
            "linux-arm64": ("libpdfium.so", "794a43ec86642d48ed69becb6923022cd0b34d23c81c524452d6f0549398d710"),
            "osx-x64": ("libpdfium.dylib", "34df27218f55104e1465ec48f69b98c233f0cf41700378849f4e337f695bb342"),
            "osx-arm64": ("libpdfium.dylib", "f151baf68cf7c4ebee7e7b9263bdce065436b8df7008fb174d89dd2a97fac124"),
            "win-arm64": ("pdfium.dll", "963307405023898d887f76a54ed59eae0462e25cd6b50716cbc2be10a8a6f6ed"),
        }
        for rid, (name, expected) in rows.items():
            with self.subTest(rid=rid):
                content = (directory / (rid + "-" + name)).read_bytes()
                self.assertEqual(expected, hashlib.sha256(content).hexdigest())
                info = binary.inspect_bytes(content, rid)
                self.assertIn("FPDF_LoadCustomDocument", info.exports)
                self.assertIn("FPDF_RenderPageBitmap", info.exports)
                self.assertGreater(len(info.exports), 300)
                self.assertEqual((), info.forwarded_exports)
                self.assertEqual(0, info.unnamed_exports)
                if rid.startswith("linux"):
                    self.assertEqual("libpdfium.so", info.identity)
                    loader = "ld-linux-x86-64.so.2" if rid.endswith("x64") else "ld-linux-aarch64.so.1"
                    self.assertEqual(tuple(sorted(("libpthread.so.0", "libm.so.6", "libgcc_s.so.1", "libc.so.6", loader))), info.imports)
                    self.assertEqual((), info.runpaths)
                    self.assertIn("GCC_3.0", info.version_requirements)
                    self.assertIn("GLIBC_2.16" if rid.endswith("x64") else "GLIBC_2.17", info.version_requirements)
                elif rid.startswith("osx"):
                    self.assertEqual("./libpdfium.dylib", info.identity)
                    self.assertEqual("13.0.0", info.minimum_os)
                    self.assertIn("/usr/lib/libSystem.B.dylib", info.imports)
                    self.assertEqual(5, len(info.imports))
                else:
                    self.assertEqual("pdfium.dll", info.identity)
                    self.assertEqual(("ADVAPI32.dll", "GDI32.dll", "KERNEL32.dll", "USER32.dll"), info.imports)


if __name__ == "__main__":
    unittest.main()
