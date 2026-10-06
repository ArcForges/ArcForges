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
