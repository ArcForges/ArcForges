// SPDX-License-Identifier: AGPL-3.0-only
using System.IO.MemoryMappedFiles;
using System.Security.Cryptography;
using ArcForges.Node.Core.Platform;

namespace ArcForges.Node.Core.Tests;

public sealed partial class WorkspaceWriteGuardTests
{
    [Theory(Timeout = 30_000)]
    [Trait("env", "windows-real")]
    [InlineData("section")]
    [InlineData("copy_mapping")]
    [InlineData("write_mapping")]
    public async Task WindowsPriorSectionOrCopyMappingRefusesBeforeEffect(string kind)
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        cancellationToken.ThrowIfCancellationRequested();
        Assert.SkipUnless(OperatingSystem.IsWindows(), "Windows native section lifetime and sharing");
        using var fixture = new OwnedDirectory();
        var path = Path.Combine(fixture.Path, "data");
        File.WriteAllText(path, "test-owned original");
        using var process = StartPython(WindowsSectionHolderScript, path, kind);
        try
        {
            Assert.Equal("READY", await ReadLine(process));
            using var root = WorkspacePath.OpenRoot(fixture.Path);
            var error = Assert.Throws<WorkspacePathException>(() =>
            {
                using var unexpected = root.OpenExistingWriteGuard("data");
            });
            Assert.Equal("file_in_use", error.Reason);
            await process.StandardInput.WriteLineAsync("map");
            Assert.Equal("STILL_MAPPED", await ReadLine(process));
            await process.StandardInput.WriteLineAsync("finish");
            await process.WaitForExitAsync(cancellationToken).WaitAsync(TimeSpan.FromSeconds(8), cancellationToken);
            Assert.Equal(0, process.ExitCode);
        }
        finally
        {
            Stop(process);
        }

        Assert.Equal("test-owned original", File.ReadAllText(path));
        using var reopened = WorkspacePath.OpenRoot(fixture.Path);
        using var guard = reopened.OpenExistingWriteGuard("data");
        Assert.True(guard.MatchesExpectedHash(SHA256.HashData("test-owned original"u8), cancellationToken));
    }

    [Fact(Timeout = 30_000)]
    [Trait("env", "windows-real")]
    public void WindowsSameProcessSurvivingReadonlyViewAlsoRefuses()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        Assert.SkipUnless(OperatingSystem.IsWindows(), "Windows native surviving view");
        using var fixture = new OwnedDirectory();
        var path = Path.Combine(fixture.Path, "data");
        File.WriteAllText(path, "test-owned original");
        MemoryMappedViewAccessor view;
        using (var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
        using (var section = MemoryMappedFile.CreateFromFile(stream, null, 0, MemoryMappedFileAccess.Read,
            HandleInheritability.None, leaveOpen: true))
        {
            view = section.CreateViewAccessor(0, 0, MemoryMappedFileAccess.Read);
        }

        using (view)
        using (var root = WorkspacePath.OpenRoot(fixture.Path))
        {
            Assert.Equal((byte)'t', view.ReadByte(0));
            var error = Assert.Throws<WorkspacePathException>(() =>
            {
                using var unexpected = root.OpenExistingWriteGuard("data");
            });
            Assert.Equal("file_in_use", error.Reason);
            Assert.Equal((byte)'t', view.ReadByte(0));
        }

        Assert.Equal("test-owned original", File.ReadAllText(path));
        using var reopened = WorkspacePath.OpenRoot(fixture.Path);
        using var guard = reopened.OpenExistingWriteGuard("data");
        guard.CheckIntact();
    }

    private const string WindowsSectionHolderScript = """
        import ctypes, sys
        from ctypes import wintypes as w
        path, kind = sys.argv[1:]
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.CreateFileW.argtypes = [w.LPCWSTR, w.DWORD, w.DWORD, ctypes.c_void_p, w.DWORD, w.DWORD, w.HANDLE]
        kernel.CreateFileW.restype = w.HANDLE
        kernel.CreateFileMappingW.argtypes = [w.HANDLE, ctypes.c_void_p, w.DWORD, w.DWORD, w.DWORD, w.LPCWSTR]
        kernel.CreateFileMappingW.restype = w.HANDLE
        kernel.MapViewOfFile.argtypes = [w.HANDLE, w.DWORD, w.DWORD, w.DWORD, ctypes.c_size_t]
        kernel.MapViewOfFile.restype = ctypes.c_void_p
        kernel.CloseHandle.argtypes = [w.HANDLE]
        kernel.CloseHandle.restype = w.BOOL
        kernel.UnmapViewOfFile.argtypes = [ctypes.c_void_p]
        kernel.UnmapViewOfFile.restype = w.BOOL
        kernel.GetHandleInformation.argtypes = [w.HANDLE, ctypes.POINTER(w.DWORD)]
        kernel.GetHandleInformation.restype = w.BOOL
        handle = kernel.CreateFileW(path, 0xc0000000 if kind == "write_mapping" else 0x80000000, 7, None, 3, 0, None)
        assert handle not in (None, ctypes.c_void_p(-1).value), ctypes.get_last_error()
        protection = 8 if kind == "copy_mapping" else 4 if kind == "write_mapping" else 2
        section = kernel.CreateFileMappingW(handle, None, protection, 0, 0, None)
        assert section, ctypes.get_last_error()
        assert kernel.CloseHandle(handle)
        flags = w.DWORD()
        assert not kernel.GetHandleInformation(handle, ctypes.byref(flags)) and ctypes.get_last_error() == 6
        view = None
        def map_section():
            mapped = kernel.MapViewOfFile(section, 1 if kind == "copy_mapping" else 2 if kind == "write_mapping" else 4, 0, 0, 0)
            assert mapped, ctypes.get_last_error()
            assert kernel.CloseHandle(section)
            assert not kernel.GetHandleInformation(section, ctypes.byref(flags)) and ctypes.get_last_error() == 6
            assert ctypes.string_at(mapped, 8) == b"test-own"
            return mapped
        if kind != "section":
            view = map_section()
        print("READY", flush=True)
        assert sys.stdin.readline().strip() == "map"
        if view is None:
            view = map_section()
        assert ctypes.string_at(view, 8) == b"test-own"
        print("STILL_MAPPED", flush=True)
        assert sys.stdin.readline().strip() == "finish"
        assert kernel.UnmapViewOfFile(view)
        """;
}
