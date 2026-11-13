// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using ArcForges.Node.Core.Platform;

namespace ArcForges.Node.Core.Tests;

/// <summary>AF-CTR-06: actual native opened identities and no-follow workspace resolution.</summary>
[Trait("feature", "workspace-path")]
public sealed partial class WorkspacePathTests
{
    [Fact(Timeout = 30_000)]
    public void ActualHandlesRemainAnchoredAfterOpeningAnotherDirectory()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        using var fixture = new OwnedDirectory();
        var root = Directory.CreateDirectory(Path.Combine(fixture.Path, "root")).FullName;
        Directory.CreateDirectory(Path.Combine(root, "nested"));
        File.WriteAllText(Path.Combine(root, "root.txt"), "root contents");
        File.WriteAllText(Path.Combine(root, "nested", "inside.txt"), "nested contents");
        using var opened = WorkspacePath.OpenRoot(root);
        var expected = opened.RootIdentity;
        Assert.True(expected.IsDirectory);
        Assert.True(Path.IsPathFullyQualified(opened.RootPath));
        opened.OpenDirectory("nested");
        Assert.True(expected.SameObject(WorkspacePath.Identity(opened.RootHandle)));
        Assert.Equal("nested contents", Read(opened.OpenRead("nested/inside.txt")));
        Assert.Equal("root contents", Read(opened.OpenRead("root.txt")));
        using var reopened = WorkspacePath.OpenRoot(opened.RootPath, expected);
        Assert.True(expected.SameObject(reopened.RootIdentity));
    }

    [Theory]
    [InlineData("")]
    [InlineData("../outside.txt")]
    [InlineData("nested/../../outside.txt")]
    [InlineData("/outside.txt")]
    [InlineData("C:/outside.txt")]
    [InlineData("C:outside.txt")]
    [InlineData("\\\\server\\share\\outside.txt")]
    [InlineData("nested//outside.txt")]
    [InlineData("nested/./outside.txt")]
    [InlineData("nested/")]
    [InlineData("nested\\outside.txt")]
    [InlineData("a\0b")]
    public void InvalidPathsAreRejectedBeforeAnyOpen(string path)
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        Assert.Throws<WorkspacePathException>(() => WorkspacePath.Components(path));
    }

    [Fact(Timeout = 30_000)]
    public void ActualHardLinksCannotAliasAnOutsideFile()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        using var fixture = new OwnedDirectory();
        var root = Directory.CreateDirectory(Path.Combine(fixture.Path, "root")).FullName;
        var outside = Path.Combine(fixture.Path, "outside.txt");
        File.WriteAllText(outside, "private outside content");
        var link = Path.Combine(root, "alias.txt");
        Run(OperatingSystem.IsWindows() ? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "cmd.exe") : "ln",
            OperatingSystem.IsWindows() ? ["/d", "/c", "mklink", "/H", link, outside] : [outside, link]);
        Assert.Equal(2, FileLinks.Count(link));
        using var opened = WorkspacePath.OpenRoot(root);
        var error = Assert.Throws<WorkspacePathException>(() => opened.OpenRead("alias.txt"));
        Assert.Equal("file_hard_link", error.Reason);
        Assert.Equal("private outside content", File.ReadAllText(outside));
    }

    [Fact(Timeout = 30_000)]
    public void AReplacedRegisteredRootIsRefusedByOpenedIdentity()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        using var fixture = new OwnedDirectory();
        var root = Directory.CreateDirectory(Path.Combine(fixture.Path, "root")).FullName;
        WorkspaceObjectIdentity expected;
        using (var opened = WorkspacePath.OpenRoot(root))
        {
            expected = opened.RootIdentity;
        }

        Directory.Move(root, Path.Combine(fixture.Path, "old-root"));
        Directory.CreateDirectory(root);
        var error = Assert.Throws<WorkspacePathException>(() => WorkspacePath.OpenRoot(root, expected));
        Assert.Equal("root_changed", error.Reason);
    }

    [Fact(Timeout = 30_000)]
    [Trait("env", "linux-real")]
    public void LinuxRefusesFinalAndIntermediateSymlinksAndNonRegularObjects()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        Assert.SkipUnless(OperatingSystem.IsLinux(), "Linux native path semantics");
        using var fixture = new OwnedDirectory();
        var root = Directory.CreateDirectory(Path.Combine(fixture.Path, "root")).FullName;
        var outside = Directory.CreateDirectory(Path.Combine(fixture.Path, "outside")).FullName;
        File.WriteAllText(Path.Combine(outside, "secret.txt"), "outside marker");
        Directory.CreateSymbolicLink(Path.Combine(root, "jump"), outside);
        File.CreateSymbolicLink(Path.Combine(root, "final.txt"), Path.Combine(outside, "secret.txt"));
        Run("mkfifo", [Path.Combine(root, "fifo")]);
        using var opened = WorkspacePath.OpenRoot(root);
        Assert.Throws<WorkspacePathException>(() => opened.OpenRead("jump/secret.txt"));
        Assert.Throws<WorkspacePathException>(() => opened.OpenRead("final.txt"));
        Assert.Throws<WorkspacePathException>(() => opened.OpenRead("fifo"));
        Assert.Throws<WorkspacePathException>(() => WorkspacePath.OpenRoot(Path.Combine(root, "jump")));
        Assert.Equal("path_invalid", Assert.Throws<WorkspacePathException>(() => WorkspacePath.OpenRoot(Path.Combine(root, "jump", "..", "root"))).Reason);
        Assert.Equal("outside marker", File.ReadAllText(Path.Combine(outside, "secret.txt")));
    }

    [Fact(Timeout = 30_000)]
    [Trait("env", "windows-real")]
    public void WindowsRefusesRealJunctionsAndReservedOrAlternateStreamNames()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        Assert.SkipUnless(OperatingSystem.IsWindows(), "Windows native path semantics");
        using var fixture = new OwnedDirectory();
        var root = Directory.CreateDirectory(Path.Combine(fixture.Path, "root")).FullName;
        var outside = Directory.CreateDirectory(Path.Combine(fixture.Path, "outside")).FullName;
        File.WriteAllText(Path.Combine(outside, "secret.txt"), "outside marker");
        Run(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "cmd.exe"),
            ["/d", "/c", "mklink", "/J", Path.Combine(root, "jump"), outside]);
        using (var opened = WorkspacePath.OpenRoot(root))
        {
            Assert.Throws<WorkspacePathException>(() => opened.OpenRead("jump/secret.txt"));
            Assert.Equal("path_invalid", Assert.Throws<WorkspacePathException>(() => WorkspacePath.OpenRoot(Path.Combine(root, "jump", "..", "root"))).Reason);
            foreach (var path in (string[])["NUL", "con.txt", "aux.log", "COM1.txt", "LPT9", "COM\u00b9", "name.", "name ", "normal:stream"])
            {
                Assert.Throws<WorkspacePathException>(() => WorkspacePath.Components(path));
            }

            Assert.Equal("outside marker", File.ReadAllText(Path.Combine(outside, "secret.txt")));
        }

        // Dispose every native guard before removing this exact test-owned junction without traversal.
        // This also proves a refused reparse open has not leaked a no-delete-sharing handle.
        Directory.Delete(Path.Combine(root, "jump"));
        Assert.False(Directory.Exists(Path.Combine(root, "jump")));
        Assert.Equal("outside marker", File.ReadAllText(Path.Combine(outside, "secret.txt")));
    }


    [Fact(Timeout = 30_000)]
    [Trait("env", "windows-real")]
    public void WindowsEnumerationReopensTheHeldDirectoryAndRejectsJunctions()
    {
        Assert.SkipUnless(OperatingSystem.IsWindows(), "Windows native directory handles");
        using var fixture = new OwnedDirectory();
        var root = Directory.CreateDirectory(Path.Combine(fixture.Path, "root")).FullName;
        var nested = Directory.CreateDirectory(Path.Combine(root, "nested")).FullName;
        var outside = Directory.CreateDirectory(Path.Combine(fixture.Path, "outside")).FullName;
        var junction = Path.Combine(root, "jump");
        File.WriteAllText(Path.Combine(nested, "inside.txt"), "checked content");
        File.WriteAllText(Path.Combine(outside, "outside.txt"), "outside marker");
        Run(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "cmd.exe"),
            ["/d", "/c", "mklink", "/J", junction, outside]);

        using (var workspace = WorkspacePath.OpenRoot(root))
        {
            using var rootAgain = workspace.OpenDirectoryForEnumeration("");
            Assert.True(workspace.RootIdentity.SameObject(WorkspacePath.Identity(rootAgain)));
            var nestedAnchor = workspace.OpenDirectory("nested");
            using var nestedAgain = workspace.OpenDirectoryForEnumeration("nested");
            Assert.True(WorkspacePath.Identity(nestedAnchor).SameObject(WorkspacePath.Identity(nestedAgain)));

            var rootNames = WorkspaceDirectoryEntries.Read(workspace, "", 100, TestContext.Current.CancellationToken).Names;
            Assert.Contains("nested", rootNames);
            Assert.Contains("jump", rootNames);
            Assert.Equal(rootNames, WorkspaceDirectoryEntries.Read(workspace, "", 100, TestContext.Current.CancellationToken).Names);
            var names = WorkspaceDirectoryEntries.Read(workspace, "nested", 100, TestContext.Current.CancellationToken).Names;
            Assert.Equal(["inside.txt"], names);
            Assert.Equal(names, WorkspaceDirectoryEntries.Read(workspace, "nested", 100, TestContext.Current.CancellationToken).Names);
            Assert.Throws<WorkspacePathException>(() => workspace.OpenDirectoryForEnumeration("jump"));

            var rootMove = Record.Exception(() => Directory.Move(root, Path.Combine(fixture.Path, "moved-root")));
            var nestedMove = Record.Exception(() => Directory.Move(nested, Path.Combine(root, "moved-nested")));
            Assert.True(rootMove is IOException or UnauthorizedAccessException);
            Assert.True(nestedMove is IOException or UnauthorizedAccessException);
            Assert.Equal("outside marker", File.ReadAllText(Path.Combine(outside, "outside.txt")));
        }

        // The retained handles are released by disposal; removing the junction never traverses its target.
        Directory.Delete(junction);
        Directory.Move(nested, Path.Combine(root, "moved-nested"));
        Directory.Move(root, Path.Combine(fixture.Path, "moved-root"));
        Assert.Equal("outside marker", File.ReadAllText(Path.Combine(outside, "outside.txt")));

        // A workspace may be the drive root, which has no parent component to reopen relative to.
        using var drive = WorkspacePath.OpenRoot(Path.GetPathRoot(fixture.Path)!);
        using var driveAgain = drive.OpenDirectoryForEnumeration("");
        Assert.True(drive.RootIdentity.SameObject(WorkspacePath.Identity(driveAgain)));
    }

    [Fact(Timeout = 30_000)]
    public void AnOpenedFileIsReadByHandleAfterACompetingNameReplacement()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        using var fixture = new OwnedDirectory();
        var root = Directory.CreateDirectory(Path.Combine(fixture.Path, "root")).FullName;
        var path = Path.Combine(root, "data.txt");
        File.WriteAllText(path, "the checked object");
        var outside = Path.Combine(fixture.Path, "outside.txt");
        File.WriteAllText(outside, "an outside object");
        using var opened = WorkspacePath.OpenRoot(root);
        var handle = opened.OpenRead("data.txt");
        if (OperatingSystem.IsWindows())
        {
            // The premise is the actual OS sharing refusal, not a simulated no-follow result.
            Assert.Throws<IOException>(() => File.Move(path, Path.Combine(root, "renamed.txt")));
        }
        else
        {
            File.Move(path, Path.Combine(root, "renamed.txt"));
            File.CreateSymbolicLink(path, outside);
            Assert.Throws<WorkspacePathException>(() => opened.OpenRead("data.txt"));
        }

        Assert.Equal("the checked object", Read(handle));
        Assert.Equal("an outside object", File.ReadAllText(outside));
    }

    [Fact(Timeout = 30_000)]
    [Trait("env", "windows-real")]
    public void WindowsCaseVariantsFollowTheActualDirectorySemantics()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        Assert.SkipUnless(OperatingSystem.IsWindows(), "Windows native case semantics");
        using var fixture = new OwnedDirectory();
        var root = Directory.CreateDirectory(Path.Combine(fixture.Path, "root")).FullName;
        File.WriteAllText(Path.Combine(root, "lower.txt"), "same native object");
        using var opened = WorkspacePath.OpenRoot(root);
        if (File.Exists(Path.Combine(root, "LOWER.TXT")))
        {
            Assert.Equal("same native object", Read(opened.OpenRead("LOWER.TXT")));
        }
        else
        {
            Assert.Throws<WorkspacePathException>(() => opened.OpenRead("LOWER.TXT"));
        }

        Assert.Equal("same native object", Read(opened.OpenRead("lower.txt")));
    }

    [Fact]
    public void InvalidUnicodeAndUtf8LengthAreRefusedBeforeNativeResolution()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        var malformed = new string((char)0xd800, 1);
        Assert.Equal("path_invalid_utf8", Assert.Throws<WorkspacePathException>(() => WorkspacePath.Components(malformed)).Reason);
        Assert.Equal("path_too_large", Assert.Throws<WorkspacePathException>(() => WorkspacePath.Components(new string('é', 2049))).Reason);
        using var fixture = new OwnedDirectory();
        Assert.Equal("path_invalid_utf8", Assert.Throws<WorkspacePathException>(() => WorkspacePath.OpenRoot(Path.Combine(fixture.Path, malformed))).Reason);
    }

    [Fact(Timeout = 30_000)]
    [Trait("env", "linux-real")]
    public void RecreatedDirectoriesDoNotReuseThePersistedNativeIdentity()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        Assert.SkipUnless(OperatingSystem.IsLinux(), "Linux inode generation and birth-time reuse");
        using var fixture = new OwnedDirectory();
        var path = Path.Combine(fixture.Path, "recreated");
        Directory.CreateDirectory(path);
        WorkspaceObjectIdentity previous;
        using (var opened = WorkspacePath.OpenRoot(path))
        {
            previous = opened.RootIdentity;
        }

        for (var index = 0; index < 128; index++)
        {
            TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
            Directory.Delete(path);
            Directory.CreateDirectory(path);
            using var next = WorkspacePath.OpenRoot(path);
            Assert.False(previous.SameObject(next.RootIdentity));
            if (previous.Low == next.RootIdentity.Low && previous.Created == next.RootIdentity.Created &&
                previous.CreatedNanoseconds == next.RootIdentity.CreatedNanoseconds)
            {
                Assert.False(previous.InstanceToken.Span.SequenceEqual(next.RootIdentity.InstanceToken.Span));
            }

            var failure = Assert.Throws<WorkspacePathException>(() => WorkspacePath.OpenRoot(path, previous));
            Assert.Equal("root_changed", failure.Reason);
            previous = next.RootIdentity;
        }
    }

    [Fact(Timeout = 30_000)]
    public void RawAbsoluteRootComponentsAreCheckedBeforeNormalization()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        using var fixture = new OwnedDirectory();
        var target = Directory.CreateDirectory(Path.Combine(fixture.Path, "target")).FullName;
        var separator = Path.DirectorySeparatorChar;
        foreach (var invalid in new[]
        {
            fixture.Path + separator + "." + separator + "target",
            fixture.Path + separator + "jump" + separator + ".." + separator + "target",
            fixture.Path + separator + separator + "target",
            target + separator,
        })
        {
            Assert.Equal("path_invalid", Assert.Throws<WorkspacePathException>(() => WorkspacePath.OpenRoot(invalid)).Reason);
        }

        using var opened = WorkspacePath.OpenRoot(target);
        Assert.True(opened.RootIdentity.IsDirectory);
    }

    [Fact(Timeout = 30_000)]
    [Trait("env", "linux-real")]
    public void LinuxParentMovedOutsideCannotSupplyANewFileToTheRootLookup()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        Assert.SkipUnless(OperatingSystem.IsLinux(), "Linux native root-relative lookup");
        using var fixture = new OwnedDirectory();
        var root = Directory.CreateDirectory(Path.Combine(fixture.Path, "root")).FullName;
        var parent = Directory.CreateDirectory(Path.Combine(root, "parent")).FullName;
        var moved = Path.Combine(fixture.Path, "outside-parent");
        using var opened = WorkspacePath.OpenRoot(root);
        var retainedParent = opened.OpenDirectory("parent");
        var before = WorkspacePath.Identity(retainedParent);
        Directory.Move(parent, moved);
        File.WriteAllText(Path.Combine(moved, "external.txt"), "outside synthetic data");
        Assert.True(before.SameObject(WorkspacePath.Identity(retainedParent)));
        Assert.Throws<WorkspacePathException>(() => opened.OpenRead("parent/external.txt"));
        Assert.Equal("outside synthetic data", File.ReadAllText(Path.Combine(moved, "external.txt")));
    }

    [Fact(Timeout = 30_000)]
    [Trait("env", "linux-real")]
    public void LinuxFifoIsRejectedWithoutEnablingAnExternalWriter()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        Assert.SkipUnless(OperatingSystem.IsLinux(), "Linux FIFO native open semantics");
        using var fixture = new OwnedDirectory();
        var fifo = Path.Combine(fixture.Path, "fifo");
        Run("mkfifo", [fifo]);
        using var opened = WorkspacePath.OpenRoot(fixture.Path);
        static void AssertNoReader(string path)
        {
            var writer = OpenLinux(path, 1 | 0x800 | 0x80000);
            var error = Marshal.GetLastPInvokeError();
            if (writer >= 0)
            {
                CloseLinux(writer);
            }

            Assert.True(writer < 0 && error == 6, "FIFO writer must receive ENXIO while there is no data reader");
        }

        AssertNoReader(fifo);
        var reachedCheckpoint = false;
        var failure = Assert.Throws<WorkspacePathException>(() => opened.OpenRead("fifo", () =>
        {
            reachedCheckpoint = true;
            AssertNoReader(fifo);
        }));
        Assert.True(reachedCheckpoint);
        Assert.Equal("path_link_or_special", failure.Reason);
        AssertNoReader(fifo);
        foreach (var entry in Directory.EnumerateFileSystemEntries("/proc/self/fd"))
        {
            string? target;
            try
            {
                target = new FileInfo(entry).LinkTarget;
            }
            catch (IOException)
            {
                continue; // Another runtime-owned descriptor can close during enumeration.
            }

            Assert.NotEqual(fifo, target);
        }
    }

    [Fact(Timeout = 30_000)]
    [Trait("env", "linux-real")]
    public void LinuxDataReopenUsesTheCheckedObjectAfterItsNameIsReplaced()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        Assert.SkipUnless(OperatingSystem.IsLinux(), "Linux procfs handle reopening");
        using var fixture = new OwnedDirectory();
        var root = Directory.CreateDirectory(Path.Combine(fixture.Path, "root")).FullName;
        var target = Path.Combine(root, "file");
        var original = Path.Combine(root, "retained");
        var outside = Path.Combine(fixture.Path, "outside");
        File.WriteAllText(target, "verified object");
        File.WriteAllText(outside, "outside marker");
        using var opened = WorkspacePath.OpenRoot(root);
        var reachedCheckpoint = false;
        var file = opened.OpenRead("file", () =>
        {
            reachedCheckpoint = true;
            File.Move(target, original);
            File.CreateSymbolicLink(target, outside);
        });
        Assert.True(reachedCheckpoint);
        Assert.Equal("verified object", Read(file));
        Assert.Throws<WorkspacePathException>(() => opened.OpenRead("file"));
        Assert.Equal("outside marker", File.ReadAllText(outside));
    }

    [Fact(Timeout = 30_000)]
    [Trait("env", "linux-real")]
    public void LinuxLiteralDeletedSuffixIsAllowedButAnUnlinkedRootIsRefused()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        Assert.SkipUnless(OperatingSystem.IsLinux(), "Linux deleted-object metadata");
        using var fixture = new OwnedDirectory();
        var live = Directory.CreateDirectory(Path.Combine(fixture.Path, "valid (deleted)")).FullName;
        using (var opened = WorkspacePath.OpenRoot(live))
        {
            Assert.Equal(live, opened.RootPath);
            Assert.True(opened.RootIdentity.Links > 0);
            using var reopened = WorkspacePath.OpenRoot(live, opened.RootIdentity);
            Assert.True(opened.RootIdentity.SameObject(reopened.RootIdentity));
        }

        var removed = Directory.CreateDirectory(Path.Combine(fixture.Path, "removed")).FullName;
        var failure = Assert.Throws<WorkspacePathException>(() => WorkspacePath.OpenRoot(removed, expected: null, afterRootOpen: () =>
        {
            Directory.Delete(removed);
            Directory.CreateDirectory(removed);
        }));
        Assert.Equal("root_changed", failure.Reason);
        using var replacement = WorkspacePath.OpenRoot(removed);
        Assert.Equal(removed, replacement.RootPath);
    }

    [Fact(Timeout = 30_000)]
    [Trait("env", "linux-real")]
    public void LinuxSearchOnlyAncestorDoesNotNeedDirectoryReadPermission()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        Assert.SkipUnless(OperatingSystem.IsLinux(), "Linux search-only ancestor permission");
        if (!OperatingSystem.IsLinux())
        {
            return;
        }

        using var fixture = new OwnedDirectory();
        var ancestor = Directory.CreateDirectory(Path.Combine(fixture.Path, "search-only")).FullName;
        var root = Directory.CreateDirectory(Path.Combine(ancestor, "root")).FullName;
        File.WriteAllText(Path.Combine(root, "visible.txt"), "known child");
        var nested = Directory.CreateDirectory(Path.Combine(root, "nested-search-only")).FullName;
        File.WriteAllText(Path.Combine(nested, "visible.txt"), "known nested child");
        var previousMode = File.GetUnixFileMode(ancestor);
        var previousNestedMode = File.GetUnixFileMode(nested);
        try
        {
            File.SetUnixFileMode(ancestor, UnixFileMode.UserExecute | UnixFileMode.GroupExecute | UnixFileMode.OtherExecute);
            File.SetUnixFileMode(nested, UnixFileMode.UserExecute | UnixFileMode.GroupExecute | UnixFileMode.OtherExecute);
            var readFd = OpenLinux(ancestor, 0x10000 | 0x80000);
            var readError = Marshal.GetLastPInvokeError();
            if (readFd >= 0)
            {
                CloseLinux(readFd);
            }

            Assert.True(readFd < 0 && readError == 13, "a read-mode directory open must receive EACCES");
            var metadataFd = OpenLinux(ancestor, 0x200000 | 0x10000 | 0x80000);
            Assert.True(metadataFd >= 0, "O_PATH must retain search-only ancestor access");
            CloseLinux(metadataFd);
            var nestedRead = OpenLinux(nested, 0x10000 | 0x80000);
            var nestedError = Marshal.GetLastPInvokeError();
            if (nestedRead >= 0)
            {
                CloseLinux(nestedRead);
            }

            Assert.True(nestedRead < 0 && nestedError == 13, "the intermediate directory must also deny reading");
            using var opened = WorkspacePath.OpenRoot(root);
            Assert.Equal("known child", Read(opened.OpenRead("visible.txt")));
            Assert.Equal("known nested child", Read(opened.OpenRead("nested-search-only/visible.txt")));
        }
        finally
        {
            File.SetUnixFileMode(nested, previousNestedMode);
            File.SetUnixFileMode(ancestor, previousMode);
        }
    }

    [LibraryImport("libc", EntryPoint = "open", StringMarshalling = StringMarshalling.Utf8, SetLastError = true)]
    private static partial int OpenLinux(string name, int flags);

    [LibraryImport("libc", EntryPoint = "close", SetLastError = true)]
    private static partial int CloseLinux(int descriptor);

    private static string Read(Microsoft.Win32.SafeHandles.SafeFileHandle handle)
    {
        var bytes = new byte[256];
        var count = RandomAccess.Read(handle, bytes, 0);
        return Encoding.UTF8.GetString(bytes.AsSpan(0, count));
    }

    private static void Run(string executable, string[] arguments)
    {
        using var process = Process.Start(new ProcessStartInfo(executable, arguments)
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
        })!;
        var output = process.StandardOutput.ReadToEnd() + process.StandardError.ReadToEnd();
        Assert.True(process.WaitForExit(10_000) && process.ExitCode == 0, "native fixture setup failed: " + output);
    }

    private sealed class OwnedDirectory : IDisposable
    {
        private readonly DirectoryInfo _directory = Directory.CreateTempSubdirectory("arcforges-workspace-path-");
        public string Path => _directory.FullName;
        public void Dispose() => _directory.Delete(recursive: true);
    }
}
