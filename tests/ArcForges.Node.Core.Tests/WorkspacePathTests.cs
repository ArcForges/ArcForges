// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using System.Text;
using ArcForges.Node.Core.Platform;

namespace ArcForges.Node.Core.Tests;

/// <summary>AF-CTR-06: actual native opened identities and no-follow workspace resolution.</summary>
[Trait("feature", "workspace-path")]
public sealed class WorkspacePathTests
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
