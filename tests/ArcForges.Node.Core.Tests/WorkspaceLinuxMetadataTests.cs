// SPDX-License-Identifier: AGPL-3.0-only
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using ArcForges.Node.Core.Platform;

namespace ArcForges.Node.Core.Tests;

/// <summary>Owned Linux file mode and user-xattr observations; inaccessible attributes and full preservation remain unproven.</summary>
[Trait("env", "linux-real")]
public sealed partial class WorkspaceLinuxMetadataTests
{
    [Fact]
    public unsafe void ActualGuardedWritePreservesObservedModeAndUserAttribute()
    {
        if (!OperatingSystem.IsLinux()) { Assert.Skip("Linux file mode and user xattr."); return; }
        using var fixture = new Fixture();
        var mode = (UnixFileMode)0x1a0; // 0640
        File.SetUnixFileMode(fixture.Target, mode);
        var attribute = "owned-xattr-synthetic-marker"u8.ToArray();
        fixed (byte* bytes = attribute)
            Assert.Equal(0, SetXattr(fixture.Target, "user.arcforges_test", bytes, (nuint)attribute.Length, 0));
        using (var root = WorkspacePath.OpenRoot(fixture.Root))
        using (var target = root.OpenExistingWriteGuard("target"))
        using (var stage = root.CreateAnonymousStage("changed default content"u8, TestContext.Current.CancellationToken))
        {
            var result = root.ApplyExistingGuardedStage("target", target, stage, SHA256.HashData(fixture.Original),
                TestContext.Current.CancellationToken);
            Assert.Equal(SHA256.HashData("changed default content"u8), result.Sha256);
        }
        Assert.Equal(mode, File.GetUnixFileMode(fixture.Target));
        var observed = new byte[attribute.Length];
        fixed (byte* bytes = observed)
            Assert.Equal((nint)attribute.Length, GetXattr(fixture.Target, "user.arcforges_test", bytes, (nuint)observed.Length));
        Assert.Equal(attribute, observed);
        Assert.Equal("changed default content"u8.ToArray(), File.ReadAllBytes(fixture.Target));
    }

    [Theory]
    [InlineData(0x800)] // setuid
    [InlineData(0x400)] // setgid
    public void SpecialModeBitsRefuseBeforeAnyWrite(int special)
    {
        if (!OperatingSystem.IsLinux()) { Assert.Skip("Linux special mode bits."); return; }
        using var fixture = new Fixture();
        var mode = (UnixFileMode)(0x1c0 | special); // 0700 plus one special bit
        File.SetUnixFileMode(fixture.Target, mode);
        Assert.Equal(mode, File.GetUnixFileMode(fixture.Target));
        using (var root = WorkspacePath.OpenRoot(fixture.Root))
        using (var target = root.OpenExistingWriteGuard("target"))
        using (var stage = root.CreateAnonymousStage("new content"u8, TestContext.Current.CancellationToken))
        {
            var failure = Assert.Throws<WorkspaceGuardedMutationException>(() => root.ApplyExistingGuardedStage(
                "target", target, stage, SHA256.HashData(fixture.Original), TestContext.Current.CancellationToken));
            Assert.False(failure.PossibleEffect);
            Assert.IsType<WorkspacePreservationUnavailableException>(failure.InnerException);
        }
        Assert.Equal(mode, File.GetUnixFileMode(fixture.Target));
        Assert.Equal(fixture.Original, File.ReadAllBytes(fixture.Target));
    }

    [LibraryImport("libc", EntryPoint = "setxattr", StringMarshalling = StringMarshalling.Utf8, SetLastError = true)]
    private static unsafe partial int SetXattr(string path, string name, byte* value, nuint size, int flags);

    [LibraryImport("libc", EntryPoint = "getxattr", StringMarshalling = StringMarshalling.Utf8, SetLastError = true)]
    private static unsafe partial nint GetXattr(string path, string name, byte* value, nuint size);

    private sealed class Fixture : IDisposable
    {
        private readonly DirectoryInfo _directory = Directory.CreateTempSubdirectory("arcforges-linux-metadata-");

        internal Fixture()
        {
            Root = _directory.FullName;
            Target = Path.Combine(Root, "target");
            File.WriteAllBytes(Target, Original);
        }

        internal string Root { get; }

        internal string Target { get; }

        internal byte[] Original { get; } = "original owned bytes"u8.ToArray();

        public void Dispose() => _directory.Delete(recursive: true);
    }
}
