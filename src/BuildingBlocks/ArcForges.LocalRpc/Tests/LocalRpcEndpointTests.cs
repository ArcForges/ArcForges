// SPDX-License-Identifier: AGPL-3.0-only
using System.Runtime.Versioning;
using Xunit;

namespace ArcForges.LocalRpc.Tests;

// One collection: the hosting-URL test changes process-wide environment variables, so no other test may run beside it.
[Collection(LocalRpcCollection.Name)]
public sealed class LocalRpcEndpointTests
{
    [Theory]
    [InlineData("af-3fa2.child_1")]
    [InlineData("A")]
    [InlineData("0")]
    public void PipeNamesAreOneFlatAsciiSegment(string name)
    {
        var endpoint = LocalRpcEndpoint.CreateForVerification(LocalRpcTransport.NamedPipe, name);

        Assert.Equal(LocalRpcTransport.NamedPipe, endpoint.Transport);
        Assert.Equal(name, endpoint.Address);
    }

    [Theory]
    [InlineData("")]
    [InlineData(".hidden")]
    [InlineData("-leading")]
    [InlineData("..")]
    [InlineData("a/b")]
    [InlineData("a\\b")]
    [InlineData("\\\\.\\pipe\\x")]
    [InlineData("\\\\server\\pipe\\x")]
    [InlineData("a b")]
    [InlineData("a:b")]
    [InlineData("naïve")]
    [InlineData("a\0b")]
    public void PipeNamesThatCouldBePathsHostsOrNonAsciiAreRefused(string name)
    {
        Assert.Throws<ArgumentException>(() => LocalRpcEndpoint.CreateForVerification(LocalRpcTransport.NamedPipe, name));
    }

    [Fact]
    public void PipeNameLengthIsBounded()
    {
        var longest = new string('a', LocalRpcEndpoint.MaximumPipeNameLength);

        Assert.Equal(longest, LocalRpcEndpoint.CreateForVerification(LocalRpcTransport.NamedPipe, longest).Address);
        Assert.Throws<ArgumentException>(() => LocalRpcEndpoint.CreateForVerification(LocalRpcTransport.NamedPipe, longest + "a"));
    }

    [Fact]
    public void SocketPathsAreCanonicalLocalAbsoluteAndShort()
    {
        var root = Path.Combine(Path.GetTempPath(), "afrpc");
        var valid = Path.Combine(root, "child.sock");

        var endpoint = LocalRpcEndpoint.CreateForVerification(LocalRpcTransport.UnixDomainSocket, valid);

        Assert.Equal(LocalRpcTransport.UnixDomainSocket, endpoint.Transport);
        Assert.Equal(valid, endpoint.Address);
        string[] invalid =
        [
            string.Empty,
            "child.sock",
            Path.Combine("afrpc", "child.sock"),
            valid + Path.DirectorySeparatorChar,
            Path.Combine(root, "..", "child.sock"),
            Path.Combine(root, ".", "child.sock"),
            valid + "\0",
            @"\\host\share\child.sock",
            Path.Combine(root, new string('a', LocalRpcEndpoint.MaximumSocketPathBytes)),
        ];
        foreach (var path in invalid)
        {
            Assert.Throws<ArgumentException>(() => LocalRpcEndpoint.CreateForVerification(LocalRpcTransport.UnixDomainSocket, path));
        }

        Assert.Throws<ArgumentOutOfRangeException>(() => LocalRpcEndpoint.CreateForVerification(LocalRpcTransport.None, "x"));
    }

    [Fact]
    public void ThePublicFactoriesRefuseTheOtherPlatformsTransport()
    {
        Assert.Throws<ArgumentNullException>(() => LocalRpcEndpoint.NamedPipe(null!));
        Assert.Throws<ArgumentNullException>(() => LocalRpcEndpoint.UnixDomainSocket(null!));
        if (OperatingSystem.IsWindows())
        {
            Assert.Equal(LocalRpcTransport.NamedPipe, LocalRpcEndpoint.NamedPipe("af-endpoint-check").Transport);
            Assert.Throws<ArgumentException>(() => LocalRpcEndpoint.NamedPipe("a/b"));
            Assert.Throws<PlatformNotSupportedException>(() => LocalRpcEndpoint.UnixDomainSocket(Path.Combine(Path.GetTempPath(), "x.sock")));
        }
        else
        {
            var path = Path.Combine(Path.GetTempPath(), "afrpc-endpoint-check.sock");
            Assert.Equal(LocalRpcTransport.UnixDomainSocket, LocalRpcEndpoint.UnixDomainSocket(path).Transport);
            Assert.Throws<ArgumentException>(() => LocalRpcEndpoint.UnixDomainSocket("relative.sock"));
            Assert.Throws<PlatformNotSupportedException>(() => LocalRpcEndpoint.NamedPipe("af-endpoint-check"));
        }
    }

    [Fact]
    [UnsupportedOSPlatform("windows")]
    public void ASocketDirectoryThatAnotherUserCouldReachIsRefused()
    {
        Assert.SkipWhen(OperatingSystem.IsWindows(), "Unix permission bits do not exist on Windows.");
        var directory = Directory.CreateTempSubdirectory("afrpc-mode-").FullName;
        try
        {
            var socket = Path.Combine(directory, "a.sock");
            File.SetUnixFileMode(directory, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
            UnixSocketAcceptSource.RequireOwnerOnlyDirectory(socket);
            foreach (var extra in new[] { UnixFileMode.GroupRead, UnixFileMode.GroupExecute, UnixFileMode.OtherRead, UnixFileMode.OtherWrite, UnixFileMode.OtherExecute })
            {
                File.SetUnixFileMode(directory, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute | extra);
                Assert.Throws<UnauthorizedAccessException>(() => UnixSocketAcceptSource.RequireOwnerOnlyDirectory(socket));
            }

            Assert.Throws<DirectoryNotFoundException>(() => UnixSocketAcceptSource.RequireOwnerOnlyDirectory(Path.Combine(directory, "missing", "a.sock")));
        }
        finally
        {
            File.SetUnixFileMode(directory, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
            Directory.Delete(directory, recursive: true);
        }
    }
}
