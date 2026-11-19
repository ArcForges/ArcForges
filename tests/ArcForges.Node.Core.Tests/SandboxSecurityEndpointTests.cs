// SPDX-License-Identifier: AGPL-3.0-only
using System.Net.Sockets;
using System.Runtime.Versioning;
using ArcForges.Contracts.Sandbox.V2;
using ArcForges.Node.Core.Sandboxes;
using ArcForges.Node.Core.Security;
using ArcForges.Node.Platform.Capabilities;

namespace ArcForges.Node.Core.Tests;

public sealed class SandboxSecurityEndpointTests
{
    [Fact]
    public void ConfiguredUnixSocketProtectsItsPhysicalDirectoryAndRefusesReplacement()
    {
        if (!OperatingSystem.IsLinux())
        {
            Assert.Skip("Linux filesystem Unix socket protection.");
            return;
        }

        VerifyConfiguredEndpoint();
    }

    [SupportedOSPlatform("linux")]
    private static void VerifyConfiguredEndpoint()
    {
        const UnixFileMode privateDirectory = UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute;
        var scratch = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".afep-" + Guid.NewGuid().ToString("N")[..10]);
        Directory.CreateDirectory(scratch, privateDirectory);
        try
        {
            var data = Directory.CreateDirectory(Path.Combine(scratch, "data"), privateDirectory).FullName;
            var stage = Directory.CreateDirectory(Path.Combine(scratch, "stage"), privateDirectory).FullName;
            File.WriteAllText(Path.Combine(stage, "mxc-manifest.json"), string.Empty);
            var other = Directory.CreateDirectory(Path.Combine(scratch, "other"), privateDirectory).FullName;
            var physical = Directory.CreateDirectory(Path.Combine(scratch, "physical", "rpc"), privateDirectory).FullName;
            Directory.CreateSymbolicLink(Path.Combine(scratch, "link"), Path.GetDirectoryName(physical)!);
            var socketPath = Path.Combine(scratch, "link", "rpc", "node.sock");

            using var socket = Bind(socketPath);
            using var endpoint = new SandboxProtectedEndpoint(socketPath);
            Assert.True(endpoint.TryBind());

            Assert.Equal("host_grant_unavailable_or_unsafe", EvaluateGrant(physical, data, stage, endpoint));
            Assert.Equal("host_grant_unavailable_or_unsafe", EvaluateGrant(Path.GetDirectoryName(physical)!, data, stage, endpoint));
            Assert.Equal("official_mxc_installation_untrusted_or_unreadable", EvaluateGrant(other, data, stage, endpoint));
            Assert.False(endpoint.AllowsPrivateRoot(Path.GetDirectoryName(physical)!));
            Assert.True(endpoint.AllowsPrivateRoot(other));

            File.Delete(socketPath);
            using var replacement = Bind(socketPath);
            Assert.Equal("host_grant_unavailable_or_unsafe", EvaluateGrant(other, data, stage, endpoint));
        }
        finally
        {
            Directory.Delete(scratch, recursive: true);
        }
    }

    [SupportedOSPlatform("linux")]
    private static Socket Bind(string path)
    {
        var socket = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
        try
        {
            socket.Bind(new UnixDomainSocketEndPoint(path));
            File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            socket.Listen(1);
            return socket;
        }
        catch
        {
            socket.Dispose();
            throw;
        }
    }

    private static string? EvaluateGrant(string grant, string data, string stage, SandboxProtectedEndpoint endpoint)
    {
        var config = new SandboxConfig
        {
            ProfileId = MxcProfileAdmission.LinuxProfileId,
            ProfileVersion = MxcProfileAdmission.LinuxProfileRevision,
            Network = new NetworkPolicy { Egress = NetworkMode.Deny, Ingress = NetworkMode.Deny, HostLoopback = false },
            Resources = new ResourcePolicy { PressureAction = PressureAction.Throttle },
        };
        config.HostGrants.Add(new HostGrant { HostPath = grant, SandboxPath = grant, Writable = false });
        return SandboxPolicyAdmission.Evaluate(config, data, stage, endpoint).Admission.Reason;
    }
}
