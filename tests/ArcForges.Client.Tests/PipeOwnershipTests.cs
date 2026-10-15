// SPDX-License-Identifier: AGPL-3.0-only
using System.IO.Pipes;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;
using ArcForges.LocalRpc;

namespace ArcForges.Client.Tests;

/// <summary>
/// The client's same-user check of the node's pipe (02 section 3): the server end must be owned by this token's user SID, in an
/// elevated token as in a filtered one. The runtime's <c>PipeOptions.CurrentUserOnly</c> compares with the token's default
/// owner instead, which is BUILTIN\Administrators when elevated (hosted runners, elevated terminals, admins with UAC off) and
/// refused the node's service pipe, owned by the user SID. These tests run in both kinds of session: the hosted Windows runner
/// is elevated, the workstation's agent shell is not; each prints which one it ran in.
/// </summary>
[Trait("env", "windows-real")]
[SupportedOSPlatform("windows")]
public sealed class PipeOwnershipTests
{
    [Fact]
    public void OnlyTheUserSidIsAnAcceptableOwner()
    {
        Assert.SkipUnless(OperatingSystem.IsWindows(), "Windows security identifiers.");
        var user = new SecurityIdentifier("S-1-5-21-1000000001-1000000002-1000000003-1001");
        var otherUser = new SecurityIdentifier("S-1-5-21-1000000001-1000000002-1000000003-1002");
        var administrators = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
        var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);

        Assert.True(NodeConnector.OwnerIsUser(user, user));
        Assert.False(NodeConnector.OwnerIsUser(otherUser, user));
        Assert.False(NodeConnector.OwnerIsUser(administrators, user));
        Assert.False(NodeConnector.OwnerIsUser(system, user));
        Assert.False(NodeConnector.OwnerIsUser(null, user));
        Assert.False(NodeConnector.OwnerIsUser(user, null));
    }

    [Fact(Timeout = 60_000)]
    public async Task APipeOwnedByTheUserSidConnectsInAnElevatedOrFilteredToken()
    {
        Assert.SkipUnless(OperatingSystem.IsWindows(), "Named pipes are the Windows transport.");
        var ct = TestContext.Current.CancellationToken;
        using var identity = WindowsIdentity.GetCurrent();
        var user = identity.User!;
        ReportSession(identity);

        // The node's service pipe protection (DesktopPlatform LocalRpc ServicePipeSecurity): owner and only allowed user the user SID.
        var security = new PipeSecurity();
        security.SetOwner(user);
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        security.AddAccessRule(new PipeAccessRule(user, PipeAccessRights.ReadWrite | PipeAccessRights.CreateNewInstance | PipeAccessRights.Synchronize, AccessControlType.Allow));
        security.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null), PipeAccessRights.ReadWrite, AccessControlType.Allow));
        var name = "af-test-owner-" + Guid.NewGuid().ToString("N")[..12];
        await using var server = NamedPipeServerStreamAcl.Create(name, PipeDirection.InOut, 1, PipeTransmissionMode.Byte, PipeOptions.Asynchronous, 0, 0, security);
        Assert.Equal(user, server.GetAccessControl().GetOwner(typeof(SecurityIdentifier)));
        var accepted = server.WaitForConnectionAsync(ct);

        await using var client = await NodeConnector.OpenAsync(LocalRpcEndpoint.NamedPipe(name), ct);
        await accepted;
        var received = new byte[1];
        var read = server.ReadAsync(received, ct).AsTask();
        await client.WriteAsync(new byte[] { 42 }, ct);
        Assert.Equal(1, await read);
        Assert.Equal(42, received[0]);
    }

    [Fact(Timeout = 60_000)]
    public async Task APipeOwnedByTheTokensDefaultOwnerIsAcceptedOnlyWhenThatOwnerIsTheUser()
    {
        Assert.SkipUnless(OperatingSystem.IsWindows(), "Named pipes are the Windows transport.");
        var ct = TestContext.Current.CancellationToken;
        using var identity = WindowsIdentity.GetCurrent();
        var elevatedOwner = ReportSession(identity);

        // No explicit security: the pipe's owner is the token's default owner (BUILTIN\Administrators when elevated, else the user).
        var name = "af-test-owner-" + Guid.NewGuid().ToString("N")[..12];
        await using var server = new NamedPipeServerStream(name, PipeDirection.InOut, 1, PipeTransmissionMode.Byte, PipeOptions.Asynchronous);
        Assert.Equal(identity.Owner, server.GetAccessControl().GetOwner(typeof(SecurityIdentifier)));
        var accepted = server.WaitForConnectionAsync(ct);

        if (elevatedOwner)
        {
            // Fail closed: a pipe this user's process can create, but not owned by the user SID, is refused before anything is sent.
            var failure = await Assert.ThrowsAsync<EndpointConnectException>(async () => await NodeConnector.OpenAsync(LocalRpcEndpoint.NamedPipe(name), ct));
            Assert.Equal(EndpointFailure.AccessDenied, failure.Failure);
            Assert.Contains(identity.Owner!.Value, failure.InnerException!.Message, StringComparison.Ordinal);
            await accepted;
            var buffer = new byte[1];
            Assert.Equal(0, await server.ReadAsync(buffer, ct));
        }
        else
        {
            await using var client = await NodeConnector.OpenAsync(LocalRpcEndpoint.NamedPipe(name), ct);
            await accepted;
        }
    }

    private static bool ReportSession(WindowsIdentity identity)
    {
        var elevatedOwner = identity.Owner != identity.User;
        TestContext.Current.TestOutputHelper?.WriteLine(elevatedOwner
            ? $"Elevated token: default owner {identity.Owner} differs from the user SID."
            : "Filtered (non-elevated) token: the default owner is the user SID.");
        return elevatedOwner;
    }
}
