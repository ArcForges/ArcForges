// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.AccessControl;
using System.Security.Principal;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Node.Store;
using Grpc.Core;
using Fleet = ArcForges.Contracts.Fleet.V1;
using V2 = ArcForges.Contracts.Sandbox.V2;

namespace ArcForges.Node.Core.Tests;

public sealed class RetiredLocalRoutesTests
{
    [Fact(Timeout = 60_000)]
    public async Task TheCurrentOwnerEndpointServesV2AndHasNoLegacyExecutionOrWorkspaceSurface()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var node = InProcessNode.Create();
        if (OperatingSystem.IsWindows())
        {
            using var principal = WindowsIdentity.GetCurrent();
            var user = principal.User ?? throw new InvalidOperationException("The test principal has no user SID.");
            var access = new DirectorySecurity();
            access.SetOwner(user);
            access.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
            access.AddAccessRule(new FileSystemAccessRule(user, FileSystemRights.FullControl,
                InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
            new DirectoryInfo(node.DataRoot).Create(access);
        }

        await node.StartAsync();
        string? ownerKey = null;
        try
        {
            await using var owner = await node.ChannelAsync(helloAsHuman: true);
            var invoker = owner.CallInvoker;
            var deadline = DateTime.UtcNow.AddSeconds(10);
            var health = await owner.Node.GetHealthAsync(new NodeServiceGetHealthRequest(), deadline: deadline, cancellationToken: ct);
            Assert.Null(health.Error);
            Assert.NotNull(health.Value);

            var v2 = new V2.NodeService.NodeServiceClient(invoker);
            var handshake = await v2.HandshakeAsync(new() { Meta = new RequestMeta { CorrelationId = CommandIds.New() } },
                deadline: deadline, cancellationToken: ct);
            if (handshake.Value?.OwnerEpoch is { Value.Length: 16 } epoch)
            {
                ownerKey = NodeDataKeyRing.TargetName(node.Runtime.NodeId.Span, "v2-owner-" + Convert.ToHexStringLower(epoch.Value.Span));
            }

            Assert.Null(handshake.Error);
            Assert.Equal(16, handshake.Value.OwnerEpoch.Value.Length);

            await Unimplemented(new TaskService.TaskServiceClient(invoker)
                .GetTaskAsync(new(), deadline: deadline, cancellationToken: ct));
            await Unimplemented(new ResourceService.ResourceServiceClient(invoker)
                .GetResourceSnapshotAsync(new(), deadline: deadline, cancellationToken: ct));
            await Unimplemented(new QueueService.QueueServiceClient(invoker)
                .ListPoolsAsync(new(), deadline: deadline, cancellationToken: ct));
            await Unimplemented(new PolicyService.PolicyServiceClient(invoker)
                .GetPolicyAsync(new(), deadline: deadline, cancellationToken: ct));
            await Unimplemented(new WorkspaceService.WorkspaceServiceClient(invoker)
                .ListWorkspacesAsync(new(), deadline: deadline, cancellationToken: ct));
            await Unimplemented(new FileService.FileServiceClient(invoker)
                .GetFileOperationAsync(new(), deadline: deadline, cancellationToken: ct));
            await Unimplemented(new Fleet.FleetService.FleetServiceClient(invoker)
                .ListNodesAsync(new(), deadline: deadline, cancellationToken: ct));
        }
        finally
        {
            var exitCode = await node.StopAsync();
            if (ownerKey is not null)
            {
                Assert.True(node.Secrets.Delete(ownerKey));
            }

            Assert.Equal(0, exitCode);
        }
    }

    private static async Task Unimplemented<TResponse>(AsyncUnaryCall<TResponse> call)
    {
        using (call)
        {
            var error = await Assert.ThrowsAsync<RpcException>(() => call.ResponseAsync);
            Assert.Equal(StatusCode.Unimplemented, error.StatusCode);
        }
    }
}
