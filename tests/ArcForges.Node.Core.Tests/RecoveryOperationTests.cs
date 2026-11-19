// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.AccessControl;
using System.Security.Principal;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Sandbox.V2;
using ArcForges.Node.Core.Sandboxes;
using ArcForges.Node.Store;
using Google.Protobuf;

namespace ArcForges.Node.Core.Tests;

public sealed class RecoveryOperationTests
{
    [Fact]
    [Trait("env", "windows-real")]
    [Trait("env", "linux-real")]
    public async Task FreshRunRecoveryAndOperationLookupLeaveOwnerAuthorityUninitialized()
    {
        var directory = Directory.CreateTempSubdirectory("arcforges-operation-recovery-");
        try
        {
            var dataRoot = Path.Combine(directory.FullName, "node-data");
            if (OperatingSystem.IsWindows())
            {
                using var identity = WindowsIdentity.GetCurrent();
                var sid = Assert.IsType<SecurityIdentifier>(identity.User);
                var access = new DirectorySecurity();
                access.SetOwner(sid);
                access.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
                access.AddAccessRule(new FileSystemAccessRule(sid, FileSystemRights.FullControl,
                    InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None,
                    AccessControlType.Allow));
                new DirectoryInfo(dataRoot).Create(access);
            }

            var clock = TimeProvider.System;
            using var store = NodeStore.Open(new NodeStoreOptions
            {
                DataRoot = dataRoot,
                BootIdentity = "operation-recovery-fixture",
                Clock = clock,
            });
            const string owner = "recovery-operation-owner";
            using var manager = new SandboxManager(store, dataRoot, owner,
                NodeSecretStores.ForTestDataRoot(dataRoot), clock);
            var ct = TestContext.Current.CancellationToken;

            Assert.True(store.Opening.Created);
            manager.VerifyExistingAuthority();
            await manager.RecoverRunsAsync(new RecoveryReport(false, false, null, store.Opening), ct);

            var request = new NodeServiceGetOperationRequest
            {
                Meta = new() { CorrelationId = IdOf(StoreIds.NewUuid7(clock)) },
                OwnerEpoch = IdOf(StoreIds.NewUuid7(clock)),
                CommandId = IdOf(StoreIds.NewUuid7(clock)),
            };
            var reply = manager.GetOperation(request, ct);
            Assert.Equal("not_found", reply.Error.Code);
            Assert.Null(reply.Value);
            Assert.False(DurableCommandStore.HasExistingAuthority(store, owner));
            Assert.False(File.Exists(DurableEpochFence.PathFor(dataRoot, owner) + ".lock"));
        }
        finally
        {
            directory.Delete(recursive: true);
        }
    }

    [Fact]
    [Trait("env", "windows-real")]
    [Trait("env", "linux-real")]
    public void ReadsOriginalUnresolvedOperationWhileMutationAuthorityIsHeld()
    {
        var directory = Directory.CreateTempSubdirectory("arcforges-operation-recovery-");
        try
        {
            var observedAt = new DateTimeOffset(2026, 11, 20, 3, 5, 0, TimeSpan.Zero);
            var clock = new FixedClock(observedAt);
            using var store = NodeStore.Open(new NodeStoreOptions
            {
                DataRoot = directory.FullName,
                BootIdentity = "operation-recovery-fixture",
                Clock = clock,
            });
            const string owner = "recovery-operation-owner";
            var secrets = NodeSecretStores.ForTestDataRoot(directory.FullName);
            using var authority = new DurableCommandStore(store, owner, secrets);
            byte[] commandId = StoreIds.NewUuid7(clock);
            byte[] sandboxId = StoreIds.NewUuid7(clock);
            var intent = new DurableIntent(commandId, authority.OwnerEpoch.ToArray(), "SandboxService.Delete",
                "sandbox", StoreIds.ToHex(sandboxId), []);
            Assert.Equal(DurableDecision.Execute, authority.Admit(intent).Decision);
            authority.SetResult(commandId, "UNKNOWN", (int)EffectCertainty.Unknown,
                """{"revision":8,"reason":"interrupted_cleanup"}""");
            var sequence = store.Read(reader => reader.Scalar("SELECT admission_sequence FROM owner_epoch WHERE owner_id=$owner;",
                ("$owner", owner)));

            // This instance has no write authority while the original live store holds it.
            using var manager = new SandboxManager(store, directory.FullName, owner, secrets, clock);
            var request = new NodeServiceGetOperationRequest
            {
                Meta = new() { CorrelationId = IdOf(StoreIds.NewUuid7(clock)) },
                OwnerEpoch = IdOf(intent.OwnerEpoch),
                CommandId = IdOf(commandId),
            };
            var ct = TestContext.Current.CancellationToken;
            var reply = manager.GetOperation(request, ct);
            Assert.Null(reply.Error);
            var operation = reply.Value.Operation;
            Assert.Equal(request.OwnerEpoch, operation.OwnerEpoch);
            Assert.Equal(request.CommandId, operation.CommandId);
            Assert.Equal(IdOf(sandboxId), operation.AggregateId);
            Assert.Equal(OperationState.Unknown, operation.State);
            Assert.Equal(EffectCertainty.Unknown, operation.Effect);
            Assert.Equal(8L, operation.Revision.Value);
            Assert.Equal("interrupted_cleanup", operation.Error.Details.State.Reason);
            Assert.Equal(ProtoTime.ToInstant(observedAt), operation.UpdatedAt);
            Assert.False(operation.ResponseCompacted);

            byte[] differentEpoch = intent.OwnerEpoch.ToArray();
            differentEpoch[0] ^= 1;
            request.OwnerEpoch = IdOf(differentEpoch);
            Assert.Equal("not_found", manager.GetOperation(request, ct).Error.Code);
            Assert.Equal(sequence, store.Read(reader => reader.Scalar("SELECT admission_sequence FROM owner_epoch WHERE owner_id=$owner;",
                ("$owner", owner))));
        }
        finally
        {
            directory.Delete(recursive: true);
        }
    }

    private static Id IdOf(byte[] bytes) => new() { Value = ByteString.CopyFrom(bytes) };

    private sealed class FixedClock(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }
}
