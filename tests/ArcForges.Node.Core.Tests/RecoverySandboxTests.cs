// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Sandbox.V2;
using ArcForges.Node.Core.Files;
using ArcForges.Node.Core.Platform;
using ArcForges.Node.Core.Sandboxes;
using ArcForges.Node.Store;

namespace ArcForges.Node.Core.Tests;

public sealed partial class SandboxRegistryTests
{
    [Fact(Timeout = 60_000)]
    [Trait("env", "windows-real")]
    [Trait("env", "linux-real")]
    public void ErrorRepairRevalidatesTheOwnedRootAndCommitsOneKnownRevision()
    {
        string stage = QualifiedStage();
        var ct = TestContext.Current.CancellationToken;
        using var fixture = new RegistryFixture();
        using var store = fixture.Open();
        using var manager = fixture.Manager(store, stage);
        var epoch = Handshake(manager, ct).OwnerEpoch;
        var sandbox = Created(manager, CreateRequest(epoch, "repair owned root"), ct);
        string id = Hex(sandbox.SandboxId);
        string originalIdentity = RootIdentity(store, sandbox.SandboxId);
        string held = sandbox.DataLocation + "-held";
        string foreign = Path.Combine(sandbox.DataLocation, "foreign.txt");
        string data = Path.Combine(sandbox.DataLocation, "data", "sentinel.txt");
        File.WriteAllText(data, "persistent repair data");
        SetRecoveryFixtureState(store, id, StoredSandboxState.Error);

        var repair = ConfigureRequest(sandbox, epoch, "repaired");
        repair.RepairError = true;
        Directory.Move(sandbox.DataLocation, held);
        try
        {
            CreateOwnerOnlyDataRoot(sandbox.DataLocation);
            File.WriteAllText(foreign, "foreign root sentinel");
            var refused = manager.Configure(repair, ct);
            Assert.Equal("identity_changed", refused.Error.Code);
            Assert.Equal(EffectCertainty.DidNotHappen, refused.Error.Effect);
            Assert.Equal("foreign root sentinel", File.ReadAllText(foreign));
            Assert.Equal(1L, Count(store, "SELECT count(*) FROM command_receipt;"));
            File.Delete(foreign);
            Directory.Delete(sandbox.DataLocation);
        }
        finally
        {
            if (!Directory.Exists(sandbox.DataLocation))
            {
                Directory.Move(held, sandbox.DataLocation);
            }
        }

        SetRecoveryFixtureState(store, id, StoredSandboxState.RecoveryRequired);
        Assert.Equal("sandbox_state_conflict", manager.Configure(repair, ct).Error.Details.State.Reason);
        SetRecoveryFixtureState(store, id, StoredSandboxState.Error);
        var repaired = manager.Configure(repair, ct);
        Assert.Null(repaired.Error);
        Assert.Equal(SandboxState.Ready, repaired.Value.Sandbox.State);
        Assert.Equal(2L, repaired.Value.Sandbox.Revision.Value);
        Assert.Equal(repaired.Value.Sandbox, manager.Configure(repair, ct).Value.Sandbox);
        Assert.Equal(originalIdentity, RootIdentity(store, sandbox.SandboxId));
        Assert.Equal("persistent repair data", File.ReadAllText(data));
        Assert.Equal(2L, Count(store, "SELECT count(*) FROM command_receipt;"));
        Assert.Equal(2L, Count(store, "SELECT count(*) FROM sandbox_config;"));
    }

    [Fact(Timeout = 60_000)]
    [Trait("env", "windows-real")]
    [Trait("env", "linux-real")]
    public void ErrorRepairRefusesAnUnknownReceiptAfterItsRunBecameTerminal()
    {
        string stage = QualifiedStage();
        var ct = TestContext.Current.CancellationToken;
        using var fixture = new RegistryFixture();
        using var store = fixture.Open();
        Id epoch;
        Sandbox sandbox;
        string owner;
        using (var manager = fixture.Manager(store, stage))
        {
            epoch = Handshake(manager, ct).OwnerEpoch;
            sandbox = Created(manager, CreateRequest(epoch, "unresolved repair"), ct);
            owner = manager.OwnerId;
        }

        var run = NewId();
        var start = NewId();
        SeedRecoveryRequiredRun(store, sandbox, run);
        SetRecoveryFixtureState(store, Hex(sandbox.SandboxId), StoredSandboxState.Error);
        using (var authority = new DurableCommandStore(store, owner, NodeSecretStores.ForTestDataRoot(fixture.DataRoot)))
        {
            var intent = new DurableIntent(start.Value.ToByteArray(), epoch.Value.ToByteArray(), "RunService.Start", "run", Hex(run), []);
            authority.AdmitObserved(intent, "UNKNOWN", (int)EffectCertainty.Unknown, """{"reason":"payload_start_unobserved"}""", transaction =>
            {
                transaction.Execute("UPDATE run SET state=5, ended_utc=created_utc WHERE run_id=$run;", ("$run", Hex(run)));
            });
        }

        using var reopened = fixture.Manager(store, stage, owner);
        var repair = ConfigureRequest(sandbox, epoch, "refused repair");
        repair.RepairError = true;
        var response = reopened.Configure(repair, ct);
        Assert.Equal("managed_use", response.Error.Code);
        Assert.Equal(EffectCertainty.DidNotHappen, response.Error.Effect);
        Assert.Equal(2L, Count(store, "SELECT count(*) FROM command_receipt;"));
        Assert.Equal(1L, Count(store, "SELECT count(*) FROM sandbox_config;"));
        Assert.Equal(SandboxState.Error, reopened.Inspect(new() { SandboxId = sandbox.SandboxId, Meta = Query() }, ct).Value.Sandbox.State);
    }

    [Theory(Timeout = 60_000)]
    [InlineData(false)]
    [InlineData(true)]
    [Trait("env", "windows-real")]
    [Trait("env", "linux-real")]
    public async Task DeleteSuccessorPreservesTheOriginalUnknownAndHeldNativeIdentity(bool quarantined)
    {
        string stage = QualifiedStage();
        var ct = TestContext.Current.CancellationToken;
        using var fixture = new RegistryFixture();
        var clock = new RegistryClock();
        using var store = fixture.Open(clock);
        Id epoch;
        Sandbox sandbox;
        string owner;
        using (var manager = fixture.Manager(store, stage, clock: clock))
        {
            epoch = Handshake(manager, ct).OwnerEpoch;
            sandbox = Created(manager, CreateRequest(epoch, "interrupted deletion"), ct);
            owner = manager.OwnerId;
        }

        var original = NewId();
        string deletionId = Hex(NewId());
        string originalIdentity = RootIdentity(store, sandbox.SandboxId);
        File.WriteAllText(Path.Combine(sandbox.DataLocation, "data", "owned.txt"), "still owned");
        string controlPath = Path.Combine(fixture.DataRoot, "control");
        string quarantinePath = Path.Combine(controlPath, SandboxPrivateRoots.DeletionQuarantineName, deletionId);
        string seededPath = quarantined ? quarantinePath : sandbox.DataLocation;
        string? quarantineIdentity = null;
        if (quarantined)
        {
            using (var control = WorkspacePath.OpenRoot(controlPath))
            using (var parent = control.CreateSandboxDirectory(SandboxPrivateRoots.DeletionQuarantineName))
            {
                var components = originalIdentity.Split(':');
                components[1] = deletionId;
                components[5] = Convert.ToBase64String(RegisteredWorkspaces.RootIdentity.Encode(parent.RootIdentity).Bytes);
                quarantineIdentity = string.Join(':', components);
            }
            // Seed the predecessor's physical relocation before calling the resume handler.
            Directory.Move(sandbox.DataLocation, quarantinePath);
        }

        var secrets = NodeSecretStores.ForTestDataRoot(fixture.DataRoot);
        using (var authority = new DurableCommandStore(store, owner, secrets))
        {
            string id = Hex(sandbox.SandboxId);
            var intent = new DurableIntent(original.Value.ToByteArray(), epoch.Value.ToByteArray(),
                SandboxDeletionRecords.Method, "sandbox", id, [], sandbox.Revision.Value);
            Assert.Equal(DurableDecision.Execute, authority.Admit(intent, transaction =>
            {
                string now = SandboxRecords.FormatTime(clock.GetUtcNow());
                var persisted = SandboxRecords.Get(transaction, owner, id)!;
                transaction.Execute("UPDATE sandbox SET state=6, revision=2 WHERE sandbox_id=$sandbox;", ("$sandbox", id));
                SandboxRecords.InsertConfig(transaction, id, 2, persisted.Config, now);
                transaction.Execute("""
                    INSERT INTO deletion_journal(deletion_id,sandbox_id,owner_id,owner_epoch,command_id,expected_revision,
                        root_identity,quarantine_identity,phase,effect_certainty,updated_utc)
                    VALUES($id,$sandbox,$owner,$epoch,$command,1,$root,$quarantine,$phase,3,$now);
                    """, ("$id", deletionId), ("$sandbox", id), ("$owner", owner), ("$epoch", epoch.Value.ToByteArray()),
                    ("$command", Hex(original)), ("$root", originalIdentity), ("$quarantine", quarantineIdentity),
                    ("$phase", quarantined ? "removing" : "locked"), ("$now", now));
            }).Decision);
            authority.SetResult(intent.CommandId, "UNKNOWN", (int)EffectCertainty.Unknown,
                """{"revision":2,"reason":"original_cleanup_unconfirmed"}""");
        }

        var resume = new SandboxServiceDeleteRequest
        {
            Meta = Command(2),
            SandboxId = sandbox.SandboxId,
            OwnerEpoch = epoch,
            ResumeCommandId = original,
        };
        string foreign = Path.Combine(fixture.Root, "foreign.txt");
        File.WriteAllText(foreign, "keep foreign");
        using (var manager = fixture.Manager(store, stage, owner, clock))
        {
            var before = manager.GetOperation(new() { Meta = Query(), CommandId = original, OwnerEpoch = epoch }, ct);
            Assert.Equal(OperationState.Unknown, before.Value.Operation.State);
            Assert.Equal(2L, Count(store, "SELECT count(*) FROM command_receipt;"));

            var wrongOriginal = resume.Clone();
            wrongOriginal.ResumeCommandId = NewId();
            Assert.Equal("not_found", manager.Delete(wrongOriginal, ct).Error.Code);
            var wrongEpoch = resume.Clone();
            wrongEpoch.OwnerEpoch = NewId();
            Assert.Equal("owner_epoch_retired", manager.Delete(wrongEpoch, ct).Error.Code);
            var stale = resume.Clone();
            stale.Meta.ExpectedRev.Value = 1;
            Assert.Equal("revision_mismatch", manager.Delete(stale, ct).Error.Code);

            string moved = seededPath + "-moved";
            Directory.Move(seededPath, moved);
            try
            {
                Assert.Equal("identity_changed", manager.Delete(resume, ct).Error.Code);
            }
            finally
            {
                Directory.Move(moved, seededPath);
            }

            if (OperatingSystem.IsWindows())
            {
                using var owned = File.Open(Path.Combine(seededPath, "data", "owned.txt"),
                    FileMode.Open, FileAccess.Read, FileShare.Read);
                lock (manager.OwnershipGate)
                {
                    var continued = manager.Delete(resume, ct);
                    Assert.True(continued.Value is not null, continued.Error?.ToString());
                    Assert.Equal(resume.Meta.CommandId, continued.Value!.Operation.CommandId);
                    Assert.Equal(OperationState.Accepted, continued.Value.Operation.State);
                    Assert.Equal(EffectCertainty.Unknown, continued.Value.Operation.Effect);
                    Assert.Equal(3L, continued.Value.Operation.Revision.Value);
                    Assert.Equal(continued.Value.Operation, manager.Delete(resume, ct).Value.Operation);
                    var second = resume.Clone();
                    second.Meta = Command(3);
                    Assert.Equal("managed_use", manager.Delete(second, ct).Error.Code);
                    Assert.Equal(SandboxState.Deleting,
                        manager.Inspect(new() { Meta = Query(), SandboxId = sandbox.SandboxId }, ct).Value.Sandbox.State);
                }

                while (true)
                {
                    var observed = manager.GetOperation(new() { Meta = Query(), CommandId = resume.Meta.CommandId, OwnerEpoch = epoch }, ct);
                    if (observed.Value.Operation.State != OperationState.Accepted)
                    {
                        Assert.Equal(OperationState.Unknown, observed.Value.Operation.State);
                        Assert.Equal(EffectCertainty.Unknown, observed.Value.Operation.Effect);
                        break;
                    }

                    await Task.Delay(25, ct);
                }

                manager.StopDeletionWorkers();
            }
            else
            {
                var refusal = manager.Delete(resume, ct).Error;
                Assert.Equal("path_rejected", refusal.Code);
                Assert.Equal(WorkspacePath.LinuxSandboxDeletionGuardUnavailable, refusal.Details.State.Reason);
                Assert.Equal(EffectCertainty.DidNotHappen, refusal.Effect);
                Assert.Equal(SandboxState.Deleting,
                    manager.Inspect(new() { Meta = Query(), SandboxId = sandbox.SandboxId }, ct).Value.Sandbox.State);
            }

            var after = manager.GetOperation(new() { Meta = Query(), CommandId = original, OwnerEpoch = epoch }, ct);
            Assert.Equal(before.Value.Operation.State, after.Value.Operation.State);
            Assert.Equal(before.Value.Operation.Effect, after.Value.Operation.Effect);
            Assert.Equal("original_cleanup_unconfirmed", after.Value.Operation.Error.Details.State.Reason);
        }

        clock.Advance(TimeSpan.FromHours(25));
        using var reopened = new DurableCommandStore(store, owner, secrets);
        _ = reopened.CompactKnownResponses();
        Assert.Equal("UNKNOWN", reopened.Inspect(original.Value.Span)!.State);
        Assert.False(reopened.Inspect(original.Value.Span)!.Compacted);
        var successor = reopened.Inspect(resume.Meta.CommandId.Value.Span);
        var journal = store.Read(reader => SandboxDeletionRecords.ReadOriginal(reader, owner, epoch.Value.ToByteArray(),
            Hex(sandbox.SandboxId), Hex(original)))!;
        Assert.Equal(Hex(original), journal.OriginalCommandId);
        if (OperatingSystem.IsWindows())
        {
            Assert.Equal("UNKNOWN", successor!.State);
            Assert.False(successor.Compacted);
            Assert.Equal(Hex(resume.Meta.CommandId), journal.LatestSuccessorId);
        }
        else
        {
            Assert.Null(successor);
            Assert.Null(journal.LatestSuccessorId);
        }

        if (quarantined || !OperatingSystem.IsWindows())
        {
            Assert.Equal(quarantineIdentity, journal.QuarantineIdentity);
        }

        string retainedPath = Directory.Exists(quarantinePath) ? quarantinePath : sandbox.DataLocation;
        Assert.False(Directory.Exists(quarantinePath) && Directory.Exists(sandbox.DataLocation));
        if (!OperatingSystem.IsWindows())
        {
            Assert.Equal(seededPath, retainedPath);
        }

        if (journal.QuarantineIdentity is not null)
        {
            Assert.Equal(quarantinePath, retainedPath);
        }

        Assert.Equal("still owned", File.ReadAllText(Path.Combine(retainedPath, "data", "owned.txt")));
        Assert.Equal("keep foreign", File.ReadAllText(foreign));
    }

    private static void SetRecoveryFixtureState(NodeStore store, string id, StoredSandboxState state) =>
        store.Write(transaction => transaction.Execute("UPDATE sandbox SET state=$state WHERE sandbox_id=$id;",
            ("$state", (int)state), ("$id", id)), CommitDurability.Full);

    [Fact(Timeout = 60_000)]
    [Trait("env", "windows-real")]
    [Trait("env", "linux-real")]
    public async Task LocalDeleteResumeDispatchesOnlyItsPublishedRequestShape()
    {
        AssertNativePlatform();
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = InProcessNode.Create();
        CreateOwnerOnlyDataRoot(fixture.DataRoot);
        await fixture.StartAsync();
        await using var channel = NodeChannel.Create(fixture.Endpoint);
        var node = new NodeService.NodeServiceClient(channel.CallInvoker);
        var sandboxes = new SandboxService.SandboxServiceClient(channel.CallInvoker);
        var hello = await node.HandshakeAsync(new NodeServiceHandshakeRequest { Meta = Query() }, cancellationToken: ct);
        Assert.Null(hello.Error);
        var epoch = hello.Value.OwnerEpoch;
        try
        {
            var resume = new SandboxServiceDeleteRequest
            {
                Meta = Command(2),
                OwnerEpoch = epoch,
                SandboxId = NewId(),
                ResumeCommandId = NewId(),
            };
            var missing = await sandboxes.DeleteAsync(resume, cancellationToken: ct);
            Assert.Equal("not_found", missing.Error.Code);
            resume.PlanId = NewId();
            var invalid = await sandboxes.DeleteAsync(resume, cancellationToken: ct);
            Assert.Equal("invalid_argument", invalid.Error.Code);
            Assert.Equal(EffectCertainty.DidNotHappen, invalid.Error.Effect);
        }
        finally
        {
            RemoveLocalOwnerKey(fixture, epoch);
        }
    }
}
