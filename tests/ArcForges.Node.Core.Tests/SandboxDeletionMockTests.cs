// SPDX-License-Identifier: AGPL-3.0-only
using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Sandbox.V2;
using ArcForges.Node.Core.Platform;
using ArcForges.Node.Core.Sandboxes;
using ArcForges.Node.Store;
using Google.Protobuf;

namespace ArcForges.Node.Core.Tests;

public sealed partial class SandboxRegistryTests
{
    [Fact(Timeout = 30_000)]
    [Trait("category", "sandbox-delete-component")]
    public async Task MockDeleteCommitsQuarantineBeforeBoundedBatchesAndProofBeforeTombstone()
    {
        var token = TestContext.Current.CancellationToken;
        using var fixture = new RegistryFixture();
        using var store = fixture.Open();
        string external = Directory.CreateDirectory(Path.Combine(fixture.Root, "external")).FullName;
        string externalFile = Path.Combine(external, "keep.txt");
        File.WriteAllText(externalFile, "external");
        var config = DefaultConfig();
        config.HostGrants.Add(new HostGrant { HostPath = external, SandboxPath = external });
        var row = SeedMockDeleteSandbox(fixture, store, "target", config);
        var sibling = SeedMockDeleteSandbox(fixture, store, "sibling", DefaultConfig());
        string siblingFile = Path.Combine(fixture.DataRoot, sibling.RootRelative, "data", "keep.txt");
        File.WriteAllText(siblingFile, "sibling");
        var effects = new MockDeletionEffects(row) { RemainingEntries = 273 };
        using var manager = OpenMockDeleteManager(fixture, store, effects);
        var request = PlanMockDelete(manager, row, token, external);
        effects.Bind(request.PlanId);

        effects.Observe = call =>
        {
            var pending = ReadMockDelete(store, row, request);
            switch (call)
            {
                case "require_fresh":
                    Assert.Null(pending);
                    break;
                case "quarantine":
                    Assert.Equal("locked", pending!.Phase);
                    Assert.Equal("ACCEPTED", pending.OriginalState);
                    Assert.Null(pending.QuarantineIdentity);
                    Assert.Empty(JsonParser.Default.Parse<SandboxConfig>(ReadMockSandbox(store, row).Config.Json).HostGrants);
                    break;
                default:
                    Assert.Equal("removing", pending!.Phase);
                    Assert.Equal(effects.QuarantineIdentity, pending.QuarantineIdentity);
                    Assert.False(pending.RemovalVerified);
                    break;
            }
        };

        AssertMockAdmission(manager.Delete(request, token), request);
        var completed = await WaitMockDeleteAsync(manager, request, token);
        AssertMockCompletion(completed, request);
        Assert.Equal(["require_fresh", "quarantine", "batch", "batch", "batch", "verify"], effects.Calls.ToArray());
        Assert.Equal([128, 128, 17], effects.Removals.ToArray());
        Assert.Equal(MockDeletionLocation.Absent, effects.Location);
        AssertMockTombstone(store, row, request, effects.QuarantineIdentity);
        Assert.Equal("sibling", File.ReadAllText(siblingFile));
        Assert.Equal("external", File.ReadAllText(externalFile));
        Assert.Equal(sibling, ReadMockSandbox(store, sibling));

        AssertMockCompletion(manager.Delete(request, token).Value.Operation, request);
        Assert.Equal(6, effects.Calls.Count);
    }

    [Fact(Timeout = 30_000)]
    [Trait("category", "sandbox-delete-component")]
    public async Task MockDeleteRefusesUnavailableGuardBeforeAdmissionAndRetainsUncertaintyAfterProgress()
    {
        var token = TestContext.Current.CancellationToken;
        using var fixture = new RegistryFixture();
        SandboxServiceDeleteRequest original;
        MockDeletionEffects effects;
        StoredSandbox row;
        StoredSandboxDeletion held;
        using (var store = fixture.Open())
        {
            row = SeedMockDeleteSandbox(fixture, store, "guarded", DefaultConfig());
            effects = new MockDeletionEffects(row) { GuardAvailable = false, RemainingEntries = 129 };
            using var manager = OpenMockDeleteManager(fixture, store, effects);
            original = PlanMockDelete(manager, row, token);
            effects.Bind(original.PlanId);

            AssertMockRefusal(manager.Delete(original, token), "path_rejected", WorkspacePath.LinuxSandboxDeletionGuardUnavailable);
            Assert.Null(ReadMockDelete(store, row, original));
            Assert.Equal("not_found", ReadMockOperation(manager, original, token).Error.Code);
            Assert.Equal(row, ReadMockSandbox(store, row));
            Assert.Equal(["require_fresh"], effects.Calls.ToArray());
            Assert.Equal(MockDeletionLocation.Original, effects.Location);
            Assert.Empty(effects.Removals);

            effects.GuardAvailable = true;
            effects.Observe = call =>
            {
                if (call == "batch" && !effects.Removals.IsEmpty)
                {
                    effects.GuardAvailable = false;
                }
            };
            AssertMockAdmission(manager.Delete(original, token), original);
            var uncertain = await WaitMockDeleteAsync(manager, original, token);
            AssertMockUncertainty(uncertain, WorkspacePath.LinuxSandboxDeletionGuardUnavailable);
            Assert.Equal(["require_fresh", "require_fresh", "quarantine", "batch", "batch"], effects.Calls.ToArray());
            Assert.Equal([128], effects.Removals.ToArray());
            Assert.Equal(1, effects.RemainingEntries);
            Assert.Equal(MockDeletionLocation.Quarantined, effects.Location);
            held = ReadMockDelete(store, row, original)!;
            Assert.Equal("recovery_required", held.Phase);
            Assert.Equal(effects.QuarantineIdentity, held.QuarantineIdentity);
            Assert.Equal(row.RootIdentity, held.RootIdentity);
            Assert.False(held.RemovalVerified);
        }

        using var reopened = fixture.Open();
        using var restarted = OpenMockDeleteManager(fixture, reopened, effects);
        restarted.ReconcileDeletionReceipts();
        Assert.Equal(5, effects.Calls.Count);
        Assert.Equal(held, ReadMockDelete(reopened, row, original));
        effects.Observe = null;
        var successor = ResumeMockDelete(original, ReadMockSandbox(reopened, row).Revision);
        AssertMockRefusal(restarted.Delete(successor, token), "path_rejected", WorkspacePath.LinuxSandboxDeletionGuardUnavailable);
        Assert.Equal("not_found", ReadMockOperation(restarted, successor, token).Error.Code);
        Assert.Equal(held, ReadMockDelete(reopened, row, original));

        effects.GuardAvailable = true;
        AssertMockAdmission(restarted.Delete(successor, token), successor);
        AssertMockCompletion(await WaitMockDeleteAsync(restarted, successor, token), successor);
        AssertMockCompletion(ReadMockOperation(restarted, original, token).Value.Operation, original);
        AssertMockTombstone(reopened, row, original, effects.QuarantineIdentity, successor);
        Assert.Equal([128, 1], effects.Removals.ToArray());
        Assert.Equal(["require_resume", "require_resume", "batch", "verify"], effects.Calls.ToArray()[5..]);
    }

    [Theory(Timeout = 30_000)]
    [InlineData(false)]
    [InlineData(true)]
    [Trait("category", "sandbox-delete-component")]
    public async Task MockDeleteRejectsBorrowedPlanAndUseThatBeganAfterPreview(bool retainedExport)
    {
        var token = TestContext.Current.CancellationToken;
        using var fixture = new RegistryFixture();
        using var store = fixture.Open();
        var target = SeedMockDeleteSandbox(fixture, store, "used", DefaultConfig());
        var sibling = SeedMockDeleteSandbox(fixture, store, "other", DefaultConfig());
        var effects = new MockDeletionEffects(target);
        using var manager = OpenMockDeleteManager(fixture, store, effects);
        var request = PlanMockDelete(manager, target, token);
        effects.Bind(request.PlanId);

        var wrongSandbox = request.Clone();
        wrongSandbox.SandboxId = new Id { Value = ByteString.CopyFrom(Convert.FromHexString(sibling.SandboxId)) };
        AssertMockRefusal(manager.Delete(wrongSandbox, token), "busy", "delete_preview_unavailable");

        try
        {
            Id blocker;
            if (retainedExport)
            {
                File.WriteAllText(Path.Combine(fixture.DataRoot, target.RootRelative, "data", "export.txt"), "export fixture");
                blocker = await RetainMockDeleteExportAsync(manager, request, token);
            }
            else
            {
                blocker = NewId();
                SeedRecoveryRequiredRun(store, new Sandbox { SandboxId = request.SandboxId, Revision = request.Meta.ExpectedRev }, blocker);
            }

            var blockedPreview = manager.PlanDelete(new() { Meta = Query(), SandboxId = request.SandboxId }, token);
            Assert.Null(blockedPreview.Error);
            var plan = blockedPreview.Value.Plan;
            Assert.Equal(blocker, Assert.Single(retainedExport ? plan.BlockingTransferIds : plan.BlockingRuns));
            Assert.Empty(retainedExport ? plan.BlockingRuns : plan.BlockingTransferIds);
            AssertMockRefusal(manager.Delete(request, token), "managed_use", "sandbox_managed_use");

            Assert.Empty(effects.Calls);
            Assert.Equal("not_found", ReadMockOperation(manager, request, token).Error.Code);
            Assert.Equal(0L, Count(store, "SELECT count(*) FROM deletion_journal;"));
            Assert.Equal(target, ReadMockSandbox(store, target));
            Assert.Equal(sibling, ReadMockSandbox(store, sibling));
        }
        finally
        {
            manager.StopDataTransfers();
        }
    }

    [Theory(Timeout = 30_000)]
    [InlineData("locked")]
    [InlineData("moved")]
    [InlineData("quarantined")]
    [InlineData("absent_unverified")]
    [InlineData("absent_verified")]
    [Trait("category", "sandbox-delete-component")]
    public async Task MockDeleteRestartDoesNotRunCleanupAndRequiresAnExactSuccessor(string checkpoint)
    {
        var token = TestContext.Current.CancellationToken;
        using var fixture = new RegistryFixture();
        bool absent = checkpoint is "absent_unverified" or "absent_verified";
        bool verified = checkpoint == "absent_verified";
        StoredSandbox row;
        MockDeletionEffects effects;
        SandboxServiceDeleteRequest original;
        StoredSandboxDeletion interrupted;
        long interruptedRevision;
        using (var store = fixture.Open())
        {
            row = SeedMockDeleteSandbox(fixture, store, "interrupted", DefaultConfig());
            effects = new MockDeletionEffects(row)
            {
                Location = absent ? MockDeletionLocation.Absent : checkpoint == "locked"
                    ? MockDeletionLocation.Original : MockDeletionLocation.Quarantined,
                RemainingEntries = absent ? 0 : 1,
            };
            using (var manager = OpenMockDeleteManager(fixture, store, effects))
            {
                original = PlanMockDelete(manager, row, token);
                effects.Bind(original.PlanId);
            }

            // Recreate the durable state at a loss-of-process checkpoint without launching a worker.
            using var receipts = new DurableCommandStore(store, row.OwnerId, NodeSecretStores.ForTestDataRoot(fixture.DataRoot));
            var command = original.Meta.CommandId.Value.ToByteArray();
            var epoch = original.OwnerEpoch.Value.ToByteArray();
            var canonical = original.Clone();
            canonical.Meta = null;
            canonical.OwnerEpoch = null;
            var intent = new DurableIntent(command, epoch, SandboxDeletionRecords.Method, "sandbox", row.SandboxId,
                canonical.ToByteArray(), row.Revision);
            Assert.Equal(DurableDecision.Execute, receipts.Admit(intent, tx => Assert.True(
                SandboxDeletionRecords.TryAdmitFresh(tx, row, epoch, Hex(original.PlanId), Hex(original.Meta.CommandId), row.Config))).Decision);
            if (checkpoint == "quarantined" || absent)
            {
                AdvanceMockDelete(store, row, original, effects.QuarantineIdentity, "quarantined");
            }
            if (absent)
            {
                AdvanceMockDelete(store, row, original, effects.QuarantineIdentity, "removing");
            }
            if (verified)
            {
                receipts.RecordSandboxRemovalVerified(command, null);
            }

            interrupted = ReadMockDelete(store, row, original)!;
            interruptedRevision = ReadMockSandbox(store, row).Revision;
            Assert.Equal("ACCEPTED", interrupted.OriginalState);
            Assert.Equal(verified, interrupted.RemovalVerified);
        }

        using var reopened = fixture.Open();
        using var restarted = OpenMockDeleteManager(fixture, reopened, effects);
        restarted.ReconcileDeletionReceipts();
        restarted.ReconcileDeletionReceipts();
        var retained = ReadMockDelete(reopened, row, original)!;
        Assert.Equal(interrupted with { OriginalState = "UNKNOWN", Phase = verified ? "removing" : "recovery_required" }, retained);
        var recovered = ReadMockSandbox(reopened, row);
        Assert.Equal(verified ? StoredSandboxState.Deleting : StoredSandboxState.RecoveryRequired, recovered.State);
        Assert.Equal(interruptedRevision + (verified ? 0 : 1), recovered.Revision);
        AssertMockUncertainty(ReadMockOperation(restarted, original, token).Value.Operation, "deletion_worker_interrupted");
        AssertMockUncertainty(restarted.Delete(original, token).Value.Operation, "deletion_worker_interrupted");

        var successor = ResumeMockDelete(original, recovered.Revision);
        var stale = successor.Clone();
        stale.Meta.ExpectedRev.Value = row.Revision;
        AssertMockRefusal(restarted.Delete(stale, token), "revision_mismatch");
        var wrongOriginal = successor.Clone();
        wrongOriginal.ResumeCommandId = NewId();
        AssertMockRefusal(restarted.Delete(wrongOriginal, token), "not_found");
        var wrongEpoch = successor.Clone();
        wrongEpoch.OwnerEpoch = NewId();
        AssertMockRefusal(restarted.Delete(wrongEpoch, token), "owner_epoch_retired");
        Assert.Empty(effects.Calls);
        Assert.Equal(retained, ReadMockDelete(reopened, row, original));

        if (checkpoint == "quarantined")
        {
            effects.Location = MockDeletionLocation.Foreign;
            AssertMockRefusal(restarted.Delete(successor, token), "identity_changed", "deletion_quarantine_identity_changed");
            Assert.Equal("not_found", ReadMockOperation(restarted, successor, token).Error.Code);
            Assert.Equal(retained, ReadMockDelete(reopened, row, original));
            Assert.Equal(MockDeletionLocation.Foreign, effects.Location);
            effects.Location = MockDeletionLocation.Quarantined;
            effects.Calls.Clear();
        }

        if (absent && !verified)
        {
            AssertMockRefusal(restarted.Delete(successor, token), "identity_changed", "native_2");
            Assert.Equal(["require_resume"], effects.Calls.ToArray());
            Assert.Equal("not_found", ReadMockOperation(restarted, successor, token).Error.Code);
            Assert.Equal(retained, ReadMockDelete(reopened, row, original));
            Assert.Equal(recovered, ReadMockSandbox(reopened, row));
            return;
        }

        AssertMockAdmission(restarted.Delete(successor, token), successor);
        AssertMockCompletion(await WaitMockDeleteAsync(restarted, successor, token), successor);
        AssertMockCompletion(ReadMockOperation(restarted, original, token).Value.Operation, original);
        AssertMockTombstone(reopened, row, original, effects.QuarantineIdentity, successor);
        string[] expected = checkpoint switch
        {
            "locked" => ["require_resume", "quarantine", "batch", "verify"],
            "moved" => ["require_resume", "observe", "quarantine", "observe", "batch", "verify"],
            "quarantined" => ["require_resume", "batch", "verify"],
            _ => ["verify", "verify"],
        };
        Assert.Equal(expected, effects.Calls.ToArray());
    }

    private static SandboxManager OpenMockDeleteManager(RegistryFixture fixture, NodeStore store, MockDeletionEffects effects) =>
        new(store, fixture.DataRoot, effects.OwnerId, NodeSecretStores.ForTestDataRoot(fixture.DataRoot), TimeProvider.System,
            mxcInstallationRoot: Path.Combine(fixture.Root, "absent-mxc-installation"), deletionEffects: effects);

    private static StoredSandbox SeedMockDeleteSandbox(RegistryFixture fixture, NodeStore store, string name, SandboxConfig config)
    {
        const string owner = "sandbox-delete-component-owner";
        string id = Hex(NewId());
        var now = store.Clock.GetUtcNow();
        string json = JsonFormatter.Default.Format(config);
        var storedConfig = new StoredSandboxConfig(config.ProfileId, config.ProfileVersion, json,
            Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(json))));
        var reservation = new StoredSandbox(id, owner, name, name.ToUpperInvariant(), 1, StoredSandboxState.Creating,
            SandboxPrivateRoots.RelativePath(id), SandboxRecords.PendingRootIdentity, 1, now, now, storedConfig);
        store.Write(tx => SandboxRecords.Reserve(tx, reservation), CommitDurability.Full);
        // The read-only preview uses a real disposable private root. The fake never mutates it.
        var root = new SandboxPrivateRoots(fixture.DataRoot).Provision(id);
        store.Write(tx => Assert.True(SandboxRecords.SettleCreation(tx, owner, id, root.Identity, StoredSandboxState.Ready)),
            CommitDurability.Full);
        return ReadMockSandbox(store, reservation);
    }

    private static SandboxServiceDeleteRequest PlanMockDelete(SandboxManager manager, StoredSandbox row, CancellationToken token,
        string? external = null)
    {
        var epoch = Handshake(manager, token).OwnerEpoch;
        var id = new Id { Value = ByteString.CopyFrom(Convert.FromHexString(row.SandboxId)) };
        var response = manager.PlanDelete(new() { Meta = Query(), SandboxId = id }, token);
        Assert.Null(response.Error);
        var plan = response.Value.Plan;
        Assert.Equal(row.Revision, plan.Revision.Value);
        Assert.Equal(external is null ? [] : [external], plan.ExcludedHostGrants.ToArray());
        return new() { Meta = Command(plan.Revision.Value), SandboxId = id, PlanId = plan.PlanId, OwnerEpoch = epoch };
    }

    private static SandboxServiceDeleteRequest ResumeMockDelete(SandboxServiceDeleteRequest original, long revision) =>
        new() { Meta = Command(revision), SandboxId = original.SandboxId, ResumeCommandId = original.Meta.CommandId, OwnerEpoch = original.OwnerEpoch };

    private static async Task<Id> RetainMockDeleteExportAsync(SandboxManager manager, SandboxServiceDeleteRequest request,
        CancellationToken token)
    {
        var begun = manager.BeginDataExport(new()
        {
            Meta = Command(request.Meta.ExpectedRev.Value),
            OwnerEpoch = request.OwnerEpoch,
            SandboxId = request.SandboxId,
            RelativePath = "data/export.txt",
        }, token);
        Assert.Null(begun.Error);
        var id = begun.Value.Transfer.TransferId;
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(token);
        deadline.CancelAfter(TimeSpan.FromSeconds(10));
        while (true)
        {
            var snapshot = manager.InspectDataTransfer(new() { Meta = Query(), TransferId = id }, deadline.Token);
            Assert.Null(snapshot.Error);
            var transfer = snapshot.Value.Transfer;
            Assert.Contains(transfer.State, new[] { TransferState.Open, TransferState.Streaming, TransferState.Complete });
            if (transfer.State == TransferState.Complete)
            {
                Assert.Null(transfer.ClosedAt);
                return id;
            }

            await Task.Delay(20, deadline.Token);
        }
    }

    private static StoredSandbox ReadMockSandbox(NodeStore store, StoredSandbox row) =>
        store.Read(reader => SandboxRecords.Get(reader, row.OwnerId, row.SandboxId))!;

    private static StoredSandboxDeletion? ReadMockDelete(NodeStore store, StoredSandbox row, SandboxServiceDeleteRequest request) =>
        store.Read(reader => SandboxDeletionRecords.ReadOriginal(reader, row.OwnerId, request.OwnerEpoch.Value.ToByteArray(),
            row.SandboxId, Hex(request.Meta.CommandId)));

    private static void AdvanceMockDelete(NodeStore store, StoredSandbox row, SandboxServiceDeleteRequest request,
        string quarantineIdentity, string phase) =>
        store.Write(tx => Assert.True(SandboxDeletionRecords.TryAdvance(tx, SandboxRecords.Get(tx, row.OwnerId, row.SandboxId)!,
            request.OwnerEpoch.Value.ToByteArray(), SandboxDeletionRecords.ReadOriginal(tx, row.OwnerId,
                request.OwnerEpoch.Value.ToByteArray(), row.SandboxId, Hex(request.Meta.CommandId))!, phase, quarantineIdentity)), CommitDurability.Full);

    private static NodeServiceGetOperationResponse ReadMockOperation(SandboxManager manager, SandboxServiceDeleteRequest request,
        CancellationToken token) => manager.GetOperation(new()
        {
            Meta = Query(),
            OwnerEpoch = request.OwnerEpoch,
            CommandId = request.Meta.CommandId,
        }, token);

    private static async Task<Operation> WaitMockDeleteAsync(SandboxManager manager, SandboxServiceDeleteRequest request,
        CancellationToken token)
    {
        var started = System.Diagnostics.Stopwatch.StartNew();
        while (started.Elapsed < TimeSpan.FromSeconds(10))
        {
            var result = ReadMockOperation(manager, request, token);
            Assert.Null(result.Error);
            if (result.Value.Operation.State != OperationState.Accepted)
            {
                return result.Value.Operation;
            }

            await Task.Delay(20, token);
        }

        throw new TimeoutException($"Mock Sandbox Delete {Hex(request.Meta.CommandId)} never left ACCEPTED.");
    }

    private static void AssertMockAdmission(SandboxServiceDeleteResponse response, SandboxServiceDeleteRequest request)
    {
        Assert.Null(response.Error);
        Assert.Equal(request.Meta.CommandId, response.Value.Operation.CommandId);
        Assert.Equal(OperationState.Accepted, response.Value.Operation.State);
        Assert.Equal(EffectCertainty.Unknown, response.Value.Operation.Effect);
    }

    private static void AssertMockRefusal(SandboxServiceDeleteResponse response, string code, string? reason = null)
    {
        Assert.Null(response.Value);
        Assert.Equal(code, response.Error.Code);
        Assert.Equal(EffectCertainty.DidNotHappen, response.Error.Effect);
        if (reason is not null)
        {
            Assert.Equal(reason, response.Error.Details.State.Reason);
        }
    }

    private static void AssertMockUncertainty(Operation operation, string reason)
    {
        Assert.Equal(OperationState.Unknown, operation.State);
        Assert.Equal(EffectCertainty.Unknown, operation.Effect);
        Assert.Equal("outcome_unknown", operation.Error.Code);
        Assert.Equal(reason, operation.Error.Details.State.Reason);
    }

    private static void AssertMockCompletion(Operation operation, SandboxServiceDeleteRequest request)
    {
        Assert.Equal(request.Meta.CommandId, operation.CommandId);
        Assert.Equal(request.SandboxId, operation.AggregateId);
        Assert.Equal(OperationState.Succeeded, operation.State);
        Assert.Equal(EffectCertainty.Happened, operation.Effect);
    }

    private static void AssertMockTombstone(NodeStore store, StoredSandbox row, SandboxServiceDeleteRequest original,
        string quarantineIdentity, SandboxServiceDeleteRequest? successor = null)
    {
        var final = ReadMockSandbox(store, row);
        Assert.Equal(StoredSandboxState.Deleted, final.State);
        Assert.Equal(row.RootIdentity, final.RootIdentity);
        Assert.True(store.Read(reader => SandboxDeletionRecords.HasTombstone(reader, row.OwnerId,
            original.OwnerEpoch.Value.ToByteArray(), row.SandboxId, Hex(original.Meta.CommandId),
            successor is null ? null : Hex(successor.Meta.CommandId))));
        Assert.Equal(quarantineIdentity, store.Read(reader => reader.Scalar(
            "SELECT quarantine_identity FROM deletion_journal WHERE deletion_id=$deletion;", ("$deletion", Hex(original.PlanId)))));
        Assert.Null(ReadMockDelete(store, row, original));
    }

    private enum MockDeletionLocation { Original, Quarantined, Absent, Foreign }

    private sealed class MockDeletionEffects(StoredSandbox target) : ISandboxDeletionEffects
    {
        private string? _deletionId;

        public string OwnerId => target.OwnerId;
        public string QuarantineIdentity => $"mock-quarantine-{_deletionId}";
        public ConcurrentQueue<string> Calls { get; } = new();
        public ConcurrentQueue<int> Removals { get; } = new();
        public MockDeletionLocation Location { get; set; }
        public int RemainingEntries { get; set; }
        public bool GuardAvailable { get; set; } = true;
        public Action<string>? Observe { get; set; }

        public void Bind(Id planId) => _deletionId = Hex(planId);

        public void RequireFreshDeletion(string sandboxId, string originalIdentity)
        {
            Require("require_fresh", sandboxId, originalIdentity);
            Assert.Equal(MockDeletionLocation.Original, Location);
        }

        public void RequireDeletionContinuation(string sandboxId, string originalIdentity, string deletionId, string? quarantineIdentity)
        {
            Require("require_resume", sandboxId, originalIdentity, deletionId);
            if (quarantineIdentity is not null)
            {
                Assert.Equal(QuarantineIdentity, quarantineIdentity);
            }

            if (Location == MockDeletionLocation.Foreign)
            {
                throw new SandboxPrivateRootException("deletion_quarantine_identity_changed");
            }

            var expected = quarantineIdentity is null ? MockDeletionLocation.Original : MockDeletionLocation.Quarantined;
            if (Location != expected)
            {
                throw new SandboxPrivateRootException("native_2");
            }
        }

        public string QuarantineDeletion(string sandboxId, string originalIdentity, string deletionId, Action applied,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Require("quarantine", sandboxId, originalIdentity, deletionId);
            if (Location != MockDeletionLocation.Original)
            {
                throw new WorkspacePathException("native_2");
            }

            Location = MockDeletionLocation.Quarantined;
            applied();
            return QuarantineIdentity;
        }

        public string ObserveQuarantinedDeletion(string sandboxId, string originalIdentity, string deletionId)
        {
            Require("observe", sandboxId, originalIdentity, deletionId);
            Assert.Equal(MockDeletionLocation.Quarantined, Location);
            return QuarantineIdentity;
        }

        public void VerifyRecordedRemoval(string sandboxId, string originalIdentity, string deletionId, string quarantineIdentity)
        {
            Require("verify", sandboxId, originalIdentity, deletionId);
            Assert.Equal(QuarantineIdentity, quarantineIdentity);
            Assert.Equal(MockDeletionLocation.Absent, Location);
            Assert.Equal(0, RemainingEntries);
        }

        public SandboxRemovalBatchResult RemoveDeletionBatch(string sandboxId, string originalIdentity, string deletionId,
            string quarantineIdentity, int maximumEntries, Action applied, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Require("batch", sandboxId, originalIdentity, deletionId);
            Assert.Equal(QuarantineIdentity, quarantineIdentity);
            Assert.Equal(MockDeletionLocation.Quarantined, Location);
            Assert.Equal(128, maximumEntries);
            int removed = Math.Min(RemainingEntries, maximumEntries);
            RemainingEntries -= removed;
            Removals.Enqueue(removed);
            if (RemainingEntries == 0)
            {
                Location = MockDeletionLocation.Absent;
            }

            applied();
            return new SandboxRemovalBatchResult(removed, Location == MockDeletionLocation.Absent);
        }

        private void Require(string call, string sandboxId, string originalIdentity, string? deletionId = null)
        {
            Assert.Equal(target.SandboxId, sandboxId);
            Assert.Equal(target.RootIdentity, originalIdentity);
            if (deletionId is not null)
            {
                Assert.Equal(_deletionId, deletionId);
            }

            Calls.Enqueue(call);
            Observe?.Invoke(call);
            if (!GuardAvailable)
            {
                throw new WorkspacePathException(WorkspacePath.LinuxSandboxDeletionGuardUnavailable);
            }
        }
    }
}
