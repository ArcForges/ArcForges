// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using ArcForges.Contracts.Node.V1;
using ArcForges.Node.Core.Execution;
using ArcForges.Node.Core.Files;
using ArcForges.Node.Store;

namespace ArcForges.Node.Core.Tests;

/// <summary>Registered roots use actual native handles and actual SQLite records, without a product RPC or Git projection.</summary>
[Trait("feature", "registered-workspaces")]
public sealed class RegisteredWorkspacesTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    [Fact(Timeout = 30_000)]
    [Trait("tool", "python")]
    public void RegistrationDuplicatePagingAndRestartUseTheSamePersistedNativeIdentity()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        using var fixture = new OwnedFixture();
        var firstPath = fixture.Workspace("first");
        var secondPath = fixture.Workspace("second");
        var thirdPath = fixture.Workspace("third");
        File.WriteAllText(Path.Combine(firstPath, "marker.txt"), "test-owned file body");
        byte[] firstId;
        byte[] firstIdentity;
        var expected = new HashSet<string>(StringComparer.Ordinal);
        using (var store = fixture.Open())
        {
            var manager = new RegisteredWorkspaces(store);
            var first = manager.RegisterFromVerifiedHuman(firstPath, cancellationToken: Ct);
            firstId = first.Id.ToArray();
            Assert.Equal("first", first.Name);
            Assert.Equal(firstId, manager.RegisterFromVerifiedHuman(firstPath, "ignored duplicate name", Ct).Id);
            var second = manager.RegisterFromVerifiedHuman(secondPath, "second label", Ct);
            var third = manager.RegisterFromVerifiedHuman(thirdPath, cancellationToken: Ct);
            expected.UnionWith(new[] { first, second, third }.Select(static item => Convert.ToHexString(item.Id)));
            var page1 = manager.List(2, cancellationToken: Ct);
            Assert.Equal(2, page1.Workspaces.Count);
            Assert.NotNull(page1.NextAfter);
            var page2 = manager.List(2, page1.NextAfter, Ct);
            Assert.Single(page2.Workspaces);
            Assert.Null(page2.NextAfter);
            Assert.True(expected.SetEquals(page1.Workspaces.Concat(page2.Workspaces).Select(static item => Convert.ToHexString(item.Id))));
            Assert.Equal(3L, store.Read(r => r.Scalar("SELECT count(*) FROM workspace_root_identity WHERE released_at IS NULL;")));
            var storedIdentity = (byte[])store.Read(r => r.Scalar(
                "SELECT native_identity FROM workspace_root_identity WHERE workspace_id = $id;", ("$id", firstId)))!;
            Assert.Equal(OperatingSystem.IsLinux() ? 53 : 33, storedIdentity.Length);
            firstIdentity = storedIdentity.ToArray();
            Assert.Equal(1, storedIdentity[0]);
            Assert.Equal(0L, store.Read(r => r.Scalar("""
                SELECT instr(native_identity, $content) FROM workspace_root_identity WHERE workspace_id = $id;
                """, ("$content", System.Text.Encoding.UTF8.GetBytes("test-owned file body")), ("$id", firstId))));
        }

        // A separate real process reads the persisted SQLite row after the writer has closed.
        ReadPersistedIdentityInAnotherProcess(fixture.DatabasePath, firstId, firstIdentity);

        using (var reopened = fixture.Open())
        {
            var manager = new RegisteredWorkspaces(reopened);
            var restored = manager.Get(firstId, Ct);
            Assert.Equal(firstId, restored.Id);
            Assert.Equal("first", restored.Name);
            Assert.Equal(firstId, manager.RegisterFromVerifiedHuman(firstPath, cancellationToken: Ct).Id);
            using var use = manager.OpenForUse(firstId, Ct);
            Assert.Equal("test-owned file body", Read(use.Root.OpenRead("marker.txt")));
            Assert.True(expected.SetEquals(manager.List(500, cancellationToken: Ct).Workspaces.Select(static item => Convert.ToHexString(item.Id))));
        }

        Assert.Equal("test-owned file body", File.ReadAllText(Path.Combine(firstPath, "marker.txt")));
    }

    [Fact(Timeout = 30_000)]
    public void MovedOrReplacedRootIsRefusedAndExplicitUnregistrationDoesNotTouchEitherDirectory()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        using var fixture = new OwnedFixture();
        var original = fixture.Workspace("original");
        var moved = Path.Combine(fixture.Root, "moved");
        File.WriteAllText(Path.Combine(original, "marker.txt"), "original marker");
        using var store = fixture.Open();
        var manager = new RegisteredWorkspaces(store);
        var registered = manager.RegisterFromVerifiedHuman(original, cancellationToken: Ct);
        Directory.Move(original, moved);
        Directory.CreateDirectory(original);
        File.WriteAllText(Path.Combine(original, "marker.txt"), "replacement marker");
        Assert.Equal("workspace_root_changed", Assert.Throws<RegisteredWorkspaceException>(() => manager.Get(registered.Id, Ct)).Reason);
        Assert.Equal("workspace_root_changed", Assert.Throws<RegisteredWorkspaceException>(() => manager.OpenForUse(registered.Id, Ct)).Reason);
        Assert.Equal("workspace_root_changed", Assert.Throws<RegisteredWorkspaceException>(() => manager.List(1, cancellationToken: Ct)).Reason);
        Assert.Equal("workspace_root_changed", Assert.Throws<RegisteredWorkspaceException>(() => manager.RegisterFromVerifiedHuman(moved, cancellationToken: Ct)).Reason);
        Assert.Equal("workspace_path_conflict", Assert.Throws<RegisteredWorkspaceException>(() => manager.RegisterFromVerifiedHuman(original, cancellationToken: Ct)).Reason);
        manager.UnregisterFromVerifiedHuman(registered.Id, Ct);
        Assert.Equal("workspace_not_found", Assert.Throws<RegisteredWorkspaceException>(() => manager.Get(registered.Id, Ct)).Reason);
        Assert.Equal("original marker", File.ReadAllText(Path.Combine(moved, "marker.txt")));
        Assert.Equal("replacement marker", File.ReadAllText(Path.Combine(original, "marker.txt")));
        var replacement = manager.RegisterFromVerifiedHuman(original, cancellationToken: Ct);
        Assert.NotEqual(Convert.ToHexString(registered.Id), Convert.ToHexString(replacement.Id));
        Assert.Equal(2L, store.Read(r => r.Scalar("SELECT count(*) FROM workspace;")));
    }

    [Fact(Timeout = 30_000)]
    public void LegacyRootCannotGainAnInventedIdentityAndMustBeExplicitlyForgotten()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        using var fixture = new OwnedFixture();
        var path = fixture.Workspace("legacy");
        using var store = fixture.Open();
        var legacyId = StoreIds.NewUuid7(store.Clock);
        store.Write(t => t.Execute("""
            INSERT INTO workspace (workspace_id, kind, state, name, root_path, created_at, last_used_at, rev)
            VALUES ($id, 1, 2, 'legacy', $path, $now, $now, 0);
            """, ("$id", legacyId), ("$path", path), ("$now", t.NowMicroseconds)));
        var manager = new RegisteredWorkspaces(store);
        Assert.Equal("workspace_identity_missing", Assert.Throws<RegisteredWorkspaceException>(() => manager.Get(legacyId, Ct)).Reason);
        Assert.Equal("workspace_identity_missing", Assert.Throws<RegisteredWorkspaceException>(() => manager.OpenForUse(legacyId, Ct)).Reason);
        Assert.Equal("workspace_identity_missing", Assert.Throws<RegisteredWorkspaceException>(() => manager.List(10, cancellationToken: Ct)).Reason);
        Assert.Equal("workspace_path_conflict", Assert.Throws<RegisteredWorkspaceException>(() => manager.RegisterFromVerifiedHuman(path, cancellationToken: Ct)).Reason);
        Assert.Equal(0L, store.Read(r => r.Scalar("SELECT count(*) FROM workspace_root_identity;")));
        manager.UnregisterFromVerifiedHuman(legacyId, Ct);
        var current = manager.RegisterFromVerifiedHuman(path, cancellationToken: Ct);
        Assert.NotEqual(Convert.ToHexString(legacyId), Convert.ToHexString(current.Id));
        Assert.Equal(1L, store.Read(r => r.Scalar("SELECT count(*) FROM workspace WHERE workspace_id = $id AND removed_at IS NOT NULL;", ("$id", legacyId))));
        Assert.Equal(0L, store.Read(r => r.Scalar("SELECT count(*) FROM workspace_root_identity WHERE workspace_id = $id;", ("$id", legacyId))));
    }

    [Fact(Timeout = 30_000)]
    public void HeldUseAndLiveTaskBlockOnlyTheirOwnWorkspaceAndHistoryIsRetained()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        using var fixture = new OwnedFixture();
        var firstPath = fixture.Workspace("first");
        var secondPath = fixture.Workspace("second");
        File.WriteAllText(Path.Combine(firstPath, "marker"), "preserved");
        using var store = fixture.Open();
        using var secondStore = fixture.Open();
        var manager = new RegisteredWorkspaces(store);
        var otherManager = new RegisteredWorkspaces(secondStore);
        var first = manager.RegisterFromVerifiedHuman(firstPath, cancellationToken: Ct);
        var second = manager.RegisterFromVerifiedHuman(secondPath, cancellationToken: Ct);
        var unrelatedApproval = StoreIds.NewUuid7(store.Clock);
        var unrelatedCommand = StoreIds.NewUuid7(store.Clock);
        store.Write(t => t.Execute("""
            INSERT INTO approval (approval_id, state, operation, summary, details_json, risk, requester, command_id,
                                  request, request_digest, created_at, expires_at, rev)
            VALUES ($approval, 1, 'unrelated', 'synthetic unrelated approval', '{}', 1, x'01', $command,
                    x'01', zeroblob(32), $now, $now + 1000000, 0);
            """, ("$approval", unrelatedApproval), ("$command", unrelatedCommand), ("$now", t.NowMicroseconds)));
        using (var use = manager.OpenForUse(first.Id, Ct))
        {
            Assert.Equal("workspace_in_use", Assert.Throws<RegisteredWorkspaceException>(() => otherManager.UnregisterFromVerifiedHuman(first.Id, Ct)).Reason);
            otherManager.UnregisterFromVerifiedHuman(second.Id, Ct);
            Assert.True(use.Root.RootIdentity.IsDirectory);
        }

        var task = StoreIds.NewUuid7(store.Clock);
        store.Write(t => t.Execute("""
            INSERT INTO task (task_id, state, kind, title, command_summary, spec, spec_digest, owner, owner_origin, workspace_id,
                              pool, priority, effective_priority, side_effect, side_effect_source, command_fingerprint, command_digest, created_at, rev)
            VALUES ($task, 4, 1, 'test', 'synthetic', x'01', zeroblob(32), x'01', 1, $workspace,
                    'test', 1, 1, 1, 1, 'synthetic', zeroblob(32), $now, 0);
            """, ("$task", task), ("$workspace", first.Id), ("$now", t.NowMicroseconds)));
        Assert.Equal("workspace_in_use", Assert.Throws<RegisteredWorkspaceException>(() => manager.UnregisterFromVerifiedHuman(first.Id, Ct)).Reason);
        store.Write(t => t.Execute("UPDATE task SET state = 7 WHERE task_id = $task;", ("$task", task)));
        manager.UnregisterFromVerifiedHuman(first.Id, Ct);
        Assert.Equal(1L, store.Read(r => r.Scalar("SELECT count(*) FROM task WHERE task_id = $task AND workspace_id = $workspace;",
            ("$task", task), ("$workspace", first.Id))));
        Assert.Equal(1L, store.Read(r => r.Scalar("SELECT count(*) FROM workspace_root_identity WHERE workspace_id = $id AND released_at IS NOT NULL;",
            ("$id", first.Id))));
        Assert.Equal("preserved", File.ReadAllText(Path.Combine(firstPath, "marker")));
    }

    [Theory(Timeout = 30_000)]
    [InlineData(TaskState.Queued)]
    [InlineData(TaskState.WaitingDependency)]
    [InlineData(TaskState.Placing)]
    [InlineData(TaskState.Running)]
    [InlineData(TaskState.Paused)]
    [InlineData(TaskState.RetryWait)]
    public void EveryNonterminalTaskBlocksOnlyItsOwnRegisteredWorkspace(TaskState state)
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        using var fixture = new OwnedFixture();
        using var store = fixture.Open();
        var manager = new RegisteredWorkspaces(store);
        var first = manager.RegisterFromVerifiedHuman(fixture.Workspace("first"), cancellationToken: Ct);
        var other = manager.RegisterFromVerifiedHuman(fixture.Workspace("other"), cancellationToken: Ct);
        InsertTask(store, first.Id, (int)state);
        Assert.Equal("workspace_in_use", Assert.Throws<RegisteredWorkspaceException>(() => manager.UnregisterFromVerifiedHuman(first.Id, Ct)).Reason);
        manager.UnregisterFromVerifiedHuman(other.Id, Ct);
        Assert.Equal(first.Id, manager.Get(first.Id, Ct).Id);
    }

    [Theory(Timeout = 30_000)]
    [InlineData(TaskState.Succeeded)]
    [InlineData(TaskState.Failed)]
    [InlineData(TaskState.Cancelled)]
    [InlineData(TaskState.Lost)]
    public void TerminalTaskAllowsUnregistrationButItsHistoryIsRetained(TaskState state)
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        using var fixture = new OwnedFixture();
        using var store = fixture.Open();
        var manager = new RegisteredWorkspaces(store);
        var registered = manager.RegisterFromVerifiedHuman(fixture.Workspace("root"), cancellationToken: Ct);
        var task = InsertTask(store, registered.Id, (int)state);
        manager.UnregisterFromVerifiedHuman(registered.Id, Ct);
        Assert.Equal(1L, store.Read(r => r.Scalar("SELECT count(*) FROM task WHERE task_id=$task AND workspace_id=$workspace;",
            ("$task", task), ("$workspace", registered.Id))));
    }

    [Fact(Timeout = 30_000)]
    public void LegacyTrailingSeparatorCannotCreateADuplicateRegistration()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        using var fixture = new OwnedFixture();
        var root = fixture.Workspace("legacy");
        using var store = fixture.Open();
        var legacy = InsertLegacy(store, root + Path.DirectorySeparatorChar);
        var manager = new RegisteredWorkspaces(store);
        Assert.Equal("workspace_path_conflict", Assert.Throws<RegisteredWorkspaceException>(
            () => manager.RegisterFromVerifiedHuman(root, cancellationToken: Ct)).Reason);
        Assert.Equal(1L, store.Read(r => r.Scalar("SELECT count(*) FROM workspace WHERE removed_at IS NULL;")));
        Assert.Equal(0L, store.Read(r => r.Scalar("SELECT count(*) FROM workspace_root_identity;")));
        Assert.Equal("workspace_identity_missing", Assert.Throws<RegisteredWorkspaceException>(() => manager.List(10, cancellationToken: Ct)).Reason);
        manager.UnregisterFromVerifiedHuman(legacy, Ct);
        var current = manager.RegisterFromVerifiedHuman(root, cancellationToken: Ct);
        Assert.NotEqual(Convert.ToHexString(legacy), Convert.ToHexString(current.Id));
    }

    [Fact(Timeout = 30_000)]
    public void LegacyCaseComparisonFollowsTheActualFilesystem()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        using var fixture = new OwnedFixture();
        var lower = fixture.Workspace("legacycase");
        var upper = Path.Combine(fixture.Root, "LEGACYCASE");
        var equivalent = Directory.Exists(upper);
        if (!equivalent)
        {
            Directory.CreateDirectory(upper);
        }

        using var store = fixture.Open();
        InsertLegacy(store, lower + Path.DirectorySeparatorChar);
        var manager = new RegisteredWorkspaces(store);
        if (equivalent)
        {
            Assert.Equal("workspace_path_conflict", Assert.Throws<RegisteredWorkspaceException>(
                () => manager.RegisterFromVerifiedHuman(upper, cancellationToken: Ct)).Reason);
            Assert.Equal(1L, store.Read(r => r.Scalar("SELECT count(*) FROM workspace WHERE removed_at IS NULL;")));
        }
        else
        {
            var distinct = manager.RegisterFromVerifiedHuman(upper, cancellationToken: Ct);
            Assert.Equal(distinct.Id, manager.Get(distinct.Id, Ct).Id);
            Assert.Equal(2L, store.Read(r => r.Scalar("SELECT count(*) FROM workspace WHERE removed_at IS NULL;")));
        }
    }

    [Fact(Timeout = 30_000)]
    [Trait("env", "linux-real")]
    public void LegacySymlinkAliasIsRefusedWhenItsIdentityCannotBeSafelyProven()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        Assert.SkipUnless(OperatingSystem.IsLinux(), "Linux native symlink alias");
        using var fixture = new OwnedFixture();
        var root = fixture.Workspace("root");
        var alias = Path.Combine(fixture.Root, "legacy-link");
        Directory.CreateSymbolicLink(alias, root);
        using var store = fixture.Open();
        InsertLegacy(store, alias);
        var manager = new RegisteredWorkspaces(store);
        Assert.Equal("legacy_root_unverifiable", Assert.Throws<RegisteredWorkspaceException>(
            () => manager.RegisterFromVerifiedHuman(root, cancellationToken: Ct)).Reason);
        Assert.Equal(1L, store.Read(r => r.Scalar("SELECT count(*) FROM workspace WHERE removed_at IS NULL;")));
        Assert.Equal(0L, store.Read(r => r.Scalar("SELECT count(*) FROM workspace_root_identity;")));
    }

    [Fact(Timeout = 30_000)]
    public void UnavailableLegacyRootFailsClosedInsteadOfGuessingDistinctIdentity()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        using var fixture = new OwnedFixture();
        var root = fixture.Workspace("root");
        using var store = fixture.Open();
        InsertLegacy(store, Path.Combine(fixture.Root, "missing-legacy"));
        var manager = new RegisteredWorkspaces(store);
        Assert.Equal("legacy_root_unverifiable", Assert.Throws<RegisteredWorkspaceException>(
            () => manager.RegisterFromVerifiedHuman(root, cancellationToken: Ct)).Reason);
        Assert.Equal(1L, store.Read(r => r.Scalar("SELECT count(*) FROM workspace WHERE removed_at IS NULL;")));
        Assert.Equal(0L, store.Read(r => r.Scalar("SELECT count(*) FROM workspace_root_identity;")));
    }

    [Fact(Timeout = 30_000)]
    [Trait("env", "linux-real")]
    public void AliasedStorePathsStillShareTheSameUseLease()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        Assert.SkipUnless(OperatingSystem.IsLinux(), "Linux native data-root alias");
        using var fixture = new OwnedFixture();
        var path = fixture.Workspace("workspace");
        using var store = fixture.Open();
        var alias = Path.Combine(fixture.Root, "data-alias");
        Directory.CreateSymbolicLink(alias, Path.Combine(fixture.Root, "node-data"));
        using var aliasStore = NodeStore.Open(new NodeStoreOptions { DataRoot = alias, BootIdentity = "synthetic-test-boot" });
        var manager = new RegisteredWorkspaces(store);
        var aliasManager = new RegisteredWorkspaces(aliasStore);
        var registered = manager.RegisterFromVerifiedHuman(path, cancellationToken: Ct);
        using (manager.OpenForUse(registered.Id, Ct))
        {
            Assert.Equal("workspace_in_use", Assert.Throws<RegisteredWorkspaceException>(
                () => aliasManager.UnregisterFromVerifiedHuman(registered.Id, Ct)).Reason);
        }

        aliasManager.UnregisterFromVerifiedHuman(registered.Id, Ct);
        Assert.True(Directory.Exists(path));
    }

    [Fact(Timeout = 30_000)]
    public async Task ConcurrentDuplicateRegistrationsUseOneRealSqliteRecord()
    {
        var cancellation = TestContext.Current.CancellationToken;
        cancellation.ThrowIfCancellationRequested();
        using var fixture = new OwnedFixture();
        var path = fixture.Workspace("concurrent");
        using var firstStore = fixture.Open();
        using var secondStore = fixture.Open();
        var first = new RegisteredWorkspaces(firstStore);
        var second = new RegisteredWorkspaces(secondStore);
        var calls = Enumerable.Range(0, 8).Select(index => Task.Run(
            () => (index % 2 == 0 ? first : second).RegisterFromVerifiedHuman(path, cancellationToken: cancellation), cancellation)).ToArray();
        var results = await Task.WhenAll(calls);
        Assert.Single(results.Select(static item => Convert.ToHexString(item.Id)).Distinct(StringComparer.Ordinal));
        Assert.Equal(1L, firstStore.Read(r => r.Scalar("SELECT count(*) FROM workspace WHERE removed_at IS NULL;")));
        Assert.Equal(1L, firstStore.Read(r => r.Scalar("SELECT count(*) FROM workspace_root_identity WHERE released_at IS NULL;")));
    }

    [Fact(Timeout = 30_000)]
    [Trait("env", "linux-real")]
    public void ReplacementAfterInitialOpenCannotBeRegisteredUnderTheCheckedIdentity()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        Assert.SkipUnless(OperatingSystem.IsLinux(), "Linux native directory replacement race");
        using var fixture = new OwnedFixture();
        var path = fixture.Workspace("root");
        var moved = Path.Combine(fixture.Root, "moved");
        File.WriteAllText(Path.Combine(path, "marker"), "old object");
        using var store = fixture.Open();
        var manager = new RegisteredWorkspaces(store);
        var error = Assert.Throws<RegisteredWorkspaceException>(() => manager.RegisterFromVerifiedHuman(path, null, () =>
        {
            Directory.Move(path, moved);
            Directory.CreateDirectory(path);
            File.WriteAllText(Path.Combine(path, "marker"), "new object");
        }, Ct));
        Assert.Equal("workspace_root_changed", error.Reason);
        Assert.Equal(0L, store.Read(r => r.Scalar("SELECT count(*) FROM workspace;")));
        Assert.Equal(0L, store.Read(r => r.Scalar("SELECT count(*) FROM workspace_root_identity;")));
        Assert.Equal("old object", File.ReadAllText(Path.Combine(moved, "marker")));
        Assert.Equal("new object", File.ReadAllText(Path.Combine(path, "marker")));
    }

    [Fact(Timeout = 30_000)]
    public void VerifiedUseUpdatesPersistedLastUsedWithoutClockRollback()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        using var fixture = new OwnedFixture();
        var path = fixture.Workspace("root");
        var initial = new DateTimeOffset(2026, 11, 9, 12, 0, 0, TimeSpan.Zero);
        var clock = new AdjustableClock(initial);
        byte[] id;
        using (var store = fixture.Open(clock))
        {
            var manager = new RegisteredWorkspaces(store);
            var created = manager.RegisterFromVerifiedHuman(path, cancellationToken: Ct);
            id = created.Id;
            clock.Set(initial.AddMinutes(1));
            using (manager.OpenForUse(id, Ct))
            {
            }

            var used = manager.Get(id, Ct);
            Assert.Equal(created.LastUsedAt + 60_000_000, used.LastUsedAt);
            clock.Set(initial);
            using (manager.OpenForUse(id, Ct))
            {
            }

            Assert.Equal(used.LastUsedAt, manager.Get(id, Ct).LastUsedAt);
        }

        using var reopened = fixture.Open(clock);
        Assert.Equal(StoreTime.ToMicroseconds(initial.AddMinutes(1)), new RegisteredWorkspaces(reopened).Get(id, Ct).LastUsedAt);
    }

    [Fact(Timeout = 30_000)]
    public void CancellationBeforeCommitOrOperationLeavesRegistrationAndFilesUntouched()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        using var fixture = new OwnedFixture();
        var path = fixture.Workspace("root");
        File.WriteAllText(Path.Combine(path, "marker"), "untouched");
        using var store = fixture.Open();
        var manager = new RegisteredWorkspaces(store);
        using (var duringRegistration = new CancellationTokenSource())
        {
            Assert.ThrowsAny<OperationCanceledException>(() => manager.RegisterFromVerifiedHuman(
                path, null, duringRegistration.Cancel, duringRegistration.Token));
        }

        Assert.Equal(0L, store.Read(r => r.Scalar("SELECT count(*) FROM workspace;")));
        var registered = manager.RegisterFromVerifiedHuman(path, cancellationToken: Ct);
        using var canceled = new CancellationTokenSource();
        canceled.Cancel();
        Assert.ThrowsAny<OperationCanceledException>(() => manager.Get(registered.Id, canceled.Token));
        Assert.ThrowsAny<OperationCanceledException>(() => manager.List(1, cancellationToken: canceled.Token));
        Assert.ThrowsAny<OperationCanceledException>(() => manager.OpenForUse(registered.Id, canceled.Token));
        Assert.ThrowsAny<OperationCanceledException>(() => manager.UnregisterFromVerifiedHuman(registered.Id, canceled.Token));
        Assert.Equal(registered.Id, manager.Get(registered.Id, Ct).Id);
        Assert.Equal("untouched", File.ReadAllText(Path.Combine(path, "marker")));
    }

    [Fact(Timeout = 30_000)]
    public void InvalidNamesAndCorruptStoredIdentityFailClosed()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        using var fixture = new OwnedFixture();
        var path = fixture.Workspace("root");
        using var store = fixture.Open();
        var manager = new RegisteredWorkspaces(store);
        Assert.Equal("workspace_name_invalid", Assert.Throws<RegisteredWorkspaceException>(() => manager.RegisterFromVerifiedHuman(path, "", Ct)).Reason);
        Assert.Equal("workspace_name_invalid", Assert.Throws<RegisteredWorkspaceException>(() => manager.RegisterFromVerifiedHuman(path, new string('x', 101), Ct)).Reason);
        Assert.Equal("workspace_name_invalid", Assert.Throws<RegisteredWorkspaceException>(() => manager.RegisterFromVerifiedHuman(path, new string('\ud800', 1), Ct)).Reason);
        Assert.Equal(0L, store.Read(r => r.Scalar("SELECT count(*) FROM workspace;")));
        var registered = manager.RegisterFromVerifiedHuman(path, string.Concat(Enumerable.Repeat("😀", 100)), Ct);
        store.Write(t => t.Execute("UPDATE workspace SET state = 1 WHERE workspace_id = $id;", ("$id", registered.Id)));
        Assert.Equal("workspace_state_invalid", Assert.Throws<RegisteredWorkspaceException>(() => manager.Get(registered.Id, Ct)).Reason);
        store.Write(t => t.Execute("UPDATE workspace SET state = 2 WHERE workspace_id = $id;", ("$id", registered.Id)));
        store.Write(t => t.Execute("""
            UPDATE workspace_root_identity SET native_identity = zeroblob(length(native_identity))
            WHERE workspace_id = $id;
            """, ("$id", registered.Id)));
        Assert.Equal("workspace_identity_invalid", Assert.Throws<RegisteredWorkspaceException>(() => manager.Get(registered.Id, Ct)).Reason);
        manager.UnregisterFromVerifiedHuman(registered.Id, Ct);
        Assert.True(Directory.Exists(path));
    }

    [Fact(Timeout = 30_000)]
    public void WorkspaceSelectionMatchesNativeFilesystemRootAndLongestBoundedPrefix()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        using var fixture = new OwnedFixture();
        var parent = fixture.Workspace("parent");
        var child = Directory.CreateDirectory(Path.Combine(parent, "child")).FullName;
        var sibling = fixture.Workspace("parent-other");
        var root = Path.GetPathRoot(parent)!;
        using var store = fixture.Open();
        var rootId = InsertLegacy(store, root);
        Assert.Equal(rootId, store.Read(reader => ExecutionSupervisor.WorkspaceOf(reader, root)));
        Assert.Equal(rootId, store.Read(reader => ExecutionSupervisor.WorkspaceOf(reader, parent)));
        var parentId = InsertLegacy(store, parent);
        Assert.Equal(parentId, store.Read(reader => ExecutionSupervisor.WorkspaceOf(reader, child)));
        Assert.Equal(rootId, store.Read(reader => ExecutionSupervisor.WorkspaceOf(reader, sibling)));
        var childId = InsertLegacy(store, child);
        Assert.Equal(childId, store.Read(reader => ExecutionSupervisor.WorkspaceOf(reader, child)));
    }

    [Fact(Timeout = 30_000)]
    public void VerifiedDuplicateIgnoresAnUnrelatedUnverifiableLegacyRootButNewRootDoesNot()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        using var fixture = new OwnedFixture();
        using var store = fixture.Open();
        var manager = new RegisteredWorkspaces(store);
        var existingPath = fixture.Workspace("known");
        var existing = manager.RegisterFromVerifiedHuman(existingPath, cancellationToken: Ct);
        InsertLegacy(store, Path.Combine(fixture.Root, "missing-legacy"));
        Assert.Equal(existing.Id, manager.RegisterFromVerifiedHuman(existingPath, cancellationToken: Ct).Id);
        var newPath = fixture.Workspace("new");
        Assert.Equal("legacy_root_unverifiable", Assert.Throws<RegisteredWorkspaceException>(
            () => manager.RegisterFromVerifiedHuman(newPath, cancellationToken: Ct)).Reason);
        Assert.Equal(1L, store.Read(reader => reader.Scalar("SELECT count(*) FROM workspace_root_identity;")));
    }

    [Fact(Timeout = 30_000)]
    public async Task LegacyNativeScanDoesNotHoldWriterAndChangedSnapshotRefusesInsertion()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        using var fixture = new OwnedFixture();
        using var store = fixture.Open();
        var legacyId = InsertLegacy(store, fixture.Workspace("old"));
        var manager = new RegisteredWorkspaces(store);
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        using var release = new ManualResetEventSlim();
        manager.AfterLegacyOpenForTests = () =>
        {
            entered.TrySetResult();
            if (!release.Wait(TimeSpan.FromSeconds(4)))
            {
                throw new TimeoutException("test did not release native legacy inspection");
            }
        };
        var path = fixture.Workspace("new");
        var pending = Task.Run(() => Record.Exception(() => manager.RegisterFromVerifiedHuman(path, cancellationToken: Ct)), Ct);
        try
        {
            await entered.Task.WaitAsync(TimeSpan.FromSeconds(3), Ct);
            // This is an actual unrelated SQLite write during a real, successfully opened legacy root.
            await Task.Run(() => store.Write(transaction => transaction.Execute(
                "UPDATE workspace SET rev = rev + 1 WHERE workspace_id = $id;", ("$id", legacyId))), Ct)
                .WaitAsync(TimeSpan.FromSeconds(3), Ct);
        }
        finally
        {
            release.Set();
        }

        var error = Assert.IsType<RegisteredWorkspaceException>(await pending.WaitAsync(TimeSpan.FromSeconds(10), Ct));
        Assert.Equal("legacy_snapshot_changed", error.Reason);
        Assert.Equal(0L, store.Read(reader => reader.Scalar("SELECT count(*) FROM workspace_root_identity;")));
        manager.AfterLegacyOpenForTests = null;
        Assert.NotNull(manager.RegisterFromVerifiedHuman(path, cancellationToken: Ct));
    }

    [Fact(Timeout = 30_000)]
    public void InvalidUtf8LegacyPathCannotBeMistakenForAnExistingReplacementCharacterPath()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        using var fixture = new OwnedFixture();
        using var store = fixture.Open();
        _ = fixture.Workspace("legacy-�");
        var invalid = System.Text.Encoding.UTF8.GetBytes(Path.Combine(fixture.Root, "legacy-")).Concat(new byte[] { 0xff }).ToArray();
        var id = StoreIds.NewUuid7(store.Clock);
        store.Write(transaction => transaction.Execute("""
            INSERT INTO workspace (workspace_id, kind, state, name, root_path, created_at, last_used_at, rev)
            VALUES ($id, 1, 2, 'legacy', CAST($path AS TEXT), $now, $now, 0);
            """, ("$id", id), ("$path", invalid), ("$now", transaction.NowMicroseconds)));
        var manager = new RegisteredWorkspaces(store);
        var error = Assert.Throws<RegisteredWorkspaceException>(() => manager.RegisterFromVerifiedHuman(
            fixture.Workspace("new"), cancellationToken: Ct));
        Assert.Equal("legacy_root_unverifiable", error.Reason);
        Assert.Equal(0L, store.Read(reader => reader.Scalar("SELECT count(*) FROM workspace_root_identity;")));
    }

    [Fact(Timeout = 30_000)]
    public void CancellationDuringRealLegacyInspectionLeavesNoNewIdentity()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        using var fixture = new OwnedFixture();
        using var store = fixture.Open();
        InsertLegacy(store, fixture.Workspace("old"));
        var manager = new RegisteredWorkspaces(store);
        using var cancellation = CancellationTokenSource.CreateLinkedTokenSource(Ct);
        var opened = false;
        manager.AfterLegacyOpenForTests = () =>
        {
            opened = true;
            cancellation.Cancel();
        };
        Assert.ThrowsAny<OperationCanceledException>(() => manager.RegisterFromVerifiedHuman(
            fixture.Workspace("new"), cancellationToken: cancellation.Token));
        Assert.True(opened);
        Assert.Equal(0L, store.Read(reader => reader.Scalar("SELECT count(*) FROM workspace_root_identity;")));
    }

    [Fact(Timeout = 30_000)]
    public void LegacyScanLimitAndCancellationFailClosed()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        using var fixture = new OwnedFixture();
        using var store = fixture.Open();
        var path = fixture.Workspace("new");
        store.Write(transaction =>
        {
            for (var index = 0; index <= RegisteredWorkspaces.MaxLegacyRoots; index++)
            {
                transaction.Execute("""
                    INSERT INTO workspace (workspace_id, kind, state, name, root_path, created_at, last_used_at, rev)
                    VALUES ($id, 1, 2, 'legacy', $path, $now, $now, 0);
                    """, ("$id", StoreIds.NewUuid7(transaction.Clock)), ("$path", Path.Combine(fixture.Root, "old-" + index)),
                    ("$now", transaction.NowMicroseconds));
            }
        });
        var manager = new RegisteredWorkspaces(store);
        Assert.Equal("legacy_scan_limit", Assert.Throws<RegisteredWorkspaceException>(
            () => manager.RegisterFromVerifiedHuman(path, cancellationToken: Ct)).Reason);
        using var cancelled = new CancellationTokenSource();
        cancelled.Cancel();
        Assert.ThrowsAny<OperationCanceledException>(() => manager.RegisterFromVerifiedHuman(path, cancellationToken: cancelled.Token));
        Assert.Equal(0L, store.Read(reader => reader.Scalar("SELECT count(*) FROM workspace_root_identity;")));
    }

    private static byte[] InsertLegacy(NodeStore store, string path)
    {
        var id = StoreIds.NewUuid7(store.Clock);
        store.Write(transaction => transaction.Execute("""
            INSERT INTO workspace (workspace_id, kind, state, name, root_path, created_at, last_used_at, rev)
            VALUES ($id, 1, 2, 'legacy', $path, $now, $now, 0);
            """, ("$id", id), ("$path", path), ("$now", transaction.NowMicroseconds)));
        return id;
    }

    private static byte[] InsertTask(NodeStore store, byte[] workspace, int state)
    {
        var id = StoreIds.NewUuid7(store.Clock);
        store.Write(transaction => transaction.Execute("""
            INSERT INTO task (task_id, state, kind, title, command_summary, spec, spec_digest, owner, owner_origin, workspace_id,
                              pool, priority, effective_priority, side_effect, side_effect_source, command_fingerprint, command_digest, created_at, rev)
            VALUES ($task, $state, 1, 'test', 'synthetic', x'01', zeroblob(32), x'01', 1, $workspace,
                    'test', 1, 1, 1, 1, 'synthetic', zeroblob(32), $now, 0);
            """, ("$task", id), ("$state", state), ("$workspace", workspace), ("$now", transaction.NowMicroseconds)));
        return id;
    }

    private static void ReadPersistedIdentityInAnotherProcess(string databasePath, byte[] id, byte[] identity)
    {
        const string script = """
            import sqlite3, sys
            connection = sqlite3.connect(sys.argv[1])
            connection.execute("PRAGMA query_only=ON")
            row = connection.execute("SELECT hex(w.workspace_id), hex(i.native_identity) FROM workspace w JOIN workspace_root_identity i ON i.workspace_id=w.workspace_id WHERE w.workspace_id=? AND w.removed_at IS NULL AND i.released_at IS NULL", (bytes.fromhex(sys.argv[2]),)).fetchone()
            assert row is not None
            print(row[0])
            print(row[1])
            """;
        var info = new ProcessStartInfo(OperatingSystem.IsWindows() ? "python" : "python3")
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
            UseShellExecute = false,
        };
        info.ArgumentList.Add("-c");
        info.ArgumentList.Add(script);
        info.ArgumentList.Add(databasePath);
        info.ArgumentList.Add(Convert.ToHexString(id));
        using var process = Process.Start(info) ?? throw new InvalidOperationException("Could not start the independent SQLite reader.");
        try
        {
            Assert.True(process.WaitForExit(5000), "independent SQLite reader timed out");
            Assert.True(process.ExitCode == 0, process.StandardError.ReadToEnd());
            var lines = process.StandardOutput.ReadToEnd().Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            Assert.Equal([Convert.ToHexString(id), Convert.ToHexString(identity)], lines);
        }
        finally
        {
            if (!process.HasExited)
            {
                process.Kill(entireProcessTree: true);
                process.WaitForExit(3000);
            }
        }
    }

    private static string Read(Microsoft.Win32.SafeHandles.SafeFileHandle handle)
    {
        var bytes = new byte[128];
        var count = RandomAccess.Read(handle, bytes, 0);
        return System.Text.Encoding.UTF8.GetString(bytes.AsSpan(0, count));
    }

    private sealed class AdjustableClock(DateTimeOffset initial) : TimeProvider
    {
        private DateTimeOffset _current = initial;
        public override DateTimeOffset GetUtcNow() => _current;
        internal void Set(DateTimeOffset value) => _current = value;
    }

    private sealed class OwnedFixture : IDisposable
    {
        private readonly DirectoryInfo _root = Directory.CreateTempSubdirectory("arcforges-registration-");
        internal string Root => _root.FullName;
        internal string DatabasePath => Path.Combine(Root, "node-data", "store", "node.db");
        internal string Workspace(string name) => Directory.CreateDirectory(Path.Combine(Root, name)).FullName;
        internal NodeStore Open(TimeProvider? clock = null) => NodeStore.Open(new NodeStoreOptions
        {
            DataRoot = Path.Combine(Root, "node-data"),
            BootIdentity = "synthetic-test-boot",
            Clock = clock ?? TimeProvider.System,
        });
        public void Dispose() => _root.Delete(recursive: true);
    }
}
