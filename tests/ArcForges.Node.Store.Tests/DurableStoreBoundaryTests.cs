// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using System.Security.Cryptography;
using ArcForges.Node.Store.Migrations;
using Microsoft.Data.Sqlite;

namespace ArcForges.Node.Store.Tests;

public sealed partial class DurableCommandStoreTests
{
    [Fact]
    public void Schema15ExpandsWithoutLosingItsSuppliedUnknownIntentOrSamples()
    {
        using var root = new TemporaryDataRoot();
        var clock = new ManualClock();
        var fifteen = new MigrationPlan(StoreMigrations.Released.Steps.Take(15));
        byte[] command = RandomNumberGenerator.GetBytes(16), workspace = RandomNumberGenerator.GetBytes(16);
        // A supplied historical intent fixture, not evidence of a native file operation or process identity.
        byte[] historicalIdentity = [1, .. new byte[32]];
        using (var old = root.Open(clock, fifteen))
        {
            old.Write(tx =>
            {
                tx.Execute("INSERT INTO resource_sample VALUES(1,zeroblob(16),123,1000,1,2,3,4,5,6,7);");
                tx.Execute("INSERT INTO workspace(workspace_id,kind,state,name,root_path,created_at,last_used_at,rev) VALUES($w,1,2,'supplied historical fixture','/fixture',0,0,0);", ("$w", workspace));
                tx.Execute("INSERT INTO command_dedup(command_id,method,payload_digest,origin,created_at,expires_at) VALUES($c,'arcforges.node.v1.FileService/WriteFile',zeroblob(32),4,0,1);", ("$c", command));
                tx.Execute("""
                    INSERT INTO file_operation_journal(command_id,kind,phase,request_sha256,caller,correlation_id,workspace_id,relative_path,
                      identity_platform,root_identity,parent_identity,expected_absent,intended_size,intended_sha256,intended_stage_identity,
                      created_at,updated_at,held,acknowledged)
                    VALUES($c,1,3,zeroblob(32),x'01',$c,$w,'fixture',1,$identity,$identity,1,0,zeroblob(32),$identity,0,0,1,0);
                    """, ("$c", command), ("$w", workspace), ("$identity", historicalIdentity));
            }, CommitDurability.Full);
        }
        using (var current = root.Open(clock))
        {
            Assert.Equal(15, current.Opening.MigratedFrom);
            Assert.Equal(17, current.Metadata.SchemaVersion);
            Assert.Equal(17, current.Metadata.MinReaderVersion);
            Assert.NotNull(current.Opening.BackupPath);
            Assert.True(File.Exists(current.Opening.BackupPath));
            Assert.Equal(1L, current.Read(r => r.Scalar("SELECT count(*) FROM file_operation_journal WHERE phase=3 AND held=1 AND command_id=$c;", ("$c", command))));
            Assert.Equal(3L, current.Read(r => r.Scalar("SELECT mem_bytes FROM resource_sample WHERE at=123;")));
            Assert.Equal(0L, current.Read(r => r.Scalar("SELECT count(*) FROM v2_resource_sample;")));
            Assert.Equal(1L, current.Read(r => r.Scalar("SELECT unresolved_count FROM migration_checkpoint;")));
            Assert.Equal(0, current.Commands.PurgeExpired());
        }
        Assert.Throws<StoreIncompatibleException>(() => root.Open(clock, fifteen));
    }

    [Fact]
    public async Task ConcurrentCompareExchangeAdmitsOnlyOneSandboxRevision()
    {
        using var root = new TemporaryDataRoot();
        using var store = root.Open(new ManualClock());
        using var commands = Commands(store, root.Path);
        store.Write(tx => tx.Execute("""
            INSERT INTO sandbox(sandbox_id,owner_id,display_name,normalized_name,revision,state,root_relative,root_identity,root_generation,created_utc,updated_utc)
            VALUES('fixture-sandbox','fixture-owner','fixture','fixture',1,2,'owned/fixture','supplied-root-metadata',1,'2026-10-15','2026-10-15');
            """));
        var outcomes = await Task.WhenAll(Enumerable.Range(0, 6).Select(_ => Task.Run(() => commands.Admit(
            Intent(commands) with { AggregateKind = "sandbox", AggregateId = "fixture-sandbox", ExpectedSandboxRevision = 1 },
            tx => Assert.Equal(1, tx.Execute("UPDATE sandbox SET revision=2 WHERE sandbox_id='fixture-sandbox' AND revision=1;"))))));
        Assert.Single(outcomes, result => result.Decision == DurableDecision.Execute);
        Assert.Equal(5, outcomes.Count(result => result.Decision == DurableDecision.RevisionConflict));
        Assert.Equal(1L, store.Read(r => r.Scalar("SELECT count(*) FROM command_receipt;")));
        Assert.Equal(2L, store.Read(r => r.Scalar("SELECT revision FROM sandbox;")));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void TransactionReturnFaultNeverBecomesASecondAdmission(bool afterCommit)
    {
        using var root = new TemporaryDataRoot();
        var clock = new ManualClock();
        DurableIntent intent;
        int syntheticEffects = 0;
        using (var store = root.Open(clock))
        using (var commands = Commands(store, root.Path))
        {
            intent = Intent(commands);
            Assert.Throws<FixtureBoundaryException>(() =>
            {
                var admitted = commands.Admit(intent, tx =>
                {
                    if (afterCommit) tx.AfterCommitForTests = () => throw new FixtureBoundaryException();
                    else throw new FixtureBoundaryException();
                });
                if (admitted.Decision == DurableDecision.Execute) syntheticEffects++;
            });
            Assert.True(commands.MaintenanceRequired);
        }
        using (var store = root.Open(clock))
        using (var commands = Commands(store, root.Path))
        {
            Assert.Equal(afterCommit ? 1L : 0L, store.Read(r => r.Scalar("SELECT count(*) FROM command_receipt;")));
            var replay = commands.Admit(intent);
            if (replay.Decision == DurableDecision.Execute) syntheticEffects++;
            Assert.Equal(afterCommit ? DurableDecision.InProgress : DurableDecision.Maintenance, replay.Decision);
            Assert.Equal(0, syntheticEffects);
        }
    }

    // Test-local phase variables never reach a product executable. Both child invocations
    // run this exact method in the existing built test project, using real DB and key files.
    [Fact]
    public async Task TwoRealProcessesPreserveOriginalEpochAndCompactedReplay()
    {
        const string childRootVariable = "ARCFORGES_DATA01_FIXTURE_ROOT";
        const string childPhaseVariable = "ARCFORGES_DATA01_FIXTURE_PHASE";
        string? suppliedRoot = Environment.GetEnvironmentVariable(childRootVariable);
        if (suppliedRoot is not null)
        {
            Assert.StartsWith(Path.Combine(Path.GetTempPath(), "arcforges-store-tests-"), suppliedRoot, StringComparison.Ordinal);
            string phase = Environment.GetEnvironmentVariable(childPhaseVariable)!;
            Assert.True(phase is "settle" or "replay");
            byte[] saved = File.ReadAllBytes(Path.Combine(suppliedRoot, "data01-original-command.fixture"));
            Assert.Equal(32, saved.Length);
            var childClock = new ManualClock();
            if (phase == "replay") childClock.Advance(TimeSpan.FromHours(25));
            using var childStore = NodeStore.Open(new NodeStoreOptions { DataRoot = suppliedRoot, BootIdentity = "data01-child", Clock = childClock });
            using var commands = Commands(childStore, suppliedRoot);
            var original = Intent(commands, saved[..16]) with { OwnerEpoch = saved[16..] };
            if (phase == "replay") Assert.Equal(1, commands.CompactKnownResponses());
            var result = commands.Admit(original);
            if (result.Decision == DurableDecision.Execute)
                File.AppendAllText(Path.Combine(suppliedRoot, "data01-synthetic-effect.fixture"), "synthetic effect\n");
            Assert.Equal(phase == "settle" ? DurableDecision.Execute : DurableDecision.Compacted, result.Decision);
            if (phase == "settle") commands.SetResult(original.CommandId, "SUCCEEDED", 2, "{\"synthetic_observation\":1}");
            Assert.Single(File.ReadAllLines(Path.Combine(suppliedRoot, "data01-synthetic-effect.fixture")));
            return;
        }
        using var root = new TemporaryDataRoot();
        using (var store = root.Open(new ManualClock()))
        using (var commands = Commands(store, root.Path))
            File.WriteAllBytes(Path.Combine(root.Path, "data01-original-command.fixture"), [.. RandomNumberGenerator.GetBytes(16), .. commands.OwnerEpoch.Span]);
        foreach (string phase in new[] { "settle", "replay" })
        {
            var start = new ProcessStartInfo("dotnet")
            {
                WorkingDirectory = Repository.Root,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true,
            };
            foreach (string argument in new[] { "test", "--project", "tests/ArcForges.Node.Store.Tests/ArcForges.Node.Store.Tests.csproj",
                "-c", "Release", "--no-build", "--filter-method", "ArcForges.Node.Store.Tests.DurableCommandStoreTests.TwoRealProcessesPreserveOriginalEpochAndCompactedReplay" })
                start.ArgumentList.Add(argument);
            start.Environment[childRootVariable] = root.Path;
            start.Environment[childPhaseVariable] = phase;
            using var child = Process.Start(start)!;
            var output = child.StandardOutput.ReadToEndAsync(TestContext.Current.CancellationToken);
            var errors = child.StandardError.ReadToEndAsync(TestContext.Current.CancellationToken);
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(TestContext.Current.CancellationToken);
            timeout.CancelAfter(TimeSpan.FromMinutes(1));
            try { await child.WaitForExitAsync(timeout.Token); }
            finally
            {
                if (!child.HasExited) { child.Kill(entireProcessTree: true); await child.WaitForExitAsync(CancellationToken.None); }
            }
            string printed = await output;
            Assert.True(child.ExitCode == 0, phase + ": " + await errors + printed);
            TestContext.Current.TestOutputHelper?.WriteLine("Real SQLite child phase {0}: exit0; process exited={1}", phase, child.HasExited);
        }
        Assert.Single(File.ReadAllLines(Path.Combine(root.Path, "data01-synthetic-effect.fixture")));
        using (var store = root.Open(new ManualClock()))
        using (var commands = Commands(store, root.Path))
        {
            byte[] original = File.ReadAllBytes(Path.Combine(root.Path, "data01-original-command.fixture"));
            Assert.Equal(original[16..], commands.OwnerEpoch.ToArray());
            Assert.True(commands.Inspect(original.AsSpan(0, 16))!.Compacted);
        }
    }

    private sealed class FixtureBoundaryException : Exception;
}
