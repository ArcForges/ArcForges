// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Node.Core.Platform;
using ArcForges.Node.Platform;
using ArcForges.Node.Store;
using ArcForges.Node.Store.Proto;
using Google.Protobuf;

namespace ArcForges.Node.Core.Tests;

/// <summary>Seeds an already executed legacy Task before the fixture Node opens its store.</summary>
internal static class LegacyTaskHistoryFixture
{
    public static Id SeedQueued(StoreTransaction transaction, ActorRef owner, Priority priority = Priority.Normal,
        Priority? effective = null, long? agedAt = null)
    {
        var task = StoreIds.NewUuid7(transaction.Clock);
        var spec = new TaskSpec
        {
            Kind = TaskKind.Command,
            Command = new CommandSpec { Argv = new ArgvCommand { Argv = { "fixture-never-starts" } } },
        }.ToByteArray();
        transaction.Execute(
            """
            INSERT INTO task (task_id, state, kind, title, command_summary, spec, spec_digest, owner, owner_origin, owner_session_id,
                              pool, priority, effective_priority, side_effect, side_effect_source, command_fingerprint,
                              command_digest, created_at, queued_at, aged_at, rev)
            VALUES ($task, $state, 1, 'retained queue fixture', 'retained queue fixture', $spec, $digest, $owner, $origin, $session,
                    'default', $priority, $effective, 4, 1, 'retained-queue-fixture', $digest, $now, $now, $agedAt, 0);
            """,
            ("$task", task), ("$state", (int)TaskState.Queued), ("$spec", spec), ("$digest", SHA256.HashData(spec)),
            ("$owner", owner.ToByteArray()), ("$origin", (int)owner.Origin), ("$session", owner.SessionId?.Value.ToByteArray()),
            ("$priority", (int)priority), ("$effective", (int)(effective ?? priority)), ("$now", agedAt ?? transaction.NowMicroseconds),
            ("$agedAt", agedAt));
        return new Id { Value = ByteString.CopyFrom(task) };
    }

    public static (Id TaskId, Id AttemptId) Seed(InProcessNode node, AttemptState phase, SecretEnvironment? secrets = null,
        RootProcess? root = null, string? stateReason = null)
    {
        var boot = BootIdentity.Read();
        using var store = NodeStore.Open(new NodeStoreOptions { DataRoot = node.DataRoot, BootIdentity = boot, Clock = node.Clock });
        using var keys = secrets is null ? null : new NodeDataKeyRing(store, node.Secrets.Selection);
        const string command = "fixture-never-starts";
        var spec = new TaskSpec
        {
            Kind = TaskKind.Command,
            Command = new CommandSpec { Argv = new ArgvCommand { Argv = { command } } },
            WorkingDirectory = node.Root,
            Resources = root is null ? null : new ResourceSpec { Pausable = true },
        }.ToByteArray();
        var finished = phase == AttemptState.Finished;
        var state = phase switch
        {
            AttemptState.Finished => TaskState.Succeeded,
            AttemptState.Paused => TaskState.Paused,
            _ => TaskState.Running,
        };
        return store.Write(transaction =>
        {
            var task = StoreIds.NewUuid7(transaction.Clock);
            var attempt = StoreIds.NewUuid7(transaction.Clock);
            var now = transaction.NowMicroseconds;
            transaction.Execute(
                """
                INSERT INTO task (task_id, state, state_reason, kind, title, command_summary, spec, spec_digest, owner, owner_origin,
                                  pool, priority, effective_priority, side_effect, side_effect_source, command_fingerprint,
                                  command_digest, created_at, started_at, finished_at, current_attempt_id, attempt_count, rev)
                VALUES ($task, $state, $stateReason, 1, $command, $command, $spec, $digest, $owner, 1,
                        'default', 3, 3, 4, 1, $command, $digest, $now, $now, $finished, $attempt, 1, 0);
                """,
                ("$task", task), ("$state", (int)state), ("$stateReason", stateReason), ("$command", command),
                ("$spec", spec), ("$digest", SHA256.HashData(spec)), ("$owner", new ActorRef { Origin = Origin.Human }.ToByteArray()),
                ("$attempt", attempt), ("$now", now), ("$finished", finished ? now : null));
            transaction.Execute(
                """
                INSERT INTO attempt (attempt_id, task_id, number, kind, state, executor_node_id, boot_identity, root_pid, root_start,
                                     request_cpu_millicores, request_mem_expected_bytes, request_mem_ceiling_bytes, request_source,
                                     accounted_mem_bytes, created_at, started_at, finished_at, exit_code, termination_reason, effect, rev)
                VALUES ($attempt, $task, 1, 1, $phase, $node, $boot, $pid, $start, 100, 67108864, 67108864, 1, 67108864,
                        $now, $now, $finished, $exit, $reason, $effect, 0);
                """,
                ("$attempt", attempt), ("$task", task), ("$phase", (int)phase), ("$node", store.Metadata.NodeId.ToArray()),
                ("$pid", root?.Pid), ("$start", root is null ? null : StoreTime.ToMicroseconds(root.StartTime)),
                ("$boot", boot), ("$now", now), ("$finished", finished ? now : null), ("$exit", finished ? 0 : null),
                ("$reason", finished ? (int)TerminationReason.Exited : null), ("$effect", finished ? (int)EffectCertainty.Happened : null));
            if (secrets is not null)
            {
                new TaskSecrets(store, keys!).Seal(transaction, task, secrets);
            }

            return (new Id { Value = ByteString.CopyFrom(task) }, new Id { Value = ByteString.CopyFrom(attempt) });
        }, CommitDurability.Full);
    }
}
