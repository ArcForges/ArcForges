// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Node.Core.Platform;
using ArcForges.Node.Store;
using ArcForges.Node.Store.Proto;
using Google.Protobuf;

namespace ArcForges.Node.Core.Tests;

/// <summary>Seeds an already executed legacy Task before the fixture Node opens its store.</summary>
internal static class LegacyTaskHistoryFixture
{
    public static (Id TaskId, Id AttemptId) Seed(InProcessNode node, AttemptState phase, SecretEnvironment? secrets = null)
    {
        var boot = BootIdentity.Read();
        using var store = NodeStore.Open(new NodeStoreOptions { DataRoot = node.DataRoot, BootIdentity = boot });
        using var keys = secrets is null ? null : new NodeDataKeyRing(store, node.Secrets.Selection);
        const string command = "fixture-already-exited";
        var spec = new TaskSpec
        {
            Kind = TaskKind.Command,
            Command = new CommandSpec { Argv = new ArgvCommand { Argv = { command } } },
            WorkingDirectory = node.Root,
        }.ToByteArray();
        var finished = phase == AttemptState.Finished;
        return store.Write(transaction =>
        {
            var task = StoreIds.NewUuid7(transaction.Clock);
            var attempt = StoreIds.NewUuid7(transaction.Clock);
            var now = transaction.NowMicroseconds;
            transaction.Execute(
                """
                INSERT INTO task (task_id, state, kind, title, command_summary, spec, spec_digest, owner, owner_origin,
                                  pool, priority, effective_priority, side_effect, side_effect_source, command_fingerprint,
                                  command_digest, created_at, started_at, finished_at, current_attempt_id, attempt_count, rev)
                VALUES ($task, $state, 1, $command, $command, $spec, $digest, $owner, 1,
                        'default', 3, 3, 4, 1, $command, $digest, $now, $now, $finished, $attempt, 1, 0);
                """,
                ("$task", task), ("$state", (int)(finished ? TaskState.Succeeded : TaskState.Running)), ("$command", command),
                ("$spec", spec), ("$digest", SHA256.HashData(spec)), ("$owner", new ActorRef { Origin = Origin.Human }.ToByteArray()),
                ("$attempt", attempt), ("$now", now), ("$finished", finished ? now : null));
            transaction.Execute(
                """
                INSERT INTO attempt (attempt_id, task_id, number, kind, state, executor_node_id, boot_identity,
                                     request_cpu_millicores, request_mem_expected_bytes, request_mem_ceiling_bytes, request_source,
                                     accounted_mem_bytes, created_at, started_at, finished_at, exit_code, termination_reason, effect, rev)
                VALUES ($attempt, $task, 1, 1, $phase, $node, $boot, 100, 67108864, 67108864, 1, 67108864,
                        $now, $now, $finished, $exit, $reason, $effect, 0);
                """,
                ("$attempt", attempt), ("$task", task), ("$phase", (int)phase), ("$node", store.Metadata.NodeId.ToArray()),
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
