// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Node.Store;
using Google.Protobuf;

namespace ArcForges.Node.Core.Tests;

/// <summary>Seeds a historical queue row for workspace binding tests.</summary>
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
}
