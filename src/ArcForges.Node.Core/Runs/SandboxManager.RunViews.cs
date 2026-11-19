// SPDX-License-Identifier: AGPL-3.0-only
using System.Buffers.Binary;
using System.Globalization;
using System.Security.Cryptography;
using System.Text.Json;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Sandbox.V2;
using ArcForges.Node.Store;
using V2Shapes = ArcForges.Contracts.Sandbox.V2.Shapes.ContractShapeValidation;

namespace ArcForges.Node.Core.Sandboxes;

internal sealed partial class SandboxManager
{
    internal RunServiceListResponse ListRuns(RunServiceListRequest request, CancellationToken cancellationToken)
    {
        lock (OwnershipGate)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var meta = Response(request.Meta);
            if (!ValidId(request.SandboxId) || (request.HasLimit && request.Limit is < 1 or > 200))
            {
                return new() { Meta = meta, Error = Error(request.Meta, ErrorCategory.Validation, "invalid_argument", "run_list_shape_invalid") };
            }

            try
            {
                string sandboxId = ToHex(request.SandboxId);
                int limit = request.HasLimit ? checked((int)request.Limit) : 50;
                var snapshot = _store.Read(reader =>
                {
                    if (SandboxRecords.Get(reader, OwnerId, sandboxId) is null)
                    {
                        return (Visible: false, Value: (RunServiceListValue?)null);
                    }

                    // Runs are retained and each change advances one positive revision. Read the
                    // catalogue revision and page from the same owner-authorized store snapshot.
                    long revision = (long)reader.Scalar("""
                        SELECT coalesce(sum(revision), 0) FROM run WHERE sandbox_id=$sandbox;
                        """, ("$sandbox", sandboxId))!;
                    if (!ReadRunCursor(request.Cursor, sandboxId, revision, out string? after))
                    {
                        return (Visible: true, Value: (RunServiceListValue?)null);
                    }

                    var rows = RunRecords.List(reader, OwnerId, sandboxId, after, limit + 1);
                    var value = new RunServiceListValue
                    {
                        Page = new Page { NextCursor = rows.Count > limit ? WriteRunCursor(sandboxId, revision, rows[limit - 1].RunId) : "" },
                    };
                    value.Runs.AddRange(rows.Take(limit).Select(RunView));
                    return (Visible: true, Value: value);
                });
                if (!snapshot.Visible)
                {
                    return new() { Meta = meta, Error = NotFound(request.Meta) };
                }

                return snapshot.Value is { } page
                    ? new() { Meta = meta, Value = page }
                    : new() { Meta = meta, Error = Error(request.Meta, ErrorCategory.Validation, "invalid_cursor", "run_catalogue_changed") };
            }
            catch (Exception failure) when (IsStorageFailure(failure))
            {
                return new() { Meta = meta, Error = StorageFailure(request.Meta) };
            }
        }
    }

    internal RunServiceInspectResponse InspectRun(RunServiceInspectRequest request, CancellationToken cancellationToken)
    {
        lock (OwnershipGate)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var meta = Response(request.Meta);
            if (!ValidId(request.RunId))
            {
                return new() { Meta = meta, Error = Error(request.Meta, ErrorCategory.Validation, "invalid_argument", "run_id_invalid") };
            }

            try
            {
                var row = _store.Read(reader => RunRecords.Get(reader, OwnerId, ToHex(request.RunId)));
                return row is not null
                    ? new() { Meta = Response(request.Meta, row.Revision), Value = new() { Run = RunView(row) } }
                    : new() { Meta = meta, Error = Error(request.Meta, ErrorCategory.State, "not_found", "run_not_visible") };
            }
            catch (Exception failure) when (IsStorageFailure(failure))
            {
                return new() { Meta = meta, Error = StorageFailure(request.Meta) };
            }
        }
    }

    private Run RunView(StoredRun run)
    {
        var launch = ReadRunSnapshot(run);
        var value = new Run
        {
            RunId = FromHex(run.RunId),
            SandboxId = FromHex(run.SandboxId),
            Revision = new Revision { Value = run.Revision },
            State = (RunState)run.State,
            Epoch = run.Epoch,
            ProfileId = launch.ProfileId,
            LaunchSha256 = run.LaunchSha256,
            TerminalMode = launch.TerminalMode,
            CreatedAt = ProtoTime.ToInstant(run.CreatedAt),
            StartedAt = run.StartedAt is { } started ? ProtoTime.ToInstant(started) : null,
            SafeCommandDisplay = launch.SafeCommandDisplay,
            SandboxRevision = new Revision { Value = run.SandboxRevision },
            ProfileVersion = launch.ProfileVersion,
        };

        var limits = ReadProjectedRunLimits(run);
        if (limits.Length == 0)
        {
            value.Limits.Add(DesiredRunLimit("cpu", "millicores", launch.CpuMillicores));
            value.Limits.Add(DesiredRunLimit("memory", "bytes", launch.MemoryMaxBytes));
            value.Limits.Add(DesiredRunLimit("pids", "count", launch.MaxProcesses));
            if (launch.CpuWeight is { } weight)
            {
                value.Limits.Add(DesiredRunLimit("cpu_weight", "weight", weight));
            }
        }
        else
        {
            value.Limits.AddRange(limits);
        }

        if (run.State is StoredRunState.Exited or StoredRunState.Failed)
        {
            if (run.EndedAt is not { } observed || string.IsNullOrWhiteSpace(run.TerminationReason))
            {
                throw new InvalidDataException("The terminal Run is missing its trusted completion observation.");
            }

            // The Store can only commit either terminal state after trusted native emptiness proof.
            value.EndedAt = ProtoTime.ToInstant(observed);
            var exit = new RunExit
            {
                Source = run.ExitSource switch
                {
                    "payload" => ExitSource.Payload,
                    "official_executor" => ExitSource.OfficialExecutor,
                    "supervisor" => ExitSource.Supervisor,
                    "unknown" => ExitSource.Unknown,
                    _ => throw new InvalidDataException("The terminal Run has invalid exit provenance."),
                },
                TerminationReason = run.TerminationReason,
                PayloadStarted = (PayloadStartEvidence)run.PayloadStarted,
                Effect = (EffectCertainty)run.EffectCertainty,
                GroupEmptyVerified = true,
                ObservedAt = ProtoTime.ToInstant(observed),
            };
            if (run.RawExitCode is { } raw)
            {
                exit.RawCode = raw;
            }

            value.Exit = exit;
        }

        if (!V2Shapes.IsValid(value))
        {
            throw new InvalidDataException("The durable Run projection does not satisfy its wire contract.");
        }

        return value;
    }

    private static LimitState DesiredRunLimit(string dimension, string unit, ulong value) => new()
    {
        Dimension = dimension,
        Unit = unit,
        DesiredRevision = new Revision { Value = 1 },
        DesiredValue = value.ToString(CultureInfo.InvariantCulture),
        Status = LimitStatus.Pending,
        Reason = "native_readback_not_recorded",
    };

    private static RunSnapshot ReadRunSnapshot(StoredRun run)
    {
        using var document = JsonDocument.Parse(run.SnapshotJson);
        var json = document.RootElement;
        if (json.ValueKind != JsonValueKind.Object)
        {
            throw new InvalidDataException("The durable Run launch snapshot is not an object.");
        }

        string? profileId = GetString(json, "profileId");
        string? profileVersion = GetString(json, "profileVersion");
        string? display = GetString(json, "safeCommandDisplay");
        string? startCommand = GetString(json, "startCommandId");
        ulong terminal = RunSnapshotNumber(json, "terminalMode");
        ulong cpu = RunSnapshotNumber(json, "cpuMillicores");
        ulong memory = RunSnapshotNumber(json, "memoryMaxBytes");
        ulong processes = RunSnapshotNumber(json, "maxProcesses");
        ulong? weight = json.TryGetProperty("cpuWeight", out var optionalWeight) && optionalWeight.ValueKind != JsonValueKind.Null
            ? RunSnapshotNumber(json, "cpuWeight")
            : null;
        if (string.IsNullOrWhiteSpace(profileId) || string.IsNullOrWhiteSpace(profileVersion)
            || string.IsNullOrWhiteSpace(display) || display.Contains('/') || display.Contains('\\') || display.Any(char.IsControl)
            || startCommand is null || !IsSandboxId(startCommand)
            || terminal is not ((ulong)TerminalMode.Pipes or (ulong)TerminalMode.Interactive)
            || cpu is 0 or > uint.MaxValue || memory == 0 || processes is 0 or > uint.MaxValue || weight is 0 or > uint.MaxValue)
        {
            throw new InvalidDataException("The durable Run launch snapshot has invalid redacted metadata.");
        }

        return new(profileId, profileVersion, (TerminalMode)terminal, display, (uint)cpu, memory, (uint)processes,
            startCommand, weight is { } present ? (uint)present : null);
    }

    private static ulong RunSnapshotNumber(JsonElement json, string key)
    {
        if (!json.TryGetProperty(key, out var value) || value.ValueKind != JsonValueKind.Number || !value.TryGetUInt64(out ulong number))
        {
            throw new InvalidDataException("The durable Run launch snapshot has an invalid numeric field.");
        }

        return number;
    }

    private string WriteRunCursor(string sandboxId, long revision, string runId)
    {
        Span<byte> token = stackalloc byte[CursorSize];
        BinaryPrimitives.WriteInt64LittleEndian(token, revision);
        Convert.FromHexString(runId).CopyTo(token[sizeof(long)..CursorPayloadSize]);
        SignRunCursor(sandboxId, token[..CursorPayloadSize], token[CursorPayloadSize..]);
        return Convert.ToBase64String(token);
    }

    private bool ReadRunCursor(string cursor, string sandboxId, long revision, out string? after)
    {
        after = null;
        if (cursor.Length == 0)
        {
            return true;
        }

        Span<byte> token = stackalloc byte[CursorSize];
        if (!Convert.TryFromBase64String(cursor, token, out int written) || written != token.Length
            || BinaryPrimitives.ReadInt64LittleEndian(token) != revision)
        {
            return false;
        }

        Span<byte> mac = stackalloc byte[32];
        SignRunCursor(sandboxId, token[..CursorPayloadSize], mac);
        if (!CryptographicOperations.FixedTimeEquals(mac, token[CursorPayloadSize..]))
        {
            return false;
        }

        after = Convert.ToHexStringLower(token[sizeof(long)..CursorPayloadSize]);
        return true;
    }

    private void SignRunCursor(string sandboxId, ReadOnlySpan<byte> cursorPayload, Span<byte> signature)
    {
        // The per-owner manager key authenticates both the catalogue and its exact Sandbox filter.
        Span<byte> authenticated = stackalloc byte[1 + 16 + CursorPayloadSize];
        authenticated[0] = (byte)'r';
        Convert.FromHexString(sandboxId).CopyTo(authenticated[1..17]);
        cursorPayload.CopyTo(authenticated[17..]);
        HMACSHA256.HashData(_cursorKey, authenticated, signature);
    }

    private sealed record RunSnapshot(
        string ProfileId,
        string ProfileVersion,
        TerminalMode TerminalMode,
        string SafeCommandDisplay,
        uint CpuMillicores,
        ulong MemoryMaxBytes,
        uint MaxProcesses,
        string StartCommandId,
        uint? CpuWeight);
}
