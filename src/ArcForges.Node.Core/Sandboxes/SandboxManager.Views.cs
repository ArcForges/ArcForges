// SPDX-License-Identifier: AGPL-3.0-only
using System.Buffers.Binary;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Sandbox.V2;
using ArcForges.Node.Platform.Capabilities;
using ArcForges.Node.Store;
using Google.Protobuf;
using Microsoft.Data.Sqlite;

namespace ArcForges.Node.Core.Sandboxes;

internal sealed partial class SandboxManager
{
    private const int CursorPayloadSize = sizeof(long) + 16;
    private const int CursorSize = CursorPayloadSize + 32;
    private static string ContractCohort =>
        typeof(Sandbox).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion
        ?? "2.0";

    internal SandboxServiceListResponse List(SandboxServiceListRequest request, CancellationToken cancellationToken)
    {
        lock (OwnershipGate)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var meta = Response(request.Meta);
            if (request.HasLimit && request.Limit is < 1 or > 200)
            {
                return new() { Meta = meta, Error = Error(request.Meta, ErrorCategory.Validation, "invalid_argument", "limit_invalid") };
            }

            try
            {
                int limit = request.HasLimit ? checked((int)request.Limit) : 50;
                var snapshot = _store.Read(reader =>
                {
                    long revision = SandboxRecords.CatalogRevision(reader, OwnerId);
                    if (!ReadCursor(request.Cursor, revision, out string? after))
                    {
                        return null;
                    }

                    var rows = SandboxRecords.List(reader, OwnerId, after, limit + 1);
                    var value = new SandboxServiceListValue
                    {
                        Page = new Page { NextCursor = rows.Count > limit ? WriteCursor(revision, rows[limit - 1].SandboxId) : "" },
                    };
                    foreach (var row in rows.Take(limit))
                    {
                        var item = View(row);
                        item.ActiveRunIds.AddRange(SandboxRecords.ListNonterminalRunIds(reader, row.SandboxId).Select(FromHex));
                        value.Sandboxes.Add(item);
                    }

                    return value;
                });
                return snapshot is not null
                    ? new() { Meta = meta, Value = snapshot }
                    : new() { Meta = meta, Error = Error(request.Meta, ErrorCategory.Validation, "invalid_cursor", "sandbox_catalogue_changed") };
            }
            catch (Exception failure) when (IsStorageFailure(failure))
            {
                return new() { Meta = meta, Error = StorageFailure(request.Meta) };
            }
        }
    }

    internal SandboxServiceInspectResponse Inspect(SandboxServiceInspectRequest request, CancellationToken cancellationToken)
    {
        lock (OwnershipGate)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var meta = Response(request.Meta);
            try
            {
                var id = ToHex(request.SandboxId);
                var snapshot = _store.Read(reader =>
                {
                    var row = SandboxRecords.Get(reader, OwnerId, id);
                    bool deleting = row?.State is StoredSandboxState.Deleting or StoredSandboxState.Deleted ||
                        row?.State == StoredSandboxState.RecoveryRequired && SandboxDeletionRecords.HasPendingForSandbox(reader, OwnerId, id);
                    return (Row: row, Active: row is null ? [] : SandboxRecords.ListNonterminalRunIds(reader, id), Deleting: deleting);
                });
                if (snapshot.Row is not { } row)
                {
                    return new() { Meta = meta, Error = NotFound(request.Meta) };
                }

                if (row.State == StoredSandboxState.Ready)
                {
                    using var root = _roots.Inspect(id, row.RootIdentity);
                }

                var value = snapshot.Deleting ? View(row) : View(row, EvaluatePolicy(FromStored(row.Config)).Admission);
                value.ActiveRunIds.AddRange(snapshot.Active.Select(FromHex));
                return new() { Meta = Response(request.Meta, row.Revision), Value = new() { Sandbox = value } };
            }
            catch (SandboxPrivateRootException failure)
            {
                return new() { Meta = meta, Error = Error(request.Meta, ErrorCategory.Conflict, "identity_changed", failure.Reason) };
            }
            catch (Exception failure) when (IsStorageFailure(failure))
            {
                return new() { Meta = meta, Error = StorageFailure(request.Meta) };
            }
        }
    }

    internal NodeServiceGetOperationResponse GetOperation(NodeServiceGetOperationRequest request, CancellationToken cancellationToken)
    {
        lock (OwnershipGate)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var meta = Response(request.Meta);
            try
            {
                if (_receipts.IsValueCreated && _receipts.Value.MaintenanceRequired)
                {
                    return new() { Meta = meta, Error = StorageFailure(request.Meta) };
                }

                var receipt = _store.Read(reader => DurableOperationReads.Find(reader, OwnerId,
                    request.OwnerEpoch.Value.Span, request.CommandId.Value.Span));
                if (receipt is null)
                {
                    return new() { Meta = meta, Error = NotFound(request.Meta) };
                }

                var result = ReadResult(receipt.ResponseJson);
                var operation = new Operation
                {
                    CommandId = request.CommandId.Clone(),
                    OwnerEpoch = request.OwnerEpoch.Clone(),
                    Method = receipt.Method,
                    State = receipt.State switch
                    {
                        "ACCEPTED" => OperationState.Accepted,
                        "SUCCEEDED" => OperationState.Succeeded,
                        "FAILED" => OperationState.Failed,
                        _ => OperationState.Unknown,
                    },
                    Effect = (EffectCertainty)receipt.Effect,
                    ResponseCompacted = receipt.Compacted,
                    UpdatedAt = ProtoTime.ToInstant(receipt.UpdatedAt),
                };
                if (receipt.AggregateId is { } aggregate && IsSandboxId(aggregate))
                {
                    operation.AggregateId = FromHex(aggregate);
                }

                if (result.Revision is long revision)
                {
                    operation.Revision = new Revision { Value = revision };
                }

                if (receipt.State == "FAILED" && !receipt.Compacted)
                {
                    operation.Error = Error(request.Meta, result.Category, result.Code, result.Reason, operation.Effect);
                }
                else if (receipt.State == "UNKNOWN")
                {
                    operation.Error = Error(request.Meta, ErrorCategory.Execution, "outcome_unknown", result.Reason,
                        EffectCertainty.Unknown);
                }

                return new() { Meta = meta, Value = new() { Operation = operation } };
            }
            catch (Exception failure) when (IsStorageFailure(failure))
            {
                return new() { Meta = meta, Error = StorageFailure(request.Meta) };
            }
        }
    }

    private Sandbox View(StoredSandbox row, MxcAdmissionResult? admission = null)
    {
        var result = new Sandbox
        {
            SandboxId = FromHex(row.SandboxId),
            DisplayName = row.DisplayName,
            Revision = new Revision { Value = row.Revision },
            State = (SandboxState)row.State,
            Config = FromStored(row.Config),
            CreatedAt = ProtoTime.ToInstant(row.CreatedAt),
        };
        if (row.State == StoredSandboxState.Ready && row.RootRelative == SandboxPrivateRoots.RelativePath(row.SandboxId))
        {
            result.DataLocation = Path.Combine(_dataRoot, row.RootRelative);
        }

        if (admission is not null)
        {
            result.Capabilities.AddRange(SandboxPolicyAdmission.Capabilities(admission));
        }

        return result;
    }

    private static StoredSandboxConfig ToStored(SandboxConfig config)
    {
        string json = JsonFormatter.Default.Format(config);
        return new(config.ProfileId, config.ProfileVersion, json, Hash(json));
    }

    private static SandboxConfig FromStored(StoredSandboxConfig stored)
    {
        if (!StringComparer.Ordinal.Equals(stored.Sha256, Hash(stored.Json)))
        {
            throw new InvalidDataException("The committed Sandbox configuration digest did not match.");
        }

        var config = JsonParser.Default.Parse<SandboxConfig>(stored.Json);
        if (config.ProfileId != stored.ProfileId || config.ProfileVersion != stored.ProfileVersion)
        {
            throw new InvalidDataException("The committed Sandbox profile metadata did not match.");
        }

        return config;
    }

    private static string Hash(string text) => Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(text)));

    private static bool NormalizeName(string value, out string name, out string normalized)
    {
        name = value.Normalize(NormalizationForm.FormC);
        normalized = name.Trim().ToUpperInvariant().Normalize(NormalizationForm.FormC);
        return !string.IsNullOrEmpty(normalized) && name.EnumerateRunes().Count() <= 80 && !name.Any(char.IsControl);
    }

    private string WriteCursor(long revision, string sandboxId)
    {
        Span<byte> token = stackalloc byte[CursorSize];
        BinaryPrimitives.WriteInt64LittleEndian(token, revision);
        Convert.FromHexString(sandboxId).CopyTo(token[sizeof(long)..CursorPayloadSize]);
        HMACSHA256.HashData(_cursorKey, token[..CursorPayloadSize], token[CursorPayloadSize..]);
        return Convert.ToBase64String(token);
    }

    private bool ReadCursor(string cursor, long revision, out string? after)
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
        HMACSHA256.HashData(_cursorKey, token[..CursorPayloadSize], mac);
        if (!CryptographicOperations.FixedTimeEquals(mac, token[CursorPayloadSize..]))
        {
            return false;
        }

        after = Convert.ToHexStringLower(token[sizeof(long)..CursorPayloadSize]);
        return true;
    }

    private static string ResultBody(long? revision, string? name, ErrorCategory category = ErrorCategory.Unspecified,
        string? code = null, string? reason = null, IEnumerable<Capability>? capabilities = null)
    {
        // The result refers to immutable config history instead of copying policy, paths or environment into a receipt.
        var result = new JsonObject
        {
            ["revision"] = revision,
            ["displayName"] = name,
            ["category"] = (int)category,
            ["code"] = code,
            ["reason"] = reason,
            ["capabilities"] = capabilities is null ? null : new JsonArray(capabilities
                .Select(capability => (JsonNode?)JsonValue.Create(Convert.ToBase64String(capability.ToByteArray()))).ToArray()),
        };
        return result.ToJsonString();
    }

    private static ResultSummary ReadResult(string? json)
    {
        if (json is null)
        {
            return new(null, null, ErrorCategory.Execution, "outcome_unknown", "original_operation_unresolved", []);
        }

        using var document = JsonDocument.Parse(json);
        var value = document.RootElement;
        if (value.ValueKind != JsonValueKind.Object)
        {
            throw new InvalidDataException("The durable Sandbox result had an invalid shape.");
        }

        long? revision = value.TryGetProperty("revision", out var rev) && rev.ValueKind == JsonValueKind.Number && rev.TryGetInt64(out long number) ? number : null;
        int category = value.TryGetProperty("category", out var cat) && cat.ValueKind == JsonValueKind.Number && cat.TryGetInt32(out int ordinal)
            ? ordinal : (int)ErrorCategory.Execution;
        return new(revision, GetString(value, "displayName"), (ErrorCategory)category,
            GetString(value, "code") ?? "outcome_unknown", GetString(value, "reason") ?? "original_operation_unresolved",
            ReadCapabilities(value));
    }

    private static IReadOnlyList<Capability> ReadCapabilities(JsonElement json)
    {
        if (!json.TryGetProperty("capabilities", out var values) || values.ValueKind == JsonValueKind.Null)
        {
            return [];
        }

        if (values.ValueKind != JsonValueKind.Array)
        {
            throw new InvalidDataException("The durable Sandbox capability observations had an invalid shape.");
        }

        return [.. values.EnumerateArray().Select(value => Capability.Parser.ParseFrom(value.GetBytesFromBase64()))];
    }

    private static string? GetString(JsonElement json, string key) =>
        json.TryGetProperty(key, out var value) && value.ValueKind == JsonValueKind.String ? value.GetString() : null;

    private static AggregateRef? AggregateIdentity(DurableReceipt receipt) =>
        receipt.AggregateKind is { } kind && receipt.AggregateId is { } id && IsSandboxId(id)
            ? new AggregateRef { Kind = kind, Id = FromHex(id) } : null;

    private static ResponseMeta Response(RequestMeta? request, long? revision = null) => new()
    {
        CorrelationId = request?.CorrelationId?.Clone(),
        ResultRev = revision is long value ? new Revision { Value = value } : null,
    };

    private static ArcError Error(RequestMeta? request, ErrorCategory category, string code, string reason,
        EffectCertainty effect = EffectCertainty.DidNotHappen)
    {
        var retry = new RetryAdvice { Mode = effect == EffectCertainty.Unknown ? RetryMode.Reconcile : RetryMode.Never };
        if (effect == EffectCertainty.Unknown)
        {
            retry.ReconciliationOperation = "NodeService.GetOperation";
        }

        return new ArcError
        {
            Category = category,
            Code = code,
            MessageKey = "sandbox." + code,
            Effect = effect,
            CorrelationId = request?.CorrelationId?.Clone(),
            Retry = retry,
            Details = new ErrorDetails { State = new StateFailure { Reason = reason } },
        };
    }

    private static ArcError PolicyError(RequestMeta meta, MxcAdmissionResult admission)
    {
        var reason = admission.Reason ?? "profile_not_admitted";
        if (admission.MissingPrerequisites != MxcPrerequisites.None)
        {
            reason += ":" + admission.MissingPrerequisites;
        }
        else if (admission.Feature is { } feature)
        {
            reason += ":" + feature;
        }

        var error = Error(meta, ErrorCategory.Execution, "unsupported_combination", reason);
        error.Details.State.State = admission.ProfileId is MxcProfileAdmission.WindowsProfileId or MxcProfileAdmission.LinuxProfileId
            ? admission.ProfileId : "unrecognized_profile";
        return error;
    }

    private static ArcError RevisionError(RequestMeta meta, long expected, long actual)
    {
        var error = Error(meta, ErrorCategory.Conflict, "revision_mismatch", "sandbox_revision_changed");
        error.Details.Revision = new RevisionConflict
        {
            Expected = new Revision { Value = expected },
            Actual = new Revision { Value = actual },
        };
        return error;
    }

    private static ArcError ControlPathFailure(RequestMeta? meta, SandboxPrivateRootException failure) =>
        Error(meta, ErrorCategory.Execution, "unsupported_combination", "private_control_paths:" + failure.Reason);

    private static ArcError StorageFailure(RequestMeta? meta) =>
        Error(meta, ErrorCategory.Internal, "store_corrupt", "sandbox_metadata_unavailable", EffectCertainty.Unknown);

    private static ArcError NotFound(RequestMeta? meta) =>
        Error(meta, ErrorCategory.State, "not_found", "sandbox_or_operation_not_visible");

    private static bool IsStorageFailure(Exception failure) => failure is IOException or UnauthorizedAccessException
        or DurableStoreMaintenanceException or SqliteException or InvalidDataException or FormatException or JsonException
        or InvalidProtocolBufferException or InvalidJsonException;

    private static void RequireChanged(bool changed)
    {
        if (!changed)
        {
            throw new DurableStoreMaintenanceException();
        }
    }

    private static bool ValidId(Id? id) => id?.Value.Length == 16;
    private static bool IsSandboxId(string id) => id.Length == 32 && id.All(char.IsAsciiHexDigitLower);
    private static Id FromBytes(ReadOnlySpan<byte> value) => new() { Value = ByteString.CopyFrom(value) };
    private static Id FromHex(string value) => FromBytes(Convert.FromHexString(value));
    private static string ToHex(Id id) => Convert.ToHexStringLower(id.Value.Span);

    private static MutationOutcome Fail(ArcError error) => new(null, error);
    private sealed record MutationOutcome(Sandbox? Value, ArcError? Error = null);
    private sealed record ResultSummary(long? Revision, string? Name, ErrorCategory Category, string Code, string Reason,
        IReadOnlyList<Capability> Capabilities);
}
