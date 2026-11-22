// SPDX-License-Identifier: AGPL-3.0-only
using System.Text.Json;
using System.Text.Json.Serialization;
using ArcForges.Node.Store.Migrations;

namespace ArcForges.Node.Store;

internal enum NativeUpdatePhase
{
    Fenced = 1,
    Prepared,
    CandidateReady,
    Completed,
    RolledBack,
}

internal sealed record NativeUpdateCohort(string Commit, string Tree, string ArchiveSha256, string InstallationRoot);

internal sealed record NativeUpdateCheckpoint(int StoreSchema, int MinimumReader, int CandidateReader, string BackupManifestSha256);

internal sealed record NativeUpdateState(int Format, Guid OperationId, NativeUpdatePhase Phase,
    NativeUpdateCohort Previous, NativeUpdateCohort Candidate, NativeUpdateCheckpoint? Checkpoint,
    DateTimeOffset UpdatedAt)
{
    [JsonIgnore]
    public bool IsFenced => Phase is not (NativeUpdatePhase.Completed or NativeUpdatePhase.RolledBack);
}

/// <summary>Serializes fresh Run admission with a durable update marker independent of the database it protects.</summary>
internal static class NativeUpdateGate
{
    private const string LockFile = "native-update.lock";
    private const string MarkerFile = "native-update.json";
    private const int Format = 1;
    private const int MaximumMarkerBytes = 32 * 1024;

    /// <summary>Holds the maintenance lease through publication of a first Start receipt. Corrupt or unavailable state refuses fresh Starts.</summary>
    internal static IDisposable? TryEnterFreshStart(string dataRoot)
    {
        FileStream? lease = null;
        try
        {
            lease = Acquire(dataRoot);
            if (ReadHeld(dataRoot) is { IsFenced: true })
                return null;

            var acquired = lease;
            lease = null;
            return acquired;
        }
        catch (Exception failure) when (failure is IOException or UnauthorizedAccessException or StoreIncompatibleException or JsonException or ArgumentException)
        {
            return null;
        }
        finally
        {
            lease?.Dispose();
        }
    }

    internal static NativeUpdateState? Read(string dataRoot)
    {
        using var lease = Acquire(dataRoot);
        return ReadHeld(dataRoot);
    }

    internal static NativeUpdateState Begin(string dataRoot, Guid operationId, NativeUpdateCohort previous, NativeUpdateCohort candidate)
    {
        var next = new NativeUpdateState(Format, operationId, NativeUpdatePhase.Fenced, previous, candidate, null, DateTimeOffset.UtcNow);
        Validate(next);
        using var lease = Acquire(dataRoot);
        if (ReadHeld(dataRoot) is { } existing)
        {
            if (existing.OperationId == operationId && existing.Previous == previous && existing.Candidate == candidate)
                return existing;
            if (existing.IsFenced || existing.OperationId == operationId)
                throw Incompatible("native_update_operation_conflict");
        }

        Publish(dataRoot, next);
        return next;
    }

    internal static NativeUpdateState Prepare(string dataRoot, Guid operationId, NativeUpdateCheckpoint checkpoint) =>
        Advance(dataRoot, operationId, NativeUpdatePhase.Prepared, checkpoint);

    internal static NativeUpdateState MarkReady(string dataRoot, Guid operationId) =>
        Advance(dataRoot, operationId, NativeUpdatePhase.CandidateReady);

    internal static NativeUpdateState Complete(string dataRoot, Guid operationId) =>
        Advance(dataRoot, operationId, NativeUpdatePhase.Completed);

    internal static NativeUpdateState MarkRolledBack(string dataRoot, Guid operationId) =>
        Advance(dataRoot, operationId, NativeUpdatePhase.RolledBack);

    internal static void RequireCompatibleReader(int schema, int minimumReader, int candidateReader)
    {
        if (schema <= 0 || minimumReader <= 0 || minimumReader > schema || candidateReader < minimumReader)
            throw Incompatible("native_update_reader_incompatible");
    }

    private static NativeUpdateState Advance(string dataRoot, Guid operationId, NativeUpdatePhase phase,
        NativeUpdateCheckpoint? checkpoint = null)
    {
        using var lease = Acquire(dataRoot);
        var current = ReadHeld(dataRoot);
        if (current is null || current.OperationId != operationId)
            throw Incompatible("native_update_operation_conflict");

        if (current.Phase == phase && (checkpoint is null || current.Checkpoint == checkpoint))
            return current;

        bool allowed = (current.Phase, phase) switch
        {
            (NativeUpdatePhase.Fenced, NativeUpdatePhase.Prepared) => true,
            (NativeUpdatePhase.Prepared, NativeUpdatePhase.CandidateReady) => true,
            (NativeUpdatePhase.CandidateReady, NativeUpdatePhase.Completed) => true,
            (_, NativeUpdatePhase.RolledBack) when current.IsFenced => true,
            _ => false,
        };
        if (!allowed)
            throw Incompatible("native_update_phase_conflict");

        var next = current with { Phase = phase, Checkpoint = checkpoint ?? current.Checkpoint, UpdatedAt = DateTimeOffset.UtcNow };
        Validate(next);
        Publish(dataRoot, next);
        return next;
    }

    private static FileStream Acquire(string dataRoot)
    {
        ContractionPaths.RequireOwnedDirectory(dataRoot);
        string path = Path.Combine(dataRoot, LockFile);
        ContractionPaths.NativeIdentity? expected = Exists(path) ? ContractionPaths.NamedRegularIdentity(path) : null;
        var lease = DurableEpochFence.OpenPrivate(path, expected is null ? FileMode.CreateNew : FileMode.Open);
        try
        {
            var identity = ContractionPaths.Identity(lease.SafeFileHandle);
            if ((expected is not null && identity != expected) || identity != ContractionPaths.NamedRegularIdentity(path))
                throw Incompatible("native_update_lock_identity_changed");
            return lease;
        }
        catch
        {
            lease.Dispose();
            throw;
        }
    }

    private static NativeUpdateState? ReadHeld(string dataRoot)
    {
        string marker = Path.Combine(dataRoot, MarkerFile);
        if (!Exists(marker))
            return null;

        using var read = ContractionPaths.OpenRegularRead(marker);
        if (read.Length <= 0 || read.Length > MaximumMarkerBytes)
            throw Incompatible("native_update_marker_invalid");

        byte[] bytes = new byte[checked((int)read.Length)];
        read.ReadExactly(bytes);
        var state = JsonSerializer.Deserialize(bytes, NativeUpdateJsonContext.Default.NativeUpdateState)
            ?? throw Incompatible("native_update_marker_invalid");
        Validate(state);
        if (!bytes.AsSpan().SequenceEqual(JsonSerializer.SerializeToUtf8Bytes(state, NativeUpdateJsonContext.Default.NativeUpdateState)))
            throw Incompatible("native_update_marker_invalid");
        return state;
    }

    private static bool Exists(string path)
    {
        try
        {
            _ = File.GetAttributes(path);
            return true;
        }
        catch (FileNotFoundException)
        {
            return false;
        }
    }

    private static void Publish(string dataRoot, NativeUpdateState state)
    {
        string marker = Path.Combine(dataRoot, MarkerFile);
        string temporary = Path.Combine(dataRoot, $".{MarkerFile}.{Guid.NewGuid():N}.partial");
        byte[] bytes = JsonSerializer.SerializeToUtf8Bytes(state, NativeUpdateJsonContext.Default.NativeUpdateState);
        if (bytes.Length > MaximumMarkerBytes)
            throw Incompatible("native_update_marker_invalid");
        try
        {
            using (var write = DurableEpochFence.OpenPrivate(temporary, FileMode.CreateNew))
            {
                write.Write(bytes);
                write.Flush(flushToDisk: true);
            }
            ContractionPaths.ReplaceSiblingFileDurably(temporary, marker);
        }
        finally
        {
            File.Delete(temporary);
        }
    }

    private static void Validate(NativeUpdateState state)
    {
        if (state.Format != Format || state.OperationId == Guid.Empty || !Enum.IsDefined(state.Phase) || state.UpdatedAt == default ||
            !ValidCohort(state.Previous) || !ValidCohort(state.Candidate) ||
            string.Equals(state.Previous.InstallationRoot, state.Candidate.InstallationRoot, OperatingSystem.IsWindows()
                ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal) ||
            (state.Phase is NativeUpdatePhase.Prepared or NativeUpdatePhase.CandidateReady or NativeUpdatePhase.Completed && state.Checkpoint is null) ||
            (state.Phase == NativeUpdatePhase.Fenced && state.Checkpoint is not null))
            throw Incompatible("native_update_marker_invalid");

        if (state.Checkpoint is { } checkpoint)
        {
            if (!Hex(checkpoint.BackupManifestSha256, 64))
                throw Incompatible("native_update_marker_invalid");
            RequireCompatibleReader(checkpoint.StoreSchema, checkpoint.MinimumReader, checkpoint.CandidateReader);
        }
    }

    private static bool ValidCohort(NativeUpdateCohort? cohort) => cohort is not null && Hex(cohort.Commit, 40) && Hex(cohort.Tree, 40)
        && Hex(cohort.ArchiveSha256, 64) && cohort.InstallationRoot is { Length: > 0 and <= 4096 } path && Path.IsPathFullyQualified(path)
        && path == Path.TrimEndingDirectorySeparator(Path.GetFullPath(path));

    private static bool Hex(string? value, int length) => value?.Length == length
        && value.All(character => character is >= '0' and <= '9' or >= 'a' and <= 'f');

    private static StoreIncompatibleException Incompatible(string reason) => new(reason);
}

[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase)]
[JsonSerializable(typeof(NativeUpdateState))]
internal sealed partial class NativeUpdateJsonContext : JsonSerializerContext;
