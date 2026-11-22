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
    RollingBack,
    RestoringPredecessor,
}

internal sealed record NativeUpdateCohort(string Commit, string Tree, string ArchiveSha256, string InstallationRoot,
    string? DigestManifestSha256 = null);

internal sealed record NativeUpdateAuthority(string NodeId, string OwnerEpoch, string? PreviousSelection,
    int PreviousSchema, int PreviousMinimumReader, string? PreviousSupervisorProtocol);
internal sealed record NativeUpdateCheckpoint(int StoreSchema, int MinimumReader, int CandidateReader, string BackupManifestSha256,
    string? BackupRoot = null, bool DrainConfirmed = false, string? CandidateSupervisorProtocol = null);

internal sealed record NativeUpdateReadiness(string ArchiveSha256, string NodeEpoch, int ProcessId, long ProcessStartUnixMs);
internal sealed record NativeUpdateState(int Format, Guid OperationId, NativeUpdatePhase Phase,
    NativeUpdateCohort Previous, NativeUpdateCohort Candidate, NativeUpdateCheckpoint? Checkpoint, NativeUpdateAuthority? Authority,
    DateTimeOffset UpdatedAt, NativeUpdateReadiness? CandidateProbe = null, NativeUpdateReadiness? ActivatedOwner = null,
    NativeUpdateReadiness? RestoredOwner = null)
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
        Lease? lease = null;
        try
        {
            lease = Acquire(dataRoot);
            if (ReadHeld(lease.Directory) is { IsFenced: true })
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
        return ReadHeld(lease.Directory);
    }

    internal static bool IsUnchangedUnfenced(string dataRoot, NativeUpdateState? expected)
    {
        var current = Read(dataRoot);
        if (current is null || expected is null)
            return current is null && expected is null;
        return !current.IsFenced && !expected.IsFenced &&
            JsonSerializer.SerializeToUtf8Bytes(current, NativeUpdateJsonContext.Default.NativeUpdateState).AsSpan()
                .SequenceEqual(JsonSerializer.SerializeToUtf8Bytes(expected, NativeUpdateJsonContext.Default.NativeUpdateState));
    }

    internal static NativeUpdateState Begin(string dataRoot, Guid operationId, NativeUpdateCohort previous, NativeUpdateCohort candidate,
        NativeUpdateAuthority? authority = null)
    {
        var next = new NativeUpdateState(Format, operationId, NativeUpdatePhase.Fenced, previous, candidate, null, authority, DateTimeOffset.UtcNow);
        Validate(next);
        using var lease = Acquire(dataRoot);
        if (ReadHeld(lease.Directory) is { } existing)
        {
            if (existing.OperationId == operationId && existing.Previous == previous && existing.Candidate == candidate && existing.Authority == authority)
                return existing;
            if (existing.IsFenced || existing.OperationId == operationId)
                throw Incompatible("native_update_operation_conflict");
        }

        Publish(lease.Directory, next);
        return next;
    }

    internal static NativeUpdateState Prepare(string dataRoot, Guid operationId, NativeUpdateCheckpoint checkpoint) =>
        Advance(dataRoot, operationId, NativeUpdatePhase.Prepared, checkpoint);

    internal static NativeUpdateState MarkReady(string dataRoot, Guid operationId, NativeUpdateReadiness? proof = null) =>
        Advance(dataRoot, operationId, NativeUpdatePhase.CandidateReady, readiness: proof);

    internal static NativeUpdateState Complete(string dataRoot, Guid operationId, NativeUpdateReadiness? proof = null) =>
        Advance(dataRoot, operationId, NativeUpdatePhase.Completed, readiness: proof);

    internal static NativeUpdateState BeginRollback(string dataRoot, Guid operationId) =>
        Advance(dataRoot, operationId, NativeUpdatePhase.RollingBack);

    internal static NativeUpdateState BeginPreviousOwnerRestore(string dataRoot, Guid operationId) =>
        Advance(dataRoot, operationId, NativeUpdatePhase.RestoringPredecessor);

    internal static NativeUpdateState MarkRolledBack(string dataRoot, Guid operationId, NativeUpdateReadiness? proof = null) =>
        Advance(dataRoot, operationId, NativeUpdatePhase.RolledBack, readiness: proof);

    internal static IDisposable EnterOperator(string dataRoot) => Acquire(dataRoot, "native-update-operator.lock");

    internal static void RequireCompatibleReader(int schema, int minimumReader, int candidateReader)
    {
        if (schema <= 0 || minimumReader <= 0 || minimumReader > schema || candidateReader < minimumReader)
            throw Incompatible("native_update_reader_incompatible");
    }

    private static NativeUpdateState Advance(string dataRoot, Guid operationId, NativeUpdatePhase phase,
        NativeUpdateCheckpoint? checkpoint = null, NativeUpdateReadiness? readiness = null)
    {
        using var lease = Acquire(dataRoot);
        var current = ReadHeld(lease.Directory);
        if (current is null || current.OperationId != operationId)
            throw Incompatible("native_update_operation_conflict");

        if (current.Phase == phase && (checkpoint is null || current.Checkpoint == checkpoint)
            && (readiness is null || phase != NativeUpdatePhase.CandidateReady || current.CandidateProbe == readiness))
            return current;

        bool allowed = (current.Phase, phase) switch
        {
            (NativeUpdatePhase.Fenced, NativeUpdatePhase.Prepared) => true,
            (NativeUpdatePhase.Prepared or NativeUpdatePhase.CandidateReady, NativeUpdatePhase.CandidateReady) => true,
            (NativeUpdatePhase.CandidateReady, NativeUpdatePhase.Completed) => true,
            (NativeUpdatePhase.Fenced or NativeUpdatePhase.Prepared or NativeUpdatePhase.CandidateReady or NativeUpdatePhase.RollingBack,
                NativeUpdatePhase.RestoringPredecessor) when current.Authority is { PreviousSupervisorProtocol: null } => true,
            (_, NativeUpdatePhase.RollingBack) when current.Phase is not (NativeUpdatePhase.RolledBack or NativeUpdatePhase.RestoringPredecessor) => true,
            (_, NativeUpdatePhase.RolledBack) when current.IsFenced => true,
            _ => false,
        };
        if (!allowed)
            throw Incompatible("native_update_phase_conflict");

        var next = current with
        {
            Phase = phase,
            Checkpoint = checkpoint ?? current.Checkpoint,
            UpdatedAt = DateTimeOffset.UtcNow,
            CandidateProbe = phase == NativeUpdatePhase.CandidateReady ? readiness : current.CandidateProbe,
            ActivatedOwner = phase == NativeUpdatePhase.Completed ? readiness : current.ActivatedOwner,
            RestoredOwner = phase == NativeUpdatePhase.RolledBack ? readiness : current.RestoredOwner,
        };
        Validate(next);
        Publish(lease.Directory, next);
        return next;
    }

    private sealed class Lease(ContractionPaths.UpdateDirectory directory, FileStream file) : IDisposable
    {
        internal ContractionPaths.UpdateDirectory Directory { get; } = directory;

        public void Dispose()
        {
            file.Dispose();
            Directory.Dispose();
        }
    }

    private static Lease Acquire(string dataRoot, string filename = LockFile)
    {
        var directory = new ContractionPaths.UpdateDirectory(dataRoot);
        try
        {
            return new(directory, directory.Lock(filename));
        }
        catch
        {
            directory.Dispose();
            throw;
        }
    }

    private static NativeUpdateState? ReadHeld(ContractionPaths.UpdateDirectory directory)
    {
        using var read = directory.TryRead(MarkerFile);
        if (read is null)
            return null;
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

    private static void Publish(ContractionPaths.UpdateDirectory directory, NativeUpdateState state)
    {
        string temporary = $".{MarkerFile}.{Guid.NewGuid():N}.partial";
        byte[] bytes = JsonSerializer.SerializeToUtf8Bytes(state, NativeUpdateJsonContext.Default.NativeUpdateState);
        if (bytes.Length > MaximumMarkerBytes)
            throw Incompatible("native_update_marker_invalid");
        try
        {
            using (var write = directory.Create(temporary))
            {
                write.Write(bytes);
                write.Flush(flushToDisk: true);
            }
            directory.Replace(temporary, MarkerFile);
        }
        finally
        {
            directory.DeleteTemporary(temporary);
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
            if (!Hex(checkpoint.BackupManifestSha256, 64) || (checkpoint.BackupRoot is not null && !CanonicalPath(checkpoint.BackupRoot))
                || (state.Authority is not null && (checkpoint.BackupRoot is null || !checkpoint.DrainConfirmed
                    || checkpoint.CandidateSupervisorProtocol is not { Length: > 0 and <= 128 })))
                throw Incompatible("native_update_marker_invalid");
            RequireCompatibleReader(checkpoint.StoreSchema, checkpoint.MinimumReader, checkpoint.CandidateReader);
        }

        if (state.Authority is { } authority)
        {
            if (!Hex(authority.NodeId, 32) || !Hex(authority.OwnerEpoch, 32)
                || (authority.PreviousSelection is not null && authority.PreviousSelection != state.Previous.ArchiveSha256)
                || authority.PreviousSupervisorProtocol is { Length: 0 or > 128 }
                || !Hex(state.Previous.DigestManifestSha256, 64) || !Hex(state.Candidate.DigestManifestSha256, 64))
                throw Incompatible("native_update_marker_invalid");
            RequireCompatibleReader(authority.PreviousSchema, authority.PreviousMinimumReader, authority.PreviousSchema);
            if ((state.Phase is NativeUpdatePhase.CandidateReady or NativeUpdatePhase.Completed &&
                    !ValidReadiness(state.CandidateProbe, state.Candidate)) ||
                (state.Phase == NativeUpdatePhase.Completed && !ValidReadiness(state.ActivatedOwner, state.Candidate)) ||
                (state.Phase == NativeUpdatePhase.RolledBack && !ValidReadiness(state.RestoredOwner, state.Previous)))
                throw Incompatible("native_update_readiness_unconfirmed");
        }
    }

    private static bool ValidReadiness(NativeUpdateReadiness? proof, NativeUpdateCohort cohort) => proof is not null &&
        proof.ArchiveSha256 == cohort.ArchiveSha256 && proof.NodeEpoch is { Length: > 0 and <= 128 } &&
        proof.ProcessId > 0 && proof.ProcessStartUnixMs > 0;

    private static bool ValidCohort(NativeUpdateCohort? cohort) => cohort is not null && Hex(cohort.Commit, 40) && Hex(cohort.Tree, 40)
        && Hex(cohort.ArchiveSha256, 64) && CanonicalPath(cohort.InstallationRoot);

    private static bool CanonicalPath(string value) => value is { Length: > 0 and <= 4096 } && Path.IsPathFullyQualified(value)
        && value == Path.TrimEndingDirectorySeparator(Path.GetFullPath(value));

    private static bool Hex(string? value, int length) => value?.Length == length
        && value.All(character => character is >= '0' and <= '9' or >= 'a' and <= 'f');

    private static StoreIncompatibleException Incompatible(string reason) => new(reason);
}

[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase)]
[JsonSerializable(typeof(NativeUpdateState))]
internal sealed partial class NativeUpdateJsonContext : JsonSerializerContext;
