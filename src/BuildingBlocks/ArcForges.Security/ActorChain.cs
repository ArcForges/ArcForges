// SPDX-License-Identifier: AGPL-3.0-only
using System.Collections.ObjectModel;
using System.Security.Cryptography;
using System.Text;
using ArcForges.Contracts.Foundation.Values;
using ArcForges.Foundation.Execution;

namespace ArcForges.Security;

/// <summary>
/// Complete immutable provenance constructed at entry and passed explicitly through every layer.
/// Presence and structural validity confer neither authentication nor authorization.
/// </summary>
public sealed class ActorChain
{
    public const int MaximumDelegatedActors = 32;

    public ActorChain(HumanPrincipal owner, DeviceId device, InstallationId installation,
        SessionId session, InstanceId callerInstance, IEnumerable<DelegatedActor> actors)
    {
        ArgumentNullException.ThrowIfNull(owner);
        ArgumentNullException.ThrowIfNull(actors);
        _ = device.ToWire();
        _ = installation.ToWire();
        _ = session.ToWire();
        _ = callerInstance.ToWire();
        var entries = new List<DelegatedActor>();
        var identities = new HashSet<(ActorKind, Guid)>();
        foreach (var actor in actors)
        {
            ArgumentNullException.ThrowIfNull(actor);
            if (entries.Count == MaximumDelegatedActors || !identities.Add((actor.Kind, actor.ActorId)))
            {
                throw new ArgumentException("Actor chain is too long or contains a repeated actor.", nameof(actors));
            }

            entries.Add(actor);
        }

        Owner = owner;
        Device = device;
        Installation = installation;
        Session = session;
        CallerInstance = callerInstance;
        Actors = entries.AsReadOnly();
    }

    public HumanPrincipal Owner { get; }
    public DeviceId Device { get; }
    public InstallationId Installation { get; }
    public SessionId Session { get; }
    public InstanceId CallerInstance { get; }
    /// <summary>Delegation order from the human entry point to the final actor; never sorted or collapsed.</summary>
    public ReadOnlyCollection<DelegatedActor> Actors { get; }
}

/// <summary>
/// Explicit operation carrier, not an authorization grant. The later decision pipeline must still
/// authenticate and authorize; neither this chain nor its payload can authorize an operation.
/// </summary>
public sealed class ActorOperation<T>
{
    public ActorOperation(ActorChain actors, T payload)
    {
        ArgumentNullException.ThrowIfNull(actors);
        Actors = actors;
        Payload = payload;
    }

    public ActorChain Actors { get; }
    public T Payload { get; }

    /// <summary>Carry the identical chain into the next layer without reconstructing identities.</summary>
    public ActorOperation<TNext> Forward<TNext>(TNext payload) => new(Actors, payload);
}

/// <summary>
/// Immutable, non-authoritative provenance attached to instruction-bearing input. The digest binds
/// the origin, source reference, and captured text for corruption detection; it is not a signature.
/// </summary>
public sealed class InstructionProvenance
{
    internal InstructionProvenance(InstructionOrigin origin, string sourceReference, string inputSha256)
    {
        Origin = origin;
        SourceReference = sourceReference;
        InputSha256 = inputSha256;
        Trust = InstructionTrust.Untrusted;
    }

    public InstructionOrigin Origin { get; }
    public string SourceReference { get; }
    public string InputSha256 { get; }
    public InstructionTrust Trust { get; }
}

/// <summary>
/// Owned instruction-bearing text whose origin is always explicitly marked and untrusted.
/// Processing or forwarding this input does not grant permission to perform an operation.
/// </summary>
public sealed class InstructionInput
{
    private static readonly UTF8Encoding StrictUtf8 = new(false, true);

    private InstructionInput(string content, InstructionProvenance provenance)
    {
        Content = content;
        Provenance = provenance;
    }

    public string Content { get; }
    public InstructionProvenance Provenance { get; }

    /// <summary>Capture instruction-bearing text with an explicit source label and untrusted provenance.</summary>
    public static InstructionInput Capture(InstructionOrigin origin, string sourceReference, string content)
    {
        if (origin == InstructionOrigin.None || !Enum.IsDefined(origin))
        {
            throw new ArgumentOutOfRangeException(nameof(origin));
        }

        ArgumentException.ThrowIfNullOrWhiteSpace(sourceReference);
        if (sourceReference.Length > 512 || sourceReference.Any(char.IsControl))
        {
            throw new ArgumentException("Instruction source reference is invalid or too long.", nameof(sourceReference));
        }

        var sourceReferenceBytes = StrictUtf8.GetBytes(sourceReference);
        ArgumentNullException.ThrowIfNull(content);
        var contentBytes = StrictUtf8.GetBytes(content);
        var digest = ComputeInputSha256(origin, sourceReferenceBytes, contentBytes);
        return new InstructionInput(content, new InstructionProvenance(origin, sourceReference, digest));
    }

    internal static InstructionInput Restore(
        InstructionOrigin origin,
        string sourceReference,
        string content,
        string expectedInputSha256)
    {
        if (expectedInputSha256.Length != 64 || expectedInputSha256.Any(c => !IsUpperHex(c)))
        {
            throw new ArgumentException("Instruction provenance digest is not canonical SHA-256 hex.", nameof(expectedInputSha256));
        }

        var input = Capture(origin, sourceReference, content);
        if (!string.Equals(input.Provenance.InputSha256, expectedInputSha256, StringComparison.Ordinal))
        {
            throw new ArgumentException("Instruction input does not match its provenance digest.", nameof(expectedInputSha256));
        }

        return input;
    }

    private static string ComputeInputSha256(InstructionOrigin origin, byte[] sourceReference, byte[] content)
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        Span<byte> prefix = stackalloc byte[2];
        prefix[0] = checked((byte)origin);
        prefix[1] = 0;
        hash.AppendData(prefix);
        hash.AppendData(sourceReference);
        Span<byte> separator = stackalloc byte[1];
        separator[0] = 0;
        hash.AppendData(separator);
        hash.AppendData(content);
        return Convert.ToHexString(hash.GetHashAndReset());
    }

    private static bool IsUpperHex(char value) => value is >= '0' and <= '9' or >= 'A' and <= 'F';
}
