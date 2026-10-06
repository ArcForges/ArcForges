// SPDX-License-Identifier: AGPL-3.0-only
using System.Text;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Foundation.Values;
using ArcForges.Foundation.Errors;
using ArcForges.Security.Decisions;
using ArcForges.Security.Leases;
using Instant = ArcForges.Foundation.Instant;

namespace ArcForges.Security.Audit;

/// <summary>Closed immutable decision facts. Only the two production intake adapters can construct these details.</summary>
public abstract class AuditDecisionDetail
{
    private protected AuditDecisionDetail() { }
}

/// <summary>The original decision producer's complete fact, including its time and explicitly absent risk/software.</summary>
public sealed class AuditSecurityDecisionDetail : AuditDecisionDetail
{
    internal AuditSecurityDecisionDetail(SecurityAuditRecord record)
    {
        DecisionAuditValidation.Security(record);
        Record = record;
    }

    public SecurityAuditRecord Record { get; }
}

/// <summary>The complete result-recording fact; it contains no invocation payload.</summary>
public sealed class AuditDecisionResultDetail : AuditDecisionDetail
{
    internal AuditDecisionResultDetail(DecisionRecord record)
    {
        DecisionAuditValidation.Result(record);
        Record = record;
    }

    public DecisionRecord Record { get; }
}

internal static class DecisionAuditValidation
{
    internal static void Security(SecurityAuditRecord record)
    {
        ArgumentNullException.ThrowIfNull(record);
        ArgumentNullException.ThrowIfNull(record.Actors);
        ArgumentNullException.ThrowIfNull(record.Scope);
        ArgumentNullException.ThrowIfNull(record.Resource);
        ArgumentNullException.ThrowIfNull(record.ReasonCode);
        ArgumentNullException.ThrowIfNull(record.RegisteredCode);
        _ = new AuditCapabilityId(record.CapabilityKey);
        _ = record.Correlation.ToWire();
        _ = record.Device.ToWire();
        _ = record.Executor.ToWire();
        if (!AuditEnumValidation.IsWireValue(record.Kind) || !AuditEnumValidation.IsWireValue(record.Point)
            || record.Point == EnforcementPoint.CallerPreCheck || !AuditEnumValidation.IsWireValue(record.Origin)
            || !ValidEffect(record.Effect) || record.Lease is { IsValid: false }
            || record.EffectiveRisk is { } risk && !Enum.IsDefined(risk))
        {
            throw new ArgumentException("The security decision has an invalid closed fact.", nameof(record));
        }

        var last = record.Actors.Actors.Count == 0 ? null : record.Actors.Actors[^1];
        if (record.Executor != (last?.Executor ?? record.Actors.CallerInstance) || record.Device != record.Actors.Device
            || !StringComparer.Ordinal.Equals(record.SoftwareIdentity, last?.SoftwareIdentity))
        {
            throw new ArgumentException("Decision provenance contradicts its actor chain.", nameof(record));
        }

        if (record.Kind == SecurityAuditKind.Refused)
        {
            if (!DecisionProfiles.StepsFor(record.Point).Contains(record.FailedStep)
                || !DecisionReasons.All.Any(info => info.Step == record.FailedStep
                    && StringComparer.Ordinal.Equals(info.Code, record.ReasonCode)
                    && StringComparer.Ordinal.Equals(info.RegisteredCode, record.RegisteredCode))
                || record.Effect != EffectCertainty.DidNotHappen)
            {
                throw new ArgumentException("Refusal step, reason and effect must agree with the producer's decision.", nameof(record));
            }
        }
        else
        {
            var ownerFailureReason = DecisionReasons.Describe(DecisionReason.S12OwnerFailed).Code;
            if (record.Point != EnforcementPoint.OwnerFinalValidation || record.FailedStep != DecisionStep.None
                || record.EffectiveRisk is null
                || record.Kind == SecurityAuditKind.Executed && (record.ReasonCode.Length != 0
                    || record.RegisteredCode.Length != 0 || record.Effect != EffectCertainty.Happened)
                || record.Kind != SecurityAuditKind.Executed && !StringComparer.Ordinal.Equals(record.ReasonCode, ownerFailureReason)
                || record.Kind == SecurityAuditKind.OwnerFailed && !ReasonCodes.TryGet(record.RegisteredCode, out _)
                || record.Kind == SecurityAuditKind.OwnerCancelled && record.RegisteredCode.Length != 0)
            {
                throw new ArgumentException("Execution facts contradict the producer's closed outcome.", nameof(record));
            }
        }
    }

    internal static void Result(DecisionRecord record)
    {
        ArgumentNullException.ThrowIfNull(record);
        ArgumentNullException.ThrowIfNull(record.Resource);
        _ = record.CommandId.ToWire();
        _ = new AuditCapabilityId(record.CapabilityKey);
        if (!Enum.IsDefined(record.EffectiveRisk) || !AuditEnumValidation.IsWireValue(record.Result)
            || !ValidEffect(record.Effect)
            || record.Result == DecisionResultKind.Success && record.Effect != EffectCertainty.Happened
            || record.Result == DecisionResultKind.Failure && (record.FailureCode is null || !ReasonCodes.TryGet(record.FailureCode, out _))
            || record.Result != DecisionResultKind.Failure && record.FailureCode is not null)
        {
            throw new ArgumentException("Result kind, failure and effect must agree.", nameof(record));
        }
    }

    private static bool ValidEffect(EffectCertainty effect) =>
        effect is EffectCertainty.DidNotHappen or EffectCertainty.Happened or EffectCertainty.Unknown;

    internal static void Envelope(AuditEvent auditEvent)
    {
        if (auditEvent.DecisionDetail is AuditSecurityDecisionDetail security)
        {
            var record = security.Record;
            var software = record.SoftwareIdentity ?? auditEvent.SoftwareIdentity.Value;
            if (auditEvent.EventType != AuditEventType.SecurityDecision
                || !ActorChainSnapshot.Encode(auditEvent.ActorChain).AsSpan().SequenceEqual(ActorChainSnapshot.Encode(record.Actors))
                || auditEvent.SoftwareIdentity.Value != software || auditEvent.Executor != record.Executor
                || auditEvent.Capability.Value != record.CapabilityKey || auditEvent.Resource.Id != record.Correlation.Value
                || auditEvent.Correlation?.Value != record.Correlation.Value || auditEvent.Workspace != record.Scope.Workspace
                || auditEvent.Origin != (record.Origin == DecisionOrigin.Local ? AuditOrigin.Local : AuditOrigin.Remote)
                || auditEvent.Risk != (record.EffectiveRisk is { } risk ? AuditEnumValidation.FromRiskLevel(risk) : AuditRisk.NotAssessed)
                || auditEvent.Decision != (record.Kind == SecurityAuditKind.Refused ? AuditDecision.Denied : AuditDecision.Completed)
                || auditEvent.Reason != (record.Kind == SecurityAuditKind.Refused ? AuditDecisionReason.PolicyDenied : AuditDecisionReason.NotApplicable))
            {
                throw new ArgumentException("Security decision detail contradicts its envelope.", nameof(auditEvent));
            }
        }
        else if (auditEvent.DecisionDetail is AuditDecisionResultDetail result)
        {
            var record = result.Record;
            if (auditEvent.EventType != AuditEventType.InvocationResult || auditEvent.Capability.Value != record.CapabilityKey
                || auditEvent.Resource.Id != record.CommandId.Value || auditEvent.Correlation?.Value != record.CommandId.Value
                || auditEvent.Risk != AuditEnumValidation.FromRiskLevel(record.EffectiveRisk)
                || auditEvent.Decision != AuditDecision.Completed || auditEvent.Reason != AuditDecisionReason.NotApplicable)
            {
                throw new ArgumentException("Invocation result detail contradicts its envelope.", nameof(auditEvent));
            }
        }
    }
}

/// <summary>Bounded, versioned, closed binary format; neither JSON properties nor content can be appended.</summary>
internal static class DecisionAuditCodec
{
    private const int MaximumBytes = ActorChainSnapshot.MaximumBytes + 8192;
    private static readonly UTF8Encoding Encoding = new(false, true);

    internal static byte[] Encode(AuditDecisionDetail detail)
    {
        using var stream = new MemoryStream();
        using (var writer = new BinaryWriter(stream, Encoding, leaveOpen: true))
        {
            writer.Write("ArcForges.audit.decision.v1");
            switch (detail)
            {
                case AuditSecurityDecisionDetail security:
                    var record = security.Record;
                    writer.Write((byte)1);
                    writer.Write((int)record.Kind);
                    writer.Write((int)record.Point);
                    writer.Write((int)record.FailedStep);
                    writer.Write(record.ReasonCode);
                    writer.Write(record.RegisteredCode);
                    WriteTime(writer, record.OccurredAt);
                    var actors = ActorChainSnapshot.Encode(record.Actors);
                    writer.Write(actors.Length);
                    writer.Write(actors);
                    WriteGuid(writer, record.Executor.Value);
                    WriteText(writer, record.SoftwareIdentity);
                    writer.Write(record.CapabilityKey);
                    WriteResource(writer, record.Resource);
                    writer.Write(record.EffectiveRisk.HasValue);
                    if (record.EffectiveRisk is { } risk) writer.Write((int)risk);
                    writer.Write((int)record.Origin);
                    WriteGuid(writer, record.Device.Value);
                    WriteGuid(writer, record.Scope.Realm.Value);
                    WriteNullableGuid(writer, record.Scope.Workspace?.Value);
                    WriteGuid(writer, record.Correlation.Value);
                    writer.Write((int)record.Effect);
                    WriteNullableGuid(writer, record.Lease?.Value);
                    break;
                case AuditDecisionResultDetail result:
                    var outcome = result.Record;
                    writer.Write((byte)2);
                    WriteGuid(writer, outcome.CommandId.Value);
                    writer.Write(outcome.CapabilityKey);
                    WriteResource(writer, outcome.Resource);
                    writer.Write((int)outcome.EffectiveRisk);
                    writer.Write((int)outcome.Result);
                    WriteText(writer, outcome.FailureCode);
                    writer.Write((int)outcome.Effect);
                    WriteTime(writer, outcome.RecordedAt);
                    break;
                default:
                    throw new ArgumentException("Unknown decision detail.", nameof(detail));
            }
        }

        if (stream.Length > MaximumBytes) throw new ArgumentException("Decision detail exceeds its closed byte budget.", nameof(detail));
        return stream.ToArray();
    }

    internal static AuditDecisionDetail Decode(byte[] bytes)
    {
        if (bytes.Length is 0 or > MaximumBytes) throw new InvalidDataException("Invalid decision detail size.");
        try
        {
            using var stream = new MemoryStream(bytes, writable: false);
            using var reader = new BinaryReader(stream, Encoding);
            if (reader.ReadString() != "ArcForges.audit.decision.v1") throw new InvalidDataException("Unknown decision detail version.");
            AuditDecisionDetail detail;
            switch (reader.ReadByte())
            {
                case 1:
                    var kind = (SecurityAuditKind)reader.ReadInt32();
                    var point = (EnforcementPoint)reader.ReadInt32();
                    var step = (DecisionStep)reader.ReadInt32();
                    var reason = reader.ReadString();
                    var code = reader.ReadString();
                    var time = ReadTime(reader);
                    var actorLength = reader.ReadInt32();
                    if (actorLength is <= 0 or > ActorChainSnapshot.MaximumBytes) throw new InvalidDataException("Invalid actor detail size.");
                    var actors = ActorChainSnapshot.Decode(reader.ReadBytes(actorLength)).Chain;
                    var executor = new InstanceId(ReadGuid(reader));
                    var software = ReadText(reader);
                    var capability = reader.ReadString();
                    var resource = ReadResource(reader);
                    var risk = reader.ReadBoolean() ? (RiskLevel?)reader.ReadInt32() : null;
                    var origin = (DecisionOrigin)reader.ReadInt32();
                    var device = new DeviceId(ReadGuid(reader));
                    var realm = new RealmId(ReadGuid(reader));
                    var workspace = ReadNullableGuid(reader);
                    var correlation = new CommandId(ReadGuid(reader));
                    var effect = (EffectCertainty)reader.ReadInt32();
                    var lease = ReadNullableGuid(reader);
                    detail = new AuditSecurityDecisionDetail(new SecurityAuditRecord(kind, point, step, reason, code, time,
                        actors, executor, software, capability, resource, risk, origin, device,
                        new DecisionScope(realm, workspace is { } workspaceId ? new WorkspaceId(workspaceId) : null),
                        correlation, effect, lease is { } leaseId ? new CapabilityLeaseId(leaseId) : null));
                    break;
                case 2:
                    detail = new AuditDecisionResultDetail(new DecisionRecord(new CommandId(ReadGuid(reader)), reader.ReadString(),
                        ReadResource(reader), (RiskLevel)reader.ReadInt32(), (DecisionResultKind)reader.ReadInt32(), ReadText(reader),
                        (EffectCertainty)reader.ReadInt32(), ReadTime(reader)));
                    break;
                default:
                    throw new InvalidDataException("Unknown decision detail arm.");
            }

            if (stream.Position != stream.Length) throw new InvalidDataException("Trailing decision detail data.");
            // Refuse noncanonical Boolean encodings or any representation our own encoder cannot produce.
            if (!bytes.AsSpan().SequenceEqual(Encode(detail))) throw new InvalidDataException("Noncanonical decision detail.");
            return detail;
        }
        catch (Exception exception) when (exception is ArgumentException or IOException or OverflowException)
        {
            throw new InvalidDataException("Malformed closed decision detail.", exception);
        }
    }

    private static void WriteGuid(BinaryWriter writer, Guid value) => writer.Write(value.ToByteArray());
    private static Guid ReadGuid(BinaryReader reader) => new(reader.ReadBytes(16));
    private static void WriteNullableGuid(BinaryWriter writer, Guid? value)
    {
        writer.Write(value.HasValue);
        if (value is { } id) WriteGuid(writer, id);
    }
    private static Guid? ReadNullableGuid(BinaryReader reader) => reader.ReadBoolean() ? ReadGuid(reader) : null;
    private static void WriteText(BinaryWriter writer, string? value)
    {
        writer.Write(value is not null);
        if (value is not null) writer.Write(value);
    }
    private static string? ReadText(BinaryReader reader) => reader.ReadBoolean() ? reader.ReadString() : null;
    private static void WriteResource(BinaryWriter writer, ResourceReference resource)
    {
        writer.Write(resource.Id);
        writer.Write(resource.Revision);
    }
    private static ResourceReference ReadResource(BinaryReader reader) => new(reader.ReadString(), reader.ReadString());
    private static void WriteTime(BinaryWriter writer, Instant time)
    {
        writer.Write(time.UnixSeconds);
        writer.Write(time.Nanoseconds);
    }
    private static Instant ReadTime(BinaryReader reader) => new(reader.ReadInt64(), reader.ReadUInt32());
}
