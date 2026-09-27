// SPDX-License-Identifier: AGPL-3.0-only
using System.Globalization;
using ArcForges.Contracts.Foundation.Values;

namespace ArcForges.Persistence.Sqlite;

public enum StoreVersionKind
{
    Uninitialized,
    NewRoot,
    Cloud,
    Native,
    LocalProjection
}

public readonly record struct LocalProjectionVersion
{
    public LocalProjectionVersion(CloudRevision? acknowledgedRevision, long headLocalSequence)
    {
        if (acknowledgedRevision is { } revision) _ = revision.ToWire();
        ArgumentOutOfRangeException.ThrowIfNegative(headLocalSequence);
        AcknowledgedRevision = acknowledgedRevision;
        HeadLocalSequence = headLocalSequence;
    }

    public CloudRevision? AcknowledgedRevision { get; }
    public long HeadLocalSequence { get; }
}

/// <summary>The complete materialized version; a Cloud shadow alone never names pending local edits.</summary>
public readonly record struct StoreVersion
{
    private StoreVersion(StoreVersionKind kind, CloudRevision? cloud, NativeRevision? native, LocalProjectionVersion? local)
    {
        Kind = kind;
        CloudRevision = cloud;
        NativeRevision = native;
        LocalVersion = local;
    }

    public StoreVersionKind Kind { get; }
    public CloudRevision? CloudRevision { get; }
    public NativeRevision? NativeRevision { get; }
    public LocalProjectionVersion? LocalVersion { get; }
    public static StoreVersion NewRoot => new(StoreVersionKind.NewRoot, null, null, null);

    public static StoreVersion Cloud(CloudRevision value)
    {
        _ = value.ToWire();
        return new(StoreVersionKind.Cloud, value, null, null);
    }

    public static StoreVersion Native(NativeRevision value)
    {
        ArgumentOutOfRangeException.ThrowIfZero(value.Value);
        return new(StoreVersionKind.Native, null, value, null);
    }

    public static StoreVersion Local(CloudRevision? acknowledgedRevision, long headLocalSequence) =>
        new(StoreVersionKind.LocalProjection, null, null, new(acknowledgedRevision, headLocalSequence));

    public bool IsSuccessorOf(StoreVersion previous)
    {
        if (previous.Kind == StoreVersionKind.NewRoot)
            return Kind switch
            {
                StoreVersionKind.Cloud => CloudRevision!.Value.Value == 1,
                StoreVersionKind.Native => NativeRevision!.Value.Value == 1,
                StoreVersionKind.LocalProjection => LocalVersion!.Value is var local &&
                    ((local.AcknowledgedRevision is null && local.HeadLocalSequence == 1) ||
                     (local.AcknowledgedRevision is not null && local.HeadLocalSequence == 0)),
                _ => false
            };
        if (Kind != previous.Kind) return false;
        if (Kind == StoreVersionKind.Cloud)
            return previous.CloudRevision!.Value.Value < long.MaxValue && CloudRevision!.Value.Value == previous.CloudRevision.Value.Value + 1;
        if (Kind == StoreVersionKind.Native)
            return previous.NativeRevision!.Value.Value < ulong.MaxValue && NativeRevision!.Value.Value == previous.NativeRevision.Value.Value + 1;
        if (Kind != StoreVersionKind.LocalProjection) return false;
        var before = previous.LocalVersion!.Value;
        var after = LocalVersion!.Value;
        return (after.AcknowledgedRevision == before.AcknowledgedRevision && before.HeadLocalSequence < long.MaxValue &&
                after.HeadLocalSequence == before.HeadLocalSequence + 1) ||
               ((after.AcknowledgedRevision?.Value ?? 0) > (before.AcknowledgedRevision?.Value ?? 0) &&
                after.HeadLocalSequence == before.HeadLocalSequence);
    }

    public string CanonicalText => Kind switch
    {
        StoreVersionKind.NewRoot => "absent",
        StoreVersionKind.Cloud => "cloud:" + CloudRevision!.Value.Value.ToString(CultureInfo.InvariantCulture),
        StoreVersionKind.Native => "native:" + NativeRevision!.Value.Value.ToString(CultureInfo.InvariantCulture),
        StoreVersionKind.LocalProjection => "local:" + (LocalVersion!.Value.AcknowledgedRevision?.Value ?? 0).ToString(CultureInfo.InvariantCulture)
            + ":" + LocalVersion.Value.HeadLocalSequence.ToString(CultureInfo.InvariantCulture),
        _ => throw new InvalidOperationException("An uninitialized version is not a precondition.")
    };

    public static StoreVersion ParseCanonicalText(string value)
    {
        ArgumentNullException.ThrowIfNull(value);
        var parts = value.Split(':');
        if (parts is ["absent"]) return NewRoot;
        if (parts is ["cloud", var cloud]) return Cloud(new(ExactInteger.ParseInt64(cloud)));
        if (parts is ["native", var native]) return Native(new(ExactInteger.ParseUInt64(native)));
        if (parts is ["local", var acknowledged, var local])
        {
            var ack = ExactInteger.ParseInt64(acknowledged);
            ArgumentOutOfRangeException.ThrowIfNegative(ack);
            return Local(ack == 0 ? null : new CloudRevision(ack), ExactInteger.ParseInt64(local));
        }
        throw new FormatException("Unknown or malformed source version.");
    }
}
