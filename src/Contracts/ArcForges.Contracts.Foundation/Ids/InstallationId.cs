// SPDX-License-Identifier: AGPL-3.0-only

using System.Globalization;
using System.Text.Json.Serialization;

namespace ArcForges.Contracts.Foundation;

/// <summary>Identifies one installation of the product family on one device (architecture §5.1).</summary>
/// <remarks>
/// <para>An installation outlives every process and every upgrade on that device. It is not a device identity: <c>DeviceId</c> is the account-visible device, while an installation is local to the install.</para>
/// </remarks>
[JsonConverter(typeof(InstallationIdJsonConverter))]
public readonly record struct InstallationId(Guid Value)
{
    /// <summary>A new identity. Version 7 so the value sorts by creation time.</summary>
    public static InstallationId New() => new(Guid.CreateVersion7());

    /// <summary>Parses a canonical GUID string, throwing on anything else.</summary>
    /// <exception cref="ArgumentException">The text is not a GUID.</exception>
    public static InstallationId Parse(string s) => new(Guid.Parse(s));

    public static bool TryParse(string? s, out InstallationId id)
    {
        if (Guid.TryParse(s, out var value))
        {
            id = new InstallationId(value);
            return true;
        }

        id = default;
        return false;
    }

    /// <summary>True when this is <c>default</c> and therefore carries no identity.</summary>
    public bool IsEmpty => Value == Guid.Empty;

    public override string ToString() => Value.ToString("D", CultureInfo.InvariantCulture);
}

/// <summary>Serialises <see cref="InstallationId"/> as a bare canonical GUID string.</summary>
public sealed class InstallationIdJsonConverter : GuidIdJsonConverter<InstallationId>
{
    protected override InstallationId FromGuid(Guid value) => new(value);

    protected override Guid ToGuid(InstallationId value) => value.Value;
}
