// SPDX-License-Identifier: AGPL-3.0-only

using System.Text.Json.Serialization;

namespace ArcForges.Contracts.Foundation;

/// <summary>
/// The stable identity of an installed ArcForges product or host.
/// </summary>
/// <remarks>
/// <para>
/// The seven wire values are closed (<c>implementation-repository-layout.md</c> §14.1). A third party cannot
/// mint one: the constructor rejects anything outside the set, so an unknown value fails at the boundary
/// rather than travelling as an unrecognised product.
/// </para>
/// <para>
/// This is the only nominal product-identity type in the repository. The concept appears as <c>AppId</c> in
/// source material and older discussion; target source, the public API, LocalRpc, Realtime, database mappers
/// and JSON Schema use <see cref="ProductId"/> exclusively.
/// </para>
/// <para>
/// A <see cref="ProductId"/> is not an <c>InstanceId</c> and not an OS process id: an installed product and a
/// runtime instance of it are separate facts (architecture §5.1).
/// </para>
/// <para>
/// Validation is inline. Contract assemblies do not reference <c>ArcForges.Foundation</c>'s Guard, so the
/// assembly keeps zero non-essential transitive dependencies (Step 01.03 constraint).
/// </para>
/// </remarks>
[JsonConverter(typeof(ProductIdJsonConverter))]
public readonly record struct ProductId
{
    public static readonly ProductId ArcChat = new(WellKnownProducts.ArcChat);
    public static readonly ProductId ArcNotes = new(WellKnownProducts.ArcNotes);
    public static readonly ProductId ArcScope = new(WellKnownProducts.ArcScope);
    public static readonly ProductId ArcSlate = new(WellKnownProducts.ArcSlate);
    public static readonly ProductId ArcChatMobile = new(WellKnownProducts.ArcChatMobile);
    public static readonly ProductId ArcForgesCloud = new(WellKnownProducts.ArcForgesCloud);
    public static readonly ProductId ArcForgesWeb = new(WellKnownProducts.ArcForgesWeb);

    public ProductId(string value) => Value = value switch
    {
        WellKnownProducts.ArcChat or WellKnownProducts.ArcNotes or WellKnownProducts.ArcScope
            or WellKnownProducts.ArcSlate or WellKnownProducts.ArcChatMobile
            or WellKnownProducts.ArcForgesCloud or WellKnownProducts.ArcForgesWeb => value,
        _ => throw new ArgumentOutOfRangeException(nameof(value), value, "Unknown product identity."),
    };

    /// <summary>The frozen wire value. Never null once the constructor has accepted it.</summary>
    public string Value { get; }

    /// <summary>True when this instance was produced by <c>default(ProductId)</c> and carries no identity.</summary>
    public bool IsEmpty => Value is null;

    public static ProductId Parse(string value) => new(value);

    public static bool TryParse(string? value, out ProductId product)
    {
        if (value is not null && WellKnownProducts.All.Contains(value, StringComparer.Ordinal))
        {
            product = new ProductId(value);
            return true;
        }

        product = default;
        return false;
    }

    /// <summary>
    /// True for the four products that can own a resource. Cloud and Web host resources but never own them,
    /// and the mobile head is a client; the <c>ResourceRef</c> owner validator accepts only these four.
    /// </summary>
    public bool CanOwnResources => Value is WellKnownProducts.ArcChat or WellKnownProducts.ArcNotes
        or WellKnownProducts.ArcScope or WellKnownProducts.ArcSlate;

    public override string ToString() => Value ?? string.Empty;
}

/// <summary>The seven frozen product wire values (<c>implementation-repository-layout.md</c> §14.1).</summary>
public static class WellKnownProducts
{
    public const string ArcChat = "arcchat";
    public const string ArcNotes = "arcnotes";
    public const string ArcScope = "arcscope";
    public const string ArcSlate = "arcslate";
    public const string ArcChatMobile = "arcchat-mobile";
    public const string ArcForgesCloud = "arcforges-cloud";
    public const string ArcForgesWeb = "arcforges-web";

    /// <summary>Every product wire value, in the order the layout table declares them.</summary>
    public static readonly IReadOnlyList<string> All =
    [
        ArcChat, ArcNotes, ArcScope, ArcSlate, ArcChatMobile, ArcForgesCloud, ArcForgesWeb,
    ];

    /// <summary>The four products that can own a resource.</summary>
    public static readonly IReadOnlyList<string> ResourceOwners = [ArcChat, ArcNotes, ArcScope, ArcSlate];
}
