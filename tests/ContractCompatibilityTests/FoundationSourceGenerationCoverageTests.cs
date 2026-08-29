// SPDX-License-Identifier: AGPL-3.0-only

using System.Reflection;
using System.Text.Json.Serialization;
using System.Text.Json.Serialization.Metadata;
using ArcForges.Contracts.Foundation;

namespace ArcForges.Tests.ContractCompatibilityTests;

/// <summary>
/// Every wire type in <c>ArcForges.Contracts.Foundation</c> is registered in both source-generated contexts.
/// </summary>
/// <remarks>
/// <para>
/// This assertion is what makes "no reflection serialisation anywhere" enforceable rather than aspirational.
/// A type with no generated metadata either throws on first use or falls back to reflection, which breaks
/// Native AOT in the desktop heads. The failure has to surface here, in a test, not in a published app.
/// </para>
/// <para>
/// What it proves precisely is that every wire type <em>has generated metadata</em>, not that every one is
/// named in a <c>[JsonSerializable]</c> attribute. The generator also emits metadata for types reachable
/// from a registered root, so deleting the attribute for a type that is still reachable — say
/// <c>LocalResourceLocator</c>, reachable through <c>ResourceRef</c> — correctly does not fail: that type is
/// still compile-time generated and still AOT-safe. Having metadata is the property that matters. A type
/// that is neither listed nor reachable does fail, which is what caught <c>ErrorCategory</c> while this
/// substep was being written and what <see cref="AnUnregisteredTypeIsDetected"/> holds in place.
/// </para>
/// <para>
/// It lives in this assembly because the contexts are <c>internal</c> and this is one of the four projects
/// Step 02's Required Inputs grants access to. <c>ArcForges.Tests.ContractSchemaTests</c> deliberately has no
/// such grant and validates the golden files from the outside instead.
/// </para>
/// </remarks>
public sealed class FoundationSourceGenerationCoverageTests
{
    private static readonly Assembly Contracts = typeof(ResourceRef).Assembly;

    /// <summary>
    /// The types that must be registered: public records and enums that cross the wire.
    /// </summary>
    /// <remarks>
    /// Converters, static helpers and identity structs are excluded. An identity carries a
    /// <c>[JsonConverter]</c> and is only ever reached as a member of a registered type, so it needs no
    /// registration of its own; the enums do not, which is why they are included.
    /// </remarks>
    public static Xunit.TheoryData<Type> WireTypes()
    {
        var types = new Xunit.TheoryData<Type>();
        foreach (var type in Contracts.GetExportedTypes().Where(IsWireType).OrderBy(type => type.FullName, StringComparer.Ordinal))
        {
            types.Add(type);
        }

        return types;
    }

    [Xunit.Theory]
    [Xunit.MemberData(nameof(WireTypes))]
    [Xunit.Trait("Category", "Contract")]
    public void TheStrictContextRegistersTheType(Type type)
    {
        ArgumentNullException.ThrowIfNull(type);
        Xunit.Assert.True(
            IsRegistered(FoundationJsonContext.Default, type),
            $"{type.FullName} is not registered in FoundationJsonContext.");
    }

    [Xunit.Theory]
    [Xunit.MemberData(nameof(WireTypes))]
    [Xunit.Trait("Category", "Contract")]
    public void TheInboundContextRegistersTheType(Type type)
    {
        ArgumentNullException.ThrowIfNull(type);
        Xunit.Assert.True(
            IsRegistered(FoundationInboundJsonContext.Default, type),
            $"{type.FullName} is not registered in FoundationInboundJsonContext.");
    }

    [Xunit.Fact]
    [Xunit.Trait("Category", "Contract")]
    public void TheSurfaceBeingCheckedIsNotEmpty()
    {
        // Guards the theories above: a selector that matched nothing would let every one of them pass.
        var count = Contracts.GetExportedTypes().Count(IsWireType);
        Xunit.Assert.True(count >= 12, $"Only {count} wire types were discovered; the selector is wrong.");
    }

    [Xunit.Fact]
    [Xunit.Trait("Category", "Contract")]
    public void AnUnregisteredTypeIsDetected()
    {
        // Counter-evidence. This type is deliberately absent from both contexts; if the check could not see
        // that, none of the assertions above would mean anything.
        Xunit.Assert.False(
            IsRegistered(FoundationJsonContext.Default, typeof(UnregisteredProbe)),
            "The coverage check reports an unregistered type as registered.");
        Xunit.Assert.False(
            IsRegistered(FoundationInboundJsonContext.Default, typeof(UnregisteredProbe)),
            "The coverage check reports an unregistered type as registered.");
    }

    [Xunit.Fact]
    [Xunit.Trait("Category", "Contract")]
    public void BothContextsRegisterExactlyTheSameTypes()
    {
        // The two contexts differ in one option only. If their registrations drift, a type could be readable
        // strictly but not tolerantly, or the reverse, which is a silent asymmetry at the boundary.
        var strict = Contracts.GetExportedTypes().Where(IsWireType)
            .Where(type => IsRegistered(FoundationJsonContext.Default, type))
            .Select(type => type.FullName)
            .OrderBy(name => name, StringComparer.Ordinal);
        var inbound = Contracts.GetExportedTypes().Where(IsWireType)
            .Where(type => IsRegistered(FoundationInboundJsonContext.Default, type))
            .Select(type => type.FullName)
            .OrderBy(name => name, StringComparer.Ordinal);

        Xunit.Assert.Equal(strict, inbound);
    }

    [Xunit.Fact]
    [Xunit.Trait("Category", "Contract")]
    public void EachGenericWireTypeHasAtLeastOneRegisteredConstruction()
    {
        // Source generation cannot register an open generic, so every closed construction is listed by hand.
        // This checks the hand-maintained list has not been forgotten entirely for a generic type.
        Type[] openGenerics = [typeof(ArcResult<>), typeof(LocalPage<>), typeof(CursorPageDto<>)];

        foreach (var definition in openGenerics)
        {
            var registered = FoundationJsonContext.Default.GetType()
                .GetProperties(BindingFlags.Public | BindingFlags.Instance)
                .Select(property => property.PropertyType)
                .Where(type => type.IsGenericType && type.GetGenericTypeDefinition() == typeof(JsonTypeInfo<>))
                .Select(type => type.GetGenericArguments()[0])
                .Any(type => type.IsGenericType && type.GetGenericTypeDefinition() == definition);

            Xunit.Assert.True(registered, $"No closed construction of {definition.Name} is registered.");
        }
    }

    private static bool IsRegistered(JsonSerializerContext context, Type type) =>
        context.GetTypeInfo(type) is not null;

    private static bool IsWireType(Type type)
    {
        if (type.IsGenericTypeDefinition || typeof(JsonConverter).IsAssignableFrom(type))
        {
            return false;
        }

        if (type.IsEnum)
        {
            return true;
        }

        if (!type.IsClass || type.IsAbstract && type.IsSealed)
        {
            // Excludes static classes such as WellKnownProducts.
            return type.IsAbstract && !type.IsSealed && IsRecord(type);
        }

        return IsRecord(type);
    }

    private static bool IsRecord(Type type) =>
        type.GetMethod("<Clone>$", BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance) is not null
        || type.GetMethods(BindingFlags.Public | BindingFlags.Static)
            .Any(method => method.Name == "op_Equality" && method.GetParameters().Length == 2);
}

/// <summary>A wire-shaped type that is deliberately never registered, used as counter-evidence.</summary>
internal sealed record UnregisteredProbe
{
    public required string Value { get; init; }
}
