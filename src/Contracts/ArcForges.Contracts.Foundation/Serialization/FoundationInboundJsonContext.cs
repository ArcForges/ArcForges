// SPDX-License-Identifier: AGPL-3.0-only

using System.Text.Json.Serialization;

namespace ArcForges.Contracts.Foundation;

/// <summary>
/// The inbound source-generated serialisation context, tolerant of additive evolution.
/// </summary>
/// <remarks>
/// <para>
/// This is the second half of the pair. It differs from <see cref="FoundationJsonContext"/> in exactly one
/// dimension: <c>UnmappedMemberHandling.Skip</c>, so a document written by a newer peer that has added a
/// field still deserialises. Contract evolution is additive-only, which is only actually survivable if the
/// reading side ignores what it does not yet know.
/// </para>
/// <para>
/// Tolerance stops there. Duplicate properties are still rejected, property names are still case-sensitive,
/// nullable annotations are still respected and required members must still be present — an unknown *field*
/// is forward compatibility, whereas a duplicate key or a missing required member is a malformed document.
/// An unknown enum value or union discriminator is likewise still refused by its converter, because that is
/// a state this build cannot act on safely rather than a field it can ignore.
/// </para>
/// <para>
/// Registration must stay identical to <see cref="FoundationJsonContext"/>; the coverage assertion in
/// <c>ArcForges.Tests.ContractCompatibilityTests</c> compares the two.
/// </para>
/// </remarks>
[JsonSourceGenerationOptions(
    WriteIndented = false,
    PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase,
    PropertyNameCaseInsensitive = false,
    AllowDuplicateProperties = false,
    RespectNullableAnnotations = true,
    RespectRequiredConstructorParameters = true,
    DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    UnmappedMemberHandling = JsonUnmappedMemberHandling.Skip)]
// ErrorCategory is declared by this substep but not yet referenced by any DTO; Step 02.06 builds the
// error model on it. It is registered explicitly so it is serialisable the moment it is used, rather
// than depending on becoming reachable from some other registered type later.
[JsonSerializable(typeof(ErrorCategory))]
[JsonSerializable(typeof(ArcError))]
[JsonSerializable(typeof(ArcResult))]
[JsonSerializable(typeof(ResourceRef))]
[JsonSerializable(typeof(ArtifactRef))]
[JsonSerializable(typeof(LocalResourceLocator))]
[JsonSerializable(typeof(ArtifactProvenance))]
[JsonSerializable(typeof(LocalPageQuery))]
[JsonSerializable(typeof(ArcResult<ResourceRef>))]
[JsonSerializable(typeof(ArcResult<ArtifactRef>))]
[JsonSerializable(typeof(LocalPage<ResourceRef>))]
[JsonSerializable(typeof(LocalPage<ArtifactRef>))]
[JsonSerializable(typeof(CursorPageDto<ResourceRef>))]
[JsonSerializable(typeof(CursorPageDto<ArtifactRef>))]
internal partial class FoundationInboundJsonContext : JsonSerializerContext
{
}
