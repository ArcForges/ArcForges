// SPDX-License-Identifier: AGPL-3.0-only

using System.Text.Json.Serialization;

namespace ArcForges.Contracts.Foundation;

/// <summary>
/// The strict source-generated serialisation context for this assembly's wire types.
/// </summary>
/// <remarks>
/// <para>
/// Reflection-based serialisation is not an option anywhere in the product: every wire type is registered in
/// a <see cref="JsonSerializerContext"/> so the desktop heads can be published Native AOT with no runtime
/// code generation and no assembly scanning.
/// </para>
/// <para>
/// This context is strict. <c>UnmappedMemberHandling.Disallow</c> makes an unexpected property an error, which
/// is what a contract owes its own tests: if this assembly emits a property the contract does not declare, a
/// round-trip here fails instead of quietly passing. It is deliberately <em>not</em> the context for reading
/// a peer that may be newer — that is <see cref="FoundationInboundJsonContext"/>.
/// </para>
/// <para>
/// The .NET 10 options are chosen so a malformed or ambiguous document is refused rather than guessed at:
/// duplicate properties are rejected, property names are case-sensitive, nullable annotations are respected
/// and required constructor parameters must be present.
/// </para>
/// <para>
/// <b>Registration is not optional.</b> Every new wire type in this assembly, and every new closed generic
/// instantiation of <see cref="ArcResult{T}"/>, <see cref="LocalPage{T}"/> or <see cref="CursorPageDto{T}"/>,
/// must be added here and to <see cref="FoundationInboundJsonContext"/>. Source generation cannot register an
/// open generic, so each closed construction is listed individually. A type that is missing is caught by the
/// coverage assertion in <c>ArcForges.Tests.ContractCompatibilityTests</c>, not at runtime.
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
    UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow)]
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
internal partial class FoundationJsonContext : JsonSerializerContext
{
}
