// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics.CodeAnalysis;
using System.Reflection;
using Xunit;

namespace ArcForges.Observability.Tests;

/// <summary>
/// The structural half of redaction by construction: the telemetry emission surface has no parameter through which free
/// text, an arbitrary object or an exception message could be handed to a signal. Every public member that does accept
/// one of those is named here, with the reason it is a reviewed trust boundary, and the list is exact.
/// </summary>
[SuppressMessage("Trimming", "IL2026", Justification = "Test-only reflection over this repository's own assembly; tests are never trimmed.")]
[SuppressMessage("Trimming", "IL2075", Justification = "Test-only reflection over this repository's own assembly; tests are never trimmed.")]
public sealed class PublicSurfaceTests
{
    [Fact]
    public void FreeTextObjectsAndExceptionsAreAcceptedOnlyAtTheNamedReviewedBoundaries()
    {
        string[] accepting = AcceptingMembers(typeof(RedactionProcessor).Assembly).Order(StringComparer.Ordinal).ToArray();

        Assert.Equal(Reviewed.Order(StringComparer.Ordinal), accepting);
    }

    // Each entry is "Type.Member(parameter types)" and is a boundary where untrusted text is validated, mapped or discarded:
    private static readonly string[] Reviewed =
    [
        // RD-07: only the exception's runtime type is inspected; the message, data and stack are never read.
        "ExceptionReasonMapper..ctor(IEnumerable<KeyValuePair<Type, ReasonCode>>)",
        "ExceptionReasonMapper.Map(Exception)",
        "ObservabilityContext.WithFailure(Exception, ExceptionReasonMapper)",
        // PLT.51: a dependency name is a host-declared identifier reported on a probe result, never exported as a signal field.
        "HealthProbe.CheckReadiness(IEnumerable<String>, IEnumerable<RequiredDependencyObservation>)",
        "RequiredDependencyObservation..ctor(String, DependencyReadinessStatus)",
        "RequiredDependencyObservation.set_DependencyId(String)",
        // PLT.47: these three are refused at ObservabilityScope.Push unless they are a lowercase SHA-256 reference or a build-policy stamp.
        "ObservabilityContext.set_ActorReference(String)",
        "ObservabilityContext.set_NativeAbiBuildId(String)",
        "ObservabilityContext.set_RedactedResourceReference(String)",
        // RD-05: the scrubbing processor itself receives arbitrary fields precisely to remove them.
        "RedactionProcessor.IsSensitiveFieldName(String)",
        "RedactionProcessor.ScrubFields(IEnumerable<KeyValuePair<String, Object>>)",
        // RD-08: a request target is reduced to a registered template and opaque identifiers; the text is never kept.
        "RouteIdentifier..ctor(String, Guid)",
        "RouteIdentifier.set_Slot(String)",
        "RouteTemplateSet.Create(IEnumerable<String>)",
        "RouteTemplateSet.Record(String)",
    ];

    private static IEnumerable<string> AcceptingMembers(Assembly assembly)
    {
        const BindingFlags Public = BindingFlags.Public | BindingFlags.Instance | BindingFlags.Static | BindingFlags.DeclaredOnly;
        foreach (Type type in assembly.GetExportedTypes())
        {
            var members = new List<MethodBase>(type.GetConstructors());
            members.AddRange(type.GetMethods(Public).Where(method => method.Name is not ("Equals" or "GetHashCode" or "ToString" or "Deconstruct" or "<Clone>$")));
            foreach (MethodBase member in members)
            {
                if (member is MethodInfo { IsSpecialName: true } special && !special.Name.StartsWith("set_", StringComparison.Ordinal)
                    && !special.Name.StartsWith("op_", StringComparison.Ordinal))
                {
                    continue;
                }

                string[] textual = member.GetParameters().Where(parameter => IsFreeForm(parameter.ParameterType))
                    .Select(parameter => Display(parameter.ParameterType)).ToArray();
                if (textual.Length > 0)
                {
                    yield return $"{type.Name}.{(member.IsConstructor ? ".ctor" : member.Name)}({string.Join(", ", member.GetParameters().Select(parameter => Display(parameter.ParameterType)))})";
                }
            }
        }
    }

    private static bool IsFreeForm(Type type)
    {
        if (type.IsByRef)
        {
            type = type.GetElementType()!;
        }

        if (type == typeof(string) || type == typeof(object) || type == typeof(Exception) || type == typeof(Uri) || type == typeof(char)
            || type == typeof(Type))
        {
            return true;
        }

        if (type.IsArray)
        {
            return IsFreeForm(type.GetElementType()!) || type.GetElementType() == typeof(byte);
        }

        return type.IsGenericType && type.GetGenericArguments().Any(argument => IsFreeForm(argument) || argument == typeof(byte));
    }

    private static string Display(Type type) => type.IsGenericType
        ? type.Name[..type.Name.IndexOf('`', StringComparison.Ordinal)] + "<" + string.Join(", ", type.GetGenericArguments().Select(Display)) + ">"
        : type.Name;
}
