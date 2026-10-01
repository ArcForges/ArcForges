// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Reflection;

namespace ArcForges.Observability.Tests;

/// <summary>
/// The structural check that a secret-bearing or content type cannot be logged (observability RD-03, RD-04). A type
/// passes only when nothing a logger, a formatter or a serializer could reach exposes its value: it is sealed and is
/// not a record, it has no formatting interface, no public member that returns or holds text, bytes, spans, streams
/// or <see cref="object"/>, no conversion to such a type and no debugger display text, and its <c>ToString</c> is
/// either the runtime default (the type name) or the constant <c>Name:[redacted]</c>.
/// </summary>
[SuppressMessage("Trimming", "IL2026", Justification = "Test-only reflection; tests are never trimmed.")]
[SuppressMessage("Trimming", "IL2070", Justification = "Test-only reflection; tests are never trimmed.")]
[SuppressMessage("Trimming", "IL2072", Justification = "Test-only reflection; tests are never trimmed.")]
[SuppressMessage("Trimming", "IL2075", Justification = "Test-only reflection; tests are never trimmed.")]
internal static class SensitiveTypeAudit
{
    private const BindingFlags Surface = BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance | BindingFlags.Static | BindingFlags.DeclaredOnly;

    /// <summary>
    /// Returns every reason the type could be logged, or an empty list when it cannot. When the type overrides
    /// <c>ToString</c> a <paramref name="sample"/> instance is required so the constant redaction can be observed.
    /// </summary>
    public static IReadOnlyList<string> Find(Type type, object? sample = null)
    {
        ArgumentNullException.ThrowIfNull(type);
        var findings = new List<string>();
        string name = type.Name;

        if (!type.IsSealed || type.IsAbstract)
        {
            findings.Add($"{name} must be a sealed concrete type so a subtype cannot add a representation.");
        }

        if (type.BaseType != typeof(object) && type.BaseType != typeof(ValueType))
        {
            findings.Add($"{name} derives from {type.BaseType?.Name}; inherited members are not covered by this audit.");
        }

        if (type.GetMethod("<Clone>$", Surface) is not null)
        {
            findings.Add($"{name} is a record; its compiler-generated ToString, PrintMembers and Equals expose every member.");
        }

        foreach (Type contract in type.GetInterfaces())
        {
            if (contract == typeof(IFormattable) || contract == typeof(ISpanFormattable) || contract == typeof(IUtf8SpanFormattable))
            {
                findings.Add($"{name} implements {contract.Name}, a formatting representation.");
            }
        }

        if (type.GetCustomAttribute<DebuggerDisplayAttribute>() is not null)
        {
            findings.Add($"{name} declares DebuggerDisplay text.");
        }

        foreach (PropertyInfo property in type.GetProperties(Surface).Where(property => IsExposed(property.GetMethod ?? property.SetMethod)))
        {
            if (IsReadable(property.PropertyType))
            {
                findings.Add($"{name}.{property.Name} exposes {Describe(property.PropertyType)}.");
            }
        }

        foreach (FieldInfo field in type.GetFields(Surface).Where(field => field.IsPublic || field.IsFamily || field.IsFamilyOrAssembly))
        {
            if (IsReadable(field.FieldType))
            {
                findings.Add($"{name}.{field.Name} exposes {Describe(field.FieldType)}.");
            }
        }

        foreach (MethodInfo method in type.GetMethods(Surface).Where(method => !method.IsSpecialName || IsConversion(method)))
        {
            if (!IsExposed(method) && !IsExplicitInterfaceImplementation(method))
            {
                continue;
            }

            if (method.Name == nameof(ToString) && method.GetParameters().Length == 0)
            {
                CheckToString(type, sample, findings);
                continue;
            }

            if (IsReadable(method.ReturnType))
            {
                findings.Add($"{name}.{method.Name} returns {Describe(method.ReturnType)}.");
            }
        }

        return Array.AsReadOnly(findings.ToArray());
    }

    private static void CheckToString(Type type, object? sample, List<string> findings)
    {
        if (sample is null)
        {
            findings.Add($"{type.Name} overrides ToString; pass a sample instance so its constant redaction can be verified.");
            return;
        }

        if (!type.IsInstanceOfType(sample))
        {
            throw new ArgumentException("The sample is not an instance of the audited type.", nameof(sample));
        }

        string? text = sample.ToString();
        if (!string.Equals(text, type.Name + ":[redacted]", StringComparison.Ordinal))
        {
            findings.Add($"{type.Name}.ToString must be the constant '{type.Name}:[redacted]'.");
        }
    }

    private static bool IsExplicitInterfaceImplementation(MethodInfo method) => method.IsPrivate && method.IsFinal && method.Name.Contains('.', StringComparison.Ordinal);

    private static bool IsConversion(MethodInfo method) => method.Name is "op_Implicit" or "op_Explicit";

    private static bool IsExposed(MethodBase? method) =>
        method is not null && (method.IsPublic || method.IsFamily || method.IsFamilyOrAssembly);

    private static bool IsReadable(Type type)
    {
        if (type.IsByRef || type.IsPointer)
        {
            type = type.GetElementType()!;
        }

        if (type == typeof(string) || type == typeof(object) || type == typeof(char[]) || type == typeof(byte[])
            || type == typeof(Stream) || type.IsSubclassOf(typeof(Stream)) || type == typeof(Exception))
        {
            return true;
        }

        if (type.IsArray)
        {
            return IsReadable(type.GetElementType()!);
        }

        if (type == typeof(System.Text.StringBuilder) || typeof(TextReader).IsAssignableFrom(type) || typeof(TextWriter).IsAssignableFrom(type))
        {
            return true;
        }

        if (type == typeof(char) || type == typeof(byte))
        {
            return true;
        }

        if (type.IsGenericType)
        {
            Type definition = type.GetGenericTypeDefinition();
            bool buffer = definition == typeof(ReadOnlySpan<>) || definition == typeof(Span<>)
                || definition == typeof(ReadOnlyMemory<>) || definition == typeof(Memory<>)
                || definition == typeof(System.Buffers.ReadOnlySequence<>) || definition == typeof(Task<>) || definition == typeof(ValueTask<>)
                || definition == typeof(Lazy<>) || definition == typeof(Func<>);
            bool sequence = typeof(System.Collections.IEnumerable).IsAssignableFrom(type);
            if (buffer || sequence)
            {
                return type.GetGenericArguments().Any(IsReadable);
            }
        }

        return false;
    }

    private static string Describe(Type type) => type.IsGenericType ? type.Name[..type.Name.IndexOf('`', StringComparison.Ordinal)] + "<...>" : type.Name;
}
