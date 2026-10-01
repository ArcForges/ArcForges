// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Reflection;
using Xunit;

namespace ArcForges.Observability.Tests;

[SuppressMessage("Performance", "CA1812", Justification = "The nested types are instantiated by reflection so the audit can inspect them.")]
[SuppressMessage("Trimming", "IL2026", Justification = "Test-only reflection over this assembly; tests are never trimmed.")]
[SuppressMessage("Trimming", "IL2067", Justification = "Test-only reflection; tests are never trimmed.")]
[SuppressMessage("Trimming", "IL2070", Justification = "Test-only reflection; tests are never trimmed.")]
[SuppressMessage("Trimming", "IL2072", Justification = "Test-only reflection; tests are never trimmed.")]
[SuppressMessage("Trimming", "IL2075", Justification = "Test-only reflection; tests are never trimmed.")]
[SuppressMessage("Performance", "CA1822", Justification = "The audited shapes must contain instance members.")]
public sealed class SensitiveTypeAuditTests
{
    [Fact]
    public void CompliantSecretAndContentTypesCannotBeLogged()
    {
        Assert.Empty(SensitiveTypeAudit.Find(typeof(OpaqueSecret), new OpaqueSecret()));
        Assert.Empty(SensitiveTypeAudit.Find(typeof(OpaqueBody), new OpaqueBody()));
        Assert.Empty(SensitiveTypeAudit.Find(typeof(SilentSecret)));
        Assert.Empty(SensitiveTypeAudit.Find(typeof(OpaqueStruct), new OpaqueStruct()));
    }

    [Theory]
    [InlineData(typeof(RecordContent), "is a record")]
    [InlineData(typeof(TextProperty), "TextProperty.Text exposes String")]
    [InlineData(typeof(ByteField), "ByteField.Bytes exposes Byte[]")]
    [InlineData(typeof(ByteSpanMethod), "ByteSpanMethod.Reveal returns ReadOnlySpan")]
    [InlineData(typeof(StreamMethod), "StreamMethod.Open returns Stream")]
    [InlineData(typeof(MemberCollection), "MemberCollection.Words exposes IReadOnlyList")]
    [InlineData(typeof(ObjectProperty), "ObjectProperty.Value exposes Object")]
    [InlineData(typeof(ExceptionProperty), "ExceptionProperty.Failure exposes Exception")]
    [InlineData(typeof(FormattableContent), "implements IFormattable")]
    [InlineData(typeof(SpanFormattableContent), "implements ISpanFormattable")]
    [InlineData(typeof(ConvertsToText), "ConvertsToText.op_Implicit returns String")]
    [InlineData(typeof(DebuggerDisplayContent), "declares DebuggerDisplay")]
    [InlineData(typeof(OpenContent), "must be a sealed concrete type")]
    [InlineData(typeof(DerivedContent), "derives from")]
    [InlineData(typeof(ProtectedText), "ProtectedText.Hidden exposes String")]
    public void AnythingAnExporterFormatterOrSerializerCouldReachIsReported(Type type, string expected)
    {
        ArgumentNullException.ThrowIfNull(type);
        IReadOnlyList<string> findings = SensitiveTypeAudit.Find(type, TryCreate(type));

        Assert.Contains(findings, finding => finding.Contains(expected, StringComparison.Ordinal));
    }

    [Fact]
    public void AToStringOverrideMustBeTheConstantRedactionObservedOnASample()
    {
        Assert.Contains(SensitiveTypeAudit.Find(typeof(LeakyToString), new LeakyToString("hello")),
            finding => finding.Contains("must be the constant 'LeakyToString:[redacted]'", StringComparison.Ordinal));
        Assert.Contains(SensitiveTypeAudit.Find(typeof(OpaqueSecret)),
            finding => finding.Contains("pass a sample instance", StringComparison.Ordinal));
        Assert.Throws<ArgumentException>(() => SensitiveTypeAudit.Find(typeof(OpaqueSecret), new OpaqueBody()));
        Assert.Throws<ArgumentNullException>(() => SensitiveTypeAudit.Find(null!));
    }

    [Fact]
    public void EveryTypeMarkedAsSensitiveInTheseAssembliesPassesTheAudit()
    {
        // The discovery loop a consumer repository runs over its own assemblies.
        var failures = new List<string>();
        int marked = 0;
        foreach (Assembly assembly in new[] { typeof(RedactionProcessor).Assembly, typeof(SensitiveTypeAuditTests).Assembly })
        {
            foreach (Type type in assembly.GetTypes().Where(candidate => candidate.GetCustomAttribute<SensitiveContentAttribute>() is not null))
            {
                marked++;
                failures.AddRange(SensitiveTypeAudit.Find(type, TryCreate(type)));
            }
        }

        Assert.Equal(4, marked);
        Assert.Empty(failures);
        Assert.Equal(SensitiveContentKind.Secret, typeof(OpaqueSecret).GetCustomAttribute<SensitiveContentAttribute>()!.Kind);
        Assert.Equal(SensitiveContentKind.UserContent, typeof(OpaqueBody).GetCustomAttribute<SensitiveContentAttribute>()!.Kind);
    }

    [Fact]
    public void TheTelemetryTypesThemselvesNeverHoldSecretOrContentText()
    {
        // The pipeline's own export carriers are plain values: no member returns a content-shaped buffer, and none
        // is a record whose generated ToString could print more than the reviewed fields.
        foreach (Type type in new[] { typeof(RecordedRoute), typeof(ScrubbedSpan), typeof(ScrubbedSpanEvent), typeof(StructuredSignal) })
        {
            Assert.DoesNotContain(type.GetMethods().Where(method => !method.IsSpecialName), method => method.ReturnType == typeof(byte[]) || method.ReturnType == typeof(Stream));
            Assert.Null(type.GetMethod("<Clone>$"));
        }
    }

    private static object? TryCreate(Type type) =>
        type.GetConstructor(BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic, Type.EmptyTypes) is { } constructor
            && !type.IsAbstract ? constructor.Invoke(null) : type.IsValueType ? Activator.CreateInstance(type) : null;

    [SensitiveContent(SensitiveContentKind.Secret)]
    private sealed class OpaqueSecret
    {
        internal Guid Id { get; } = Guid.NewGuid();

        public bool Matches(string candidate) => candidate.Length == Id.ToString().Length;

        public override string ToString() => "OpaqueSecret:[redacted]";
    }

    [SensitiveContent(SensitiveContentKind.UserContent)]
    private sealed class OpaqueBody
    {
        private readonly byte[] _bytes = [1, 2, 3];

        public int Length => _bytes.Length;

        public override string ToString() => "OpaqueBody:[redacted]";
    }

    [SensitiveContent(SensitiveContentKind.Secret)]
    private sealed class SilentSecret
    {
        private readonly string _value = "hidden";

        public bool IsEmpty => _value.Length == 0;
    }

    [SensitiveContent(SensitiveContentKind.UserContent)]
    private struct OpaqueStruct
    {
        public override readonly string ToString() => "OpaqueStruct:[redacted]";
    }

    private sealed record RecordContent(int Count);

    private sealed class TextProperty
    {
        public string Text { get; } = "text";
    }

    private sealed class ByteField
    {
        public readonly byte[] Bytes = [1];
    }

    private sealed class ByteSpanMethod
    {
        private readonly byte[] _bytes = [1];

        public ReadOnlySpan<byte> Reveal() => _bytes;
    }

    private sealed class StreamMethod
    {
        public Stream Open() => Stream.Null;
    }

    private sealed class MemberCollection
    {
        public IReadOnlyList<string> Words { get; } = ["a"];
    }

    private sealed class ObjectProperty
    {
        public object Value { get; } = new();
    }

    private sealed class ExceptionProperty
    {
        public Exception Failure { get; } = new InvalidOperationException();
    }

    private sealed class FormattableContent : IFormattable
    {
        public string ToString(string? format, IFormatProvider? formatProvider) => "x";
    }

    private sealed class SpanFormattableContent : ISpanFormattable
    {
        public string ToString(string? format, IFormatProvider? formatProvider) => "x";

        public bool TryFormat(Span<char> destination, out int charsWritten, ReadOnlySpan<char> format, IFormatProvider? provider)
        {
            charsWritten = 0;
            return true;
        }
    }

    private sealed class ConvertsToText
    {
        public static implicit operator string(ConvertsToText value) => value is null ? string.Empty : "x";
    }

    [DebuggerDisplay("{Secret}")]
    private sealed class DebuggerDisplayContent
    {
        private string Secret => "x";
    }

    private class OpenContent
    {
    }

    private sealed class DerivedContent : OpenContent
    {
    }

    private class ProtectedText
    {
        protected string Hidden { get; } = "x";
    }

    private sealed class DerivedProtectedText : ProtectedText
    {
    }

    private sealed class LeakyToString(string text)
    {
        public override string ToString() => text;
    }
}
