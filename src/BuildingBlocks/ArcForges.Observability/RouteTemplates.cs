// SPDX-License-Identifier: AGPL-3.0-only
using System.Buffers;
using System.Collections.Concurrent;
namespace ArcForges.Observability;

/// <summary>One opaque identifier taken from a recorded route: the template slot it filled and its value.</summary>
public readonly record struct RouteIdentifier(string Slot, Guid Value);

/// <summary>
/// How a request URL is recorded (observability architecture RD-08): the registered route template plus the opaque
/// identifiers that filled its slots. Only <see cref="RouteTemplateSet"/> creates one; no raw URL, host, query
/// string, fragment, user information or free-text segment is ever stored.
/// </summary>
public sealed class RecordedRoute
{
    internal const string UnmatchedTemplate = "{unmatched}";

    internal RecordedRoute(string template, IReadOnlyList<RouteIdentifier> identifiers)
    {
        Template = template;
        Identifiers = identifiers;
    }

    /// <summary>The route recorded for a URL that matched no registered template. It carries no identifiers.</summary>
    public static RecordedRoute Unmatched { get; } = new(UnmatchedTemplate, []);

    /// <summary>The registered template, for example <c>/v1/workspaces/{workspace}/tasks/{task}</c>.</summary>
    public string Template { get; }

    /// <summary>The identifiers in template order. They belong on traces and log records, never on metrics.</summary>
    public IReadOnlyList<RouteIdentifier> Identifiers { get; }

    public bool IsMatched => !ReferenceEquals(this, Unmatched);
}

/// <summary>
/// A reviewed set of route templates. A URL is recorded as the template it matches; a slot accepts only a canonical
/// opaque identifier (a UUID), so a resource name, file path or token in the URL can never reach telemetry, and a
/// URL that fits no template is recorded as <see cref="RecordedRoute.Unmatched"/> rather than as text.
/// </summary>
public sealed class RouteTemplateSet
{
    private const int MaximumTargetLength = 2048;
    private const int MaximumTemplateLength = 256;
    private const int MaximumSegments = 16;
    private const int MaximumRegisteredTemplates = 4096;

    // Every template ever registered in this process. An exporter accepts an http.route value only if it is one of
    // these, so a foreign instrumentation tag cannot smuggle a path-shaped string through as a "template".
    private static readonly ConcurrentDictionary<string, byte> Registered = new(StringComparer.Ordinal);

    private static readonly SearchValues<char> SlotCharacters = SearchValues.Create("abcdefghijklmnopqrstuvwxyz0123456789");
    private static readonly SearchValues<char> LiteralCharacters = SearchValues.Create("abcdefghijklmnopqrstuvwxyz0123456789._-");

    private readonly Template[] _templates;

    private RouteTemplateSet(Template[] templates) => _templates = templates;

    /// <summary>
    /// Registers templates such as <c>/v1/workspaces/{workspace}/tasks/{task}</c>. Literal segments are lower-case
    /// words; slots are lower-case names. A slot name that is itself a known-sensitive field name, a duplicate slot in
    /// one template, or two templates of the same shape is refused.
    /// </summary>
    public static RouteTemplateSet Create(IEnumerable<string> templates)
    {
        ArgumentNullException.ThrowIfNull(templates);
        var parsed = new List<Template>();
        var shapes = new HashSet<string>(StringComparer.Ordinal);
        foreach (string text in templates)
        {
            Template template = Template.Parse(text);
            if (!shapes.Add(template.Shape))
            {
                throw new ArgumentException("Two route templates have the same shape.", nameof(templates));
            }

            parsed.Add(template);
        }

        if (parsed.Count == 0)
        {
            throw new ArgumentException("At least one route template is required.", nameof(templates));
        }

        int additional = parsed.Count(template => !Registered.ContainsKey(template.Text));
        if (Registered.Count + additional > MaximumRegisteredTemplates)
        {
            throw new InvalidOperationException("Too many distinct route templates are registered in this process.");
        }

        foreach (Template template in parsed)
        {
            Registered.TryAdd(template.Text, 0);
        }

        return new RouteTemplateSet(parsed.ToArray());
    }

    /// <summary>
    /// Maps a request target (an absolute URL, an absolute path, or a path with a query; for a <see cref="Uri"/> pass its
    /// <see cref="Uri.OriginalString"/>) to its recorded route. The scheme, authority, query and
    /// fragment are discarded unread. Anything that is not an exact match of one template becomes
    /// <see cref="RecordedRoute.Unmatched"/>; this method never throws for hostile input.
    /// </summary>
    public RecordedRoute Record(string? target)
    {
        if (!TryExtractSegments(target, out string[] segments))
        {
            return RecordedRoute.Unmatched;
        }

        foreach (Template template in _templates)
        {
            if (template.TryMatch(segments, out RouteIdentifier[]? identifiers))
            {
                return new RecordedRoute(template.Text, Array.AsReadOnly(identifiers!));
            }
        }

        return RecordedRoute.Unmatched;
    }

    /// <summary>A slot name is a short lower-case word that is not itself a sensitive field name.</summary>
    internal static bool IsValidSlotName(ReadOnlySpan<char> slot)
    {
        if (slot.Length is 0 or > 32 || slot[0] is < 'a' or > 'z' || slot.IndexOfAnyExcept(SlotCharacters) >= 0)
        {
            return false;
        }

        return !SensitiveFieldNames.IsSensitive(slot.ToString());
    }

    /// <summary>True for the unmatched marker or for a template some <see cref="RouteTemplateSet"/> registered.</summary>
    internal static bool IsValidRecordedTemplate(string value) =>
        string.Equals(value, RecordedRoute.UnmatchedTemplate, StringComparison.Ordinal) || Registered.ContainsKey(value);

    private static bool TryExtractSegments(string? target, out string[] segments)
    {
        segments = [];
        if (string.IsNullOrEmpty(target) || target.Length > MaximumTargetLength || target.Contains('\\', StringComparison.Ordinal))
        {
            return false;
        }

        foreach (char character in target)
        {
            if (char.IsControl(character) || char.IsWhiteSpace(character))
            {
                return false;
            }
        }

        ReadOnlySpan<char> rest = target;
        int end = rest.IndexOfAny('?', '#');
        if (end >= 0)
        {
            rest = rest[..end];
        }

        int scheme = rest.IndexOf("://", StringComparison.Ordinal);
        if (scheme > 0)
        {
            ReadOnlySpan<char> name = rest[..scheme];
            if (!name.Equals("http", StringComparison.OrdinalIgnoreCase) && !name.Equals("https", StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            rest = rest[(scheme + 3)..];
            int slash = rest.IndexOf('/');
            rest = slash < 0 ? "/".AsSpan() : rest[slash..];
        }

        if (rest.Length == 0 || rest[0] != '/' || rest.Length > 1 && rest[^1] == '/')
        {
            return false;
        }

        if (rest.IndexOfAny('%', ';') >= 0)
        {
            return false;
        }

        if (rest.Length == 1)
        {
            return true;
        }

        string[] parts = rest[1..].ToString().Split('/');
        if (parts.Length > MaximumSegments || parts.Any(part => part.Length == 0))
        {
            return false;
        }

        segments = parts;
        return true;
    }

    private sealed class Template
    {
        private readonly Segment[] _segments;

        private Template(string text, Segment[] segments, string shape)
        {
            Text = text;
            _segments = segments;
            Shape = shape;
        }

        public string Text { get; }

        /// <summary>The template with every slot name replaced, so interchangeable slot names collide.</summary>
        public string Shape { get; }

        public static Template Parse(string text)
        {
            ArgumentNullException.ThrowIfNull(text);
            if (text.Length is 0 or > MaximumTemplateLength || text[0] != '/' || text.Length > 1 && text[^1] == '/')
            {
                throw new ArgumentException("A route template is an absolute path of at most 256 characters without a trailing slash.", nameof(text));
            }

            string[] parts = text.Length == 1 ? [] : text[1..].Split('/');
            if (parts.Length > MaximumSegments)
            {
                throw new ArgumentException("A route template has too many segments.", nameof(text));
            }

            var segments = new Segment[parts.Length];
            var slots = new HashSet<string>(StringComparer.Ordinal);
            var shape = new System.Text.StringBuilder();
            for (int index = 0; index < parts.Length; index++)
            {
                string part = parts[index];
                shape.Append('/');
                if (part.Length > 2 && part[0] == '{' && part[^1] == '}')
                {
                    string slot = part[1..^1];
                    if (!IsValidSlotName(slot) || !slots.Add(slot))
                    {
                        throw new ArgumentException("A route slot is a unique lower-case word that is not a sensitive field name.", nameof(text));
                    }

                    segments[index] = new Segment(slot, true);
                    shape.Append('*');
                }
                else
                {
                    if (!IsLiteral(part))
                    {
                        throw new ArgumentException("A route literal is a lower-case word of letters, digits, '.', '_' or '-'.", nameof(text));
                    }

                    segments[index] = new Segment(part, false);
                    shape.Append(part);
                }
            }

            return new Template(text, segments, shape.ToString());
        }

        public bool TryMatch(string[] actual, out RouteIdentifier[]? identifiers)
        {
            identifiers = null;
            if (actual.Length != _segments.Length)
            {
                return false;
            }

            var found = new List<RouteIdentifier>();
            for (int index = 0; index < actual.Length; index++)
            {
                Segment expected = _segments[index];
                if (!expected.IsSlot)
                {
                    if (!string.Equals(actual[index], expected.Value, StringComparison.Ordinal))
                    {
                        return false;
                    }

                    continue;
                }

                if (!TryIdentifier(actual[index], out Guid value))
                {
                    return false;
                }

                found.Add(new RouteIdentifier(expected.Value, value));
            }

            identifiers = found.ToArray();
            return true;
        }

        private static bool IsLiteral(string value) =>
            value.Length is > 0 and <= 48 && value[0] is >= 'a' and <= 'z' or >= '0' and <= '9'
            && value.AsSpan().IndexOfAnyExcept(LiteralCharacters) < 0;

        private static bool TryIdentifier(string value, out Guid identifier)
        {
            identifier = Guid.Empty;
            if (value.Length is not (32 or 36))
            {
                return false;
            }

            string format = value.Length == 32 ? "N" : "D";
            return Guid.TryParseExact(value, format, out identifier) && identifier != Guid.Empty;
        }
    }

    private readonly record struct Segment(string Value, bool IsSlot);
}
