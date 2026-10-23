// SPDX-License-Identifier: AGPL-3.0-only
using System.Globalization;

namespace ArcForges.Node.Core.Scheduling;

/// <summary>How a task holds a key (node-store.md <c>task_concurrency_key.mode</c>).</summary>
public enum KeyMode
{
    /// <summary>A writer: conflicts with every overlapping key.</summary>
    Exclusive = 1,

    /// <summary>A reader: conflicts only with exclusive holders of an overlapping key.</summary>
    Shared = 2,
}

/// <summary>Where a key came from (node-store.md <c>task_concurrency_key.source</c>).</summary>
public enum KeySource
{
    /// <summary>The caller's <c>TaskSpec.concurrency</c>.</summary>
    Caller = 1,

    /// <summary>The adapter of the tool and operation (05 sections 2-3).</summary>
    Adapter = 2,

    /// <summary><c>access = EXCLUSIVE</c> or the workspace's concurrency mode <c>SERIAL</c>.</summary>
    Workspace = 3,
}

/// <summary>The kinds of key of 03 section 4.</summary>
public enum KeyKind
{
    /// <summary><c>ws:&lt;workspace&gt;</c>: overlaps every key of that workspace.</summary>
    Workspace,

    /// <summary><c>ws:&lt;workspace&gt;/&lt;dir&gt;[:&lt;purpose&gt;]</c> (or <c>ws:&lt;workspace&gt;:&lt;purpose&gt;</c> for the root directory).</summary>
    Directory,

    /// <summary><c>tool:&lt;name&gt;:&lt;scope&gt;</c>: a tool's own state.</summary>
    Tool,

    /// <summary><c>name:&lt;text&gt;</c>.</summary>
    Name,
}

/// <summary>
/// A parsed concurrency key (03 section 4 "Workspace concurrency and keys"; tasks.proto <c>ConcurrencySpec</c>). Directory paths are
/// workspace-relative with <c>/</c> separators, without empty, <c>.</c> or <c>..</c> segments.
/// </summary>
public sealed record ConcurrencyKey
{
    /// <summary>The longest key text (tasks.proto: 200 characters).</summary>
    public const int MaxLength = 200;

    private ConcurrencyKey(string text, KeyKind kind)
    {
        Text = text;
        Kind = kind;
    }

    /// <summary>The canonical text.</summary>
    public string Text { get; }

    /// <summary>The kind.</summary>
    public KeyKind Kind { get; }

    /// <summary>The workspace of a workspace or directory key.</summary>
    public string Workspace { get; private init; } = string.Empty;

    /// <summary>The directory segments of a directory key (empty for the workspace root).</summary>
    public IReadOnlyList<string> Directory { get; private init; } = [];

    /// <summary>The purpose of a directory key (<c>deps</c>), or <see langword="null"/>.</summary>
    public string? Purpose { get; private init; }

    /// <summary>The tool of a tool key.</summary>
    public string Tool { get; private init; } = string.Empty;

    /// <summary>The scope of a tool key (a workspace, a directory in one, or a path).</summary>
    public string Scope { get; private init; } = string.Empty;

    /// <summary>The text of a name key.</summary>
    public string Name { get; private init; } = string.Empty;

    /// <summary>The workspace key <c>ws:&lt;workspace&gt;</c>.</summary>
    public static ConcurrencyKey ForWorkspace(string workspace) => Parse("ws:" + workspace);

    /// <summary>Parses a key; throws <see cref="FormatException"/> with the rule it broke.</summary>
    public static ConcurrencyKey Parse(string text) =>
        TryParse(text, out var key, out var error) ? key! : throw new FormatException(error);

    /// <summary>Parses a key; on failure <paramref name="error"/> says which rule it broke.</summary>
    public static bool TryParse(string? text, out ConcurrencyKey? key, out string error)
    {
        key = null;
        error = string.Empty;
        if (string.IsNullOrEmpty(text) || text.Length > MaxLength)
        {
            error = "a key has 1..200 characters";
            return false;
        }

        if (text.Any(char.IsControl))
        {
            error = "a key contains no control characters";
            return false;
        }

        if (text.StartsWith("name:", StringComparison.Ordinal))
        {
            var name = text[5..];
            if (name.Length == 0)
            {
                error = "name:<text> needs a text";
                return false;
            }

            key = new ConcurrencyKey(text, KeyKind.Name) { Name = name };
            return true;
        }

        if (text.StartsWith("tool:", StringComparison.Ordinal))
        {
            var rest = text[5..];
            var colon = rest.IndexOf(':', StringComparison.Ordinal);
            if (colon <= 0 || colon == rest.Length - 1)
            {
                error = "tool:<name>:<scope> needs a tool name and a scope";
                return false;
            }

            var scope = rest[(colon + 1)..].Replace('\\', '/').TrimEnd('/');
            key = new ConcurrencyKey("tool:" + rest[..colon] + ":" + scope, KeyKind.Tool) { Tool = rest[..colon], Scope = scope };
            return true;
        }

        if (!text.StartsWith("ws:", StringComparison.Ordinal))
        {
            error = "a key is ws:<workspace>[/<relative dir>][:<purpose>], tool:<name>:<scope> or name:<text>";
            return false;
        }

        var body = text[3..].Replace('\\', '/');
        var end = body.IndexOfAny(['/', ':']);
        var workspace = end < 0 ? body : body[..end];
        if (workspace.Length == 0)
        {
            error = "ws:<workspace> needs a workspace";
            return false;
        }

        if (end < 0)
        {
            key = new ConcurrencyKey("ws:" + workspace, KeyKind.Workspace) { Workspace = workspace };
            return true;
        }

        var remainder = body[end..];
        string? purpose = null;
        var path = string.Empty;
        if (remainder[0] == ':')
        {
            purpose = remainder[1..];
        }
        else
        {
            var lastColon = remainder.LastIndexOf(':');
            if (lastColon > 0)
            {
                purpose = remainder[(lastColon + 1)..];
                path = remainder[1..lastColon];
            }
            else
            {
                path = remainder[1..];
            }
        }

        if (purpose is not null && (purpose.Length == 0 || purpose.Contains('/', StringComparison.Ordinal)))
        {
            error = "a purpose (after ':') is a non-empty word";
            return false;
        }

        var segments = new List<string>();
        foreach (var segment in path.Replace('\\', '/').Split('/', StringSplitOptions.RemoveEmptyEntries))
        {
            if (segment == ".")
            {
                continue;
            }

            if (segment == "..")
            {
                error = "a key's directory is relative to its workspace and never leaves it ('..')";
                return false;
            }

            segments.Add(segment);
        }

        if (segments.Count == 0 && purpose is null)
        {
            key = new ConcurrencyKey("ws:" + workspace, KeyKind.Workspace) { Workspace = workspace };
            return true;
        }

        var canonical = "ws:" + workspace + (segments.Count > 0 ? "/" + string.Join('/', segments) : string.Empty) + (purpose is null ? string.Empty : ":" + purpose);
        key = new ConcurrencyKey(canonical, KeyKind.Directory) { Workspace = workspace, Directory = segments, Purpose = purpose };
        return true;
    }

    /// <summary>
    /// The overlap rule of 03 section 4: directory keys of one workspace overlap when one directory is the other's, an ancestor or a
    /// descendant, unless both carry a purpose and the purposes differ; tool keys overlap only the same tool key; the workspace key
    /// overlaps every key of its workspace, including tool keys whose scope is the workspace or a directory in it; name keys overlap only
    /// the same name. <paramref name="workspaceRoot"/> resolves a workspace to its root path, so a tool key scoped by an absolute path inside
    /// it is recognised (null when unknown).
    /// </summary>
    public bool Overlaps(ConcurrencyKey other, Func<string, string?>? workspaceRoot = null)
    {
        ArgumentNullException.ThrowIfNull(other);
        if (Kind == KeyKind.Workspace || other.Kind == KeyKind.Workspace)
        {
            var (workspace, key) = Kind == KeyKind.Workspace ? (this, other) : (other, this);
            return key.Kind switch
            {
                KeyKind.Workspace or KeyKind.Directory => Same(workspace.Workspace, key.Workspace),
                KeyKind.Tool => ScopeIn(key.Scope, workspace.Workspace, workspaceRoot),
                _ => false,
            };
        }

        if (Kind != other.Kind)
        {
            return false;
        }

        return Kind switch
        {
            KeyKind.Tool => string.Equals(Tool, other.Tool, StringComparison.Ordinal) && SamePath(Scope, other.Scope),
            KeyKind.Name => string.Equals(Name, other.Name, StringComparison.Ordinal),
            _ => Same(Workspace, other.Workspace) && Nested(Directory, other.Directory)
                && !(Purpose is not null && other.Purpose is not null && !string.Equals(Purpose, other.Purpose, StringComparison.Ordinal)),
        };
    }

    /// <inheritdoc />
    public override string ToString() => Text;

    private static StringComparison PathComparison => OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;

    private static bool Same(string left, string right) => string.Equals(left, right, StringComparison.OrdinalIgnoreCase);

    private static bool SamePath(string left, string right) => string.Equals(left, right, PathComparison);

    private static bool Nested(IReadOnlyList<string> left, IReadOnlyList<string> right)
    {
        var shorter = Math.Min(left.Count, right.Count);
        for (var index = 0; index < shorter; index++)
        {
            if (!string.Equals(left[index], right[index], PathComparison))
            {
                return false;
            }
        }

        return true;
    }

    private static bool ScopeIn(string scope, string workspace, Func<string, string?>? workspaceRoot)
    {
        if (Same(scope, workspace) || scope.StartsWith(workspace + "/", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        if (workspaceRoot?.Invoke(workspace) is not { Length: > 0 } root)
        {
            return false;
        }

        var normalized = root.Replace('\\', '/').TrimEnd('/');
        return SamePath(scope, normalized) || scope.StartsWith(normalized + "/", PathComparison);
    }
}

/// <summary>A key a task holds or asks for.</summary>
/// <param name="Key">The key.</param>
/// <param name="Mode">Exclusive or shared.</param>
/// <param name="Source">Where it came from.</param>
public sealed record HeldKey(ConcurrencyKey Key, KeyMode Mode, KeySource Source);

/// <summary>A conflict of a candidate's keys with keys running attempts hold (03 section 4: blocking reason <c>exclusive_key</c>).</summary>
/// <param name="Keys">The held keys in conflict (the holders' key text).</param>
/// <param name="Holders">The tasks holding them.</param>
public sealed record KeyConflict(IReadOnlyList<string> Keys, IReadOnlyList<string> Holders);

/// <summary>
/// The keys running attempts hold (rebuilt from <c>task_concurrency_key</c> after a restart): the conflict rule of 03 section 4 is
/// "overlapping keys conflict unless both are shared".
/// </summary>
public sealed class KeyHolders
{
    private readonly List<(string Task, HeldKey Key)> _held = [];
    private readonly Func<string, string?>? _workspaceRoot;

    /// <summary>Creates an empty set.</summary>
    public KeyHolders(Func<string, string?>? workspaceRoot = null) => _workspaceRoot = workspaceRoot;

    /// <summary>The held keys.</summary>
    public IReadOnlyList<(string Task, HeldKey Key)> Held => _held;

    /// <summary>Adds the keys a task now holds.</summary>
    public void Add(string task, IEnumerable<HeldKey> keys)
    {
        ArgumentNullException.ThrowIfNull(keys);
        foreach (var key in keys)
        {
            _held.Add((task, key));
        }
    }

    /// <summary>The conflict of <paramref name="keys"/> (a candidate's) with the held keys, or <see langword="null"/>.</summary>
    public KeyConflict? Conflict(string task, IReadOnlyCollection<HeldKey> keys)
    {
        ArgumentNullException.ThrowIfNull(keys);
        if (keys.Count == 0 || _held.Count == 0)
        {
            return null;
        }

        var blocking = new SortedSet<string>(StringComparer.Ordinal);
        var holders = new SortedSet<string>(StringComparer.Ordinal);
        foreach (var wanted in keys)
        {
            foreach (var (holder, held) in _held)
            {
                if (holder == task || (wanted.Mode == KeyMode.Shared && held.Mode == KeyMode.Shared) || !wanted.Key.Overlaps(held.Key, _workspaceRoot))
                {
                    continue;
                }

                blocking.Add(held.Key.Text);
                holders.Add(holder);
            }
        }

        return blocking.Count == 0 ? null : new KeyConflict([.. blocking], [.. holders]);
    }

    /// <summary>The caller keys of a spec, validated (tasks.proto: at most 16 of each mode); the error names the field and rule.</summary>
    public static (List<HeldKey> Keys, string? Error) FromSpec(IReadOnlyList<string> exclusive, IReadOnlyList<string> shared)
    {
        ArgumentNullException.ThrowIfNull(exclusive);
        ArgumentNullException.ThrowIfNull(shared);
        if (exclusive.Count > 16 || shared.Count > 16)
        {
            return ([], "concurrency: <= 16 exclusive_keys and <= 16 shared_keys");
        }

        var keys = new List<HeldKey>();
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var (texts, mode, field) in new[] { (exclusive, KeyMode.Exclusive, "exclusive_keys"), (shared, KeyMode.Shared, "shared_keys") })
        {
            for (var index = 0; index < texts.Count; index++)
            {
                if (!ConcurrencyKey.TryParse(texts[index], out var key, out var error))
                {
                    return ([], string.Create(CultureInfo.InvariantCulture, $"concurrency.{field}[{index}]: {error}"));
                }

                if (!seen.Add(key!.Text))
                {
                    return ([], string.Create(CultureInfo.InvariantCulture, $"concurrency.{field}[{index}]: '{key.Text}' is listed twice"));
                }

                keys.Add(new HeldKey(key, mode, KeySource.Caller));
            }
        }

        return (keys, null);
    }
}
