// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Capabilities;
using ArcForges.Foundation.Errors;

namespace ArcForges.Desktop.Shell.Commands;

[Flags]
public enum CommandShortcutModifiers
{
    None = 0,
    Control = 1,
    Alt = 2,
    Shift = 4,
    Meta = 8,
}

/// <summary>A normalized keyboard gesture used for deterministic shortcut conflict detection.</summary>
public sealed record CommandShortcut
{
    private const CommandShortcutModifiers KnownModifiers =
        CommandShortcutModifiers.Control |
        CommandShortcutModifiers.Alt |
        CommandShortcutModifiers.Shift |
        CommandShortcutModifiers.Meta;

    private static readonly HashSet<string> NamedKeys = new(StringComparer.Ordinal)
    {
        "ARROWDOWN",
        "ARROWLEFT",
        "ARROWRIGHT",
        "ARROWUP",
        "BACKSPACE",
        "DELETE",
        "END",
        "ENTER",
        "ESCAPE",
        "HOME",
        "PAGEDOWN",
        "PAGEUP",
        "SPACE",
        "TAB",
    };

    public CommandShortcut(string key, CommandShortcutModifiers modifiers = CommandShortcutModifiers.None)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(key);
        if ((modifiers & ~KnownModifiers) != 0)
        {
            throw new ArgumentOutOfRangeException(nameof(modifiers));
        }

        string normalized = NormalizeKey(key);
        if (!IsSupportedKey(normalized))
        {
            throw new ArgumentException("A shortcut must use one supported key name.", nameof(key));
        }

        Key = normalized;
        Modifiers = modifiers;
    }

    public string Key { get; }

    public CommandShortcutModifiers Modifiers { get; }

    private static string NormalizeKey(string value)
    {
        string normalized = value.Trim().ToUpperInvariant();
        return normalized switch
        {
            "ESC" => "ESCAPE",
            "RETURN" => "ENTER",
            "DOWN" => "ARROWDOWN",
            "LEFT" => "ARROWLEFT",
            "RIGHT" => "ARROWRIGHT",
            "UP" => "ARROWUP",
            _ => normalized,
        };
    }

    private static bool IsSupportedKey(string value)
    {
        if (NamedKeys.Contains(value))
        {
            return true;
        }

        if (value.Length == 1 &&
            ((value[0] is >= 'A' and <= 'Z') || (value[0] is >= '0' and <= '9')))
        {
            return true;
        }

        return (value.Length is 2 or 3) &&
            value[0] == 'F' &&
            int.TryParse(value.AsSpan(1), System.Globalization.NumberStyles.None,
                System.Globalization.CultureInfo.InvariantCulture, out int functionKey) &&
            functionKey is >= 1 and <= 24 &&
            value == $"F{functionKey}";
    }
}

/// <summary>Immutable menu position for a command; menu content always comes from the registered command identity.</summary>
public sealed class ShellMenuPlacement
{
    public ShellMenuPlacement(string menuId, string sectionId, int order)
    {
        if (!IsMenuKey(menuId))
        {
            throw new ArgumentException("Menu IDs must be bounded lowercase dotted keys.", nameof(menuId));
        }

        if (!IsMenuKey(sectionId))
        {
            throw new ArgumentException("Menu section IDs must be bounded lowercase dotted keys.", nameof(sectionId));
        }

        if (order is < 0 or > 4096)
        {
            throw new ArgumentOutOfRangeException(nameof(order));
        }

        MenuId = menuId;
        SectionId = sectionId;
        Order = order;
    }

    public string MenuId { get; }

    public string SectionId { get; }

    public int Order { get; }

    private static bool IsMenuKey(string? value) =>
        !string.IsNullOrWhiteSpace(value) &&
        value.Length <= 96 &&
        (value[0] is >= 'a' and <= 'z' or >= '0' and <= '9') &&
        (value[^1] is >= 'a' and <= 'z' or >= '0' and <= '9') &&
        value.All(character => character is >= 'a' and <= 'z' or >= '0' and <= '9' or '.' or '-') &&
        !value.Contains("..", StringComparison.Ordinal) &&
        !value.Contains("--", StringComparison.Ordinal);
}

/// <summary>Immutable shell metadata bound to one canonical capability action.</summary>
public sealed class ShellCommand
{
    private readonly string[] _keywords;
    private readonly IReadOnlyList<string> _keywordView;

    public ShellCommand(
        string id,
        string title,
        ActionKey actionKey,
        string? description = "",
        IEnumerable<string>? keywords = null,
        CommandShortcut? shortcut = null,
        ShellMenuPlacement? menuPlacement = null)
    {
        if (!IsCommandId(id))
        {
            throw new ArgumentException("Command IDs must be bounded lowercase dotted keys.", nameof(id));
        }

        ArgumentNullException.ThrowIfNull(title);
        ValidateDisplayText(title, nameof(title), 128, allowEmpty: false);
        string safeDescription = description ?? string.Empty;
        ValidateDisplayText(safeDescription, nameof(description), 512, allowEmpty: true);
        ArgumentNullException.ThrowIfNull(actionKey);

        string[] keywordItems = (keywords ?? []).Take(33).ToArray();
        if (keywordItems.Length > 32 ||
            keywordItems.Any(keyword => !IsDisplayText(keyword, 80)) ||
            keywordItems.Distinct(StringComparer.OrdinalIgnoreCase).Count() != keywordItems.Length)
        {
            throw new ArgumentException("Command keywords must be at most 32 unique bounded text values.", nameof(keywords));
        }

        Id = id;
        Title = title;
        ActionKey = actionKey;
        Description = safeDescription;
        _keywords = keywordItems;
        _keywordView = Array.AsReadOnly(_keywords);
        Shortcut = shortcut;
        MenuPlacement = menuPlacement;
    }

    public string Id { get; }

    public string Title { get; }

    public ActionKey ActionKey { get; }

    public string Description { get; }

    public IReadOnlyList<string> Keywords => _keywordView;

    public CommandShortcut? Shortcut { get; }

    public ShellMenuPlacement? MenuPlacement { get; }

    internal IEnumerable<string> SearchTerms
    {
        get
        {
            yield return Id;
            yield return Title;
            if (Description.Length > 0)
            {
                yield return Description;
            }

            foreach (string keyword in _keywords)
            {
                yield return keyword;
            }
        }
    }

    private static bool IsCommandId(string? value) =>
        !string.IsNullOrWhiteSpace(value) &&
        value.Length <= 128 &&
        (value[0] is >= 'a' and <= 'z' or >= '0' and <= '9') &&
        (value[^1] is >= 'a' and <= 'z' or >= '0' and <= '9') &&
        value.All(character => character is >= 'a' and <= 'z' or >= '0' and <= '9' or '.' or '-') &&
        !value.Contains("..", StringComparison.Ordinal) &&
        !value.Contains("--", StringComparison.Ordinal);

    private static void ValidateDisplayText(string value, string parameterName, int maximumLength, bool allowEmpty)
    {
        if (allowEmpty && value.Length == 0)
        {
            return;
        }

        if (!IsDisplayText(value, maximumLength))
        {
            throw new ArgumentException("Display text must be bounded and contain no control characters.", parameterName);
        }
    }

    private static bool IsDisplayText(string? value, int maximumLength) =>
        !string.IsNullOrWhiteSpace(value) &&
        value.Length <= maximumLength &&
        value.All(character => !char.IsControl(character));
}

/// <summary>
/// Owns a bounded command registry, deterministic offline palette search, and the shared capability evaluator.
/// Registration is atomic: duplicate IDs or normalized shortcuts never partially alter the registry.
/// </summary>
public sealed class ShellCommandPalette
{
    private const int MaximumCommands = 256;
    private const int MaximumResults = 64;
    private const int DefaultResults = 32;

    private readonly object _gate = new();
    private readonly Dictionary<string, ShellCommand> _commands = new(StringComparer.Ordinal);
    private readonly Dictionary<CommandShortcut, string> _shortcuts = [];
    private readonly ICapabilityProvider _capabilityProvider;

    public ShellCommandPalette(ICapabilityProvider capabilityProvider)
    {
        _capabilityProvider = capabilityProvider ?? throw new ArgumentNullException(nameof(capabilityProvider));
    }

    /// <summary>Registers one command unless its ID, shortcut, or the bounded registry capacity conflicts.</summary>
    public bool TryRegister(ShellCommand command)
    {
        ArgumentNullException.ThrowIfNull(command);
        lock (_gate)
        {
            if (_commands.Count >= MaximumCommands || _commands.ContainsKey(command.Id))
            {
                return false;
            }

            if (command.Shortcut is not null && _shortcuts.ContainsKey(command.Shortcut))
            {
                return false;
            }

            _commands.Add(command.Id, command);
            if (command.Shortcut is not null)
            {
                _shortcuts.Add(command.Shortcut, command.Id);
            }

            return true;
        }
    }

    /// <summary>Returns a stable immutable snapshot ordered by command ID.</summary>
    public IReadOnlyList<ShellCommand> Snapshot()
    {
        lock (_gate)
        {
            return Array.AsReadOnly(_commands.Values
                .OrderBy(static command => command.Id, StringComparer.Ordinal)
                .ToArray());
        }
    }

    /// <summary>Returns registered menu commands in a stable menu, section, order, and command-ID order.</summary>
    public IReadOnlyList<ShellCommand> GetMenuContributions()
    {
        lock (_gate)
        {
            return Array.AsReadOnly(_commands.Values
                .Where(static command => command.MenuPlacement is not null)
                .OrderBy(static command => command.MenuPlacement!.MenuId, StringComparer.Ordinal)
                .ThenBy(static command => command.MenuPlacement!.SectionId, StringComparer.Ordinal)
                .ThenBy(static command => command.MenuPlacement!.Order)
                .ThenBy(static command => command.Id, StringComparer.Ordinal)
                .ToArray());
        }
    }

    /// <summary>Resolves a normalized shortcut to its registered command without dispatching it.</summary>
    public bool TryResolveShortcut(CommandShortcut shortcut, out ShellCommand? command)
    {
        ArgumentNullException.ThrowIfNull(shortcut);
        lock (_gate)
        {
            if (_shortcuts.TryGetValue(shortcut, out string? commandId) &&
                commandId is not null &&
                _commands.TryGetValue(commandId, out ShellCommand? registered) &&
                registered is not null)
            {
                command = registered;
                return true;
            }
        }

        command = null;
        return false;
    }

    /// <summary>Searches local command metadata only; it performs no availability evaluation or host I/O.</summary>
    public IReadOnlyList<ShellCommand> SearchPalette(string query, int maximumResults = DefaultResults)
    {
        ArgumentNullException.ThrowIfNull(query);
        if (query.Length > 256)
        {
            throw new ArgumentOutOfRangeException(nameof(query));
        }

        if (maximumResults is < 1 or > MaximumResults)
        {
            throw new ArgumentOutOfRangeException(nameof(maximumResults));
        }

        ShellCommand[] commands = Snapshot().ToArray();
        string[] tokens = query.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        if (tokens.Length == 0)
        {
            return Array.AsReadOnly(commands
                .OrderBy(static command => command.Title, StringComparer.OrdinalIgnoreCase)
                .ThenBy(static command => command.Id, StringComparer.Ordinal)
                .Take(maximumResults)
                .ToArray());
        }

        var matches = new List<(ShellCommand Command, int Rank)>();
        foreach (ShellCommand command in commands)
        {
            int rank = 0;
            bool matched = true;
            foreach (string token in tokens)
            {
                int tokenRank = RankToken(command, token);
                if (tokenRank == int.MaxValue)
                {
                    matched = false;
                    break;
                }

                rank += tokenRank;
            }

            if (matched)
            {
                matches.Add((command, rank));
            }
        }

        return Array.AsReadOnly(matches
            .OrderBy(static item => item.Rank)
            .ThenBy(static item => item.Command.Title, StringComparer.OrdinalIgnoreCase)
            .ThenBy(static item => item.Command.Id, StringComparer.Ordinal)
            .Take(maximumResults)
            .Select(static item => item.Command)
            .ToArray());
    }

    /// <summary>Delegates to the canonical capability evaluator without deriving availability in the shell.</summary>
    public ValueTask<Outcome<AvailabilityResult>> EvaluateAvailabilityAsync(
        string commandId,
        FrozenContextSnapshot context,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(commandId);
        ArgumentNullException.ThrowIfNull(context);

        ShellCommand? command;
        lock (_gate)
        {
            _commands.TryGetValue(commandId, out command);
        }

        return command is null
            ? ValueTask.FromResult(Outcome.Failure<AvailabilityResult>(TypedFailure.Create("validation.invalid_request")))
            : _capabilityProvider.EvaluateAvailabilityAsync(command.ActionKey, context, cancellationToken);
    }

    private static int RankToken(ShellCommand command, string token)
    {
        int rank = int.MaxValue;
        foreach (string term in command.SearchTerms)
        {
            if (string.Equals(term, token, StringComparison.OrdinalIgnoreCase))
            {
                return 0;
            }

            if (term.StartsWith(token, StringComparison.OrdinalIgnoreCase))
            {
                rank = Math.Min(rank, 1);
            }
            else if (term.Contains(token, StringComparison.OrdinalIgnoreCase))
            {
                rank = Math.Min(rank, 2);
            }
        }

        return rank;
    }
}
