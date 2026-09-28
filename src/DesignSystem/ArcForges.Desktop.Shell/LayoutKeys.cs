// SPDX-License-Identifier: AGPL-3.0-only
namespace ArcForges.Desktop.Shell;

/// <summary>A validated, non-path application identity used to isolate device-local layouts.</summary>
public sealed record ApplicationKey
{
    private ApplicationKey(string value) => Value = value;

    public string Value { get; }

    public static ApplicationKey Parse(string value)
        => TryParse(value) ?? throw new ArgumentException("Application keys must be lower-case kebab-case identifiers.", nameof(value));

    public static ApplicationKey? TryParse(string? value)
        => StableKey.IsValid(value) ? new ApplicationKey(value!) : null;
}

/// <summary>A validated, non-path identifier for one saved layout within an application.</summary>
public sealed record LayoutKey
{
    private LayoutKey(string value) => Value = value;

    public string Value { get; }

    public static LayoutKey Parse(string value)
        => TryParse(value) ?? throw new ArgumentException("Layout keys must be lower-case kebab-case identifiers.", nameof(value));

    public static LayoutKey? TryParse(string? value)
        => StableKey.IsValid(value) ? new LayoutKey(value!) : null;
}

/// <summary>A stable semantic key for a panel. It is data, never a filesystem path component.</summary>
public sealed record PanelKey
{
    private PanelKey(string value) => Value = value;

    public string Value { get; }

    public static PanelKey Parse(string value)
        => TryParse(value) ?? throw new ArgumentException("Panel keys must be lower-case kebab-case identifiers.", nameof(value));

    public static PanelKey? TryParse(string? value)
        => StableKey.IsValid(value) ? new PanelKey(value!) : null;
}

/// <summary>A stable identifier for a window in a persisted layout.</summary>
public sealed record WindowId
{
    private WindowId(string value) => Value = value;

    public string Value { get; }

    public static WindowId Parse(string value)
        => TryParse(value) ?? throw new ArgumentException("Window IDs must be lower-case kebab-case identifiers.", nameof(value));

    public static WindowId? TryParse(string? value)
        => StableKey.IsValid(value) ? new WindowId(value!) : null;
}

/// <summary>A display identifier supplied by the platform adapter.</summary>
public sealed record DisplayId
{
    private DisplayId(string value) => Value = value;

    public string Value { get; }

    public static DisplayId Parse(string value)
        => TryParse(value) ?? throw new ArgumentException("Display IDs must be lower-case kebab-case identifiers.", nameof(value));

    public static DisplayId? TryParse(string? value)
        => StableKey.IsValid(value) ? new DisplayId(value!) : null;
}

internal static class StableKey
{
    private const int MaximumLength = 48;

    internal static bool IsValid(string? value)
    {
        if (string.IsNullOrEmpty(value) || value.Length > MaximumLength || value[0] is < 'a' or > 'z' || value[^1] == '-')
        {
            return false;
        }

        var previousWasSeparator = false;
        foreach (var character in value)
        {
            var isSeparator = character == '-';
            if (!isSeparator && character is not (>= 'a' and <= 'z') and not (>= '0' and <= '9'))
            {
                return false;
            }

            if (isSeparator && previousWasSeparator)
            {
                return false;
            }

            previousWasSeparator = isSeparator;
        }

        return true;
    }
}
