// SPDX-License-Identifier: AGPL-3.0-only
using System.Globalization;
using System.Resources;

namespace ArcForges.Desktop.Shell.Localization;

/// <summary>
/// The single route by which the shell obtains user-visible text. Every shell-owned string lives in an embedded
/// resource set and is read through here, so one switch can render the whole shell in the pseudo-locale and expose any
/// string that bypassed resources.
/// </summary>
public static class ShellText
{
    internal const string SurfaceSet = "ArcForges.Desktop.Shell.Localization.ShellStrings";
    internal const string ErrorSet = "ArcForges.Desktop.Shell.Errors.ErrorPresentationStrings";

    private static readonly ResourceManager Surfaces = new(SurfaceSet, typeof(ShellText).Assembly);
    private static readonly ResourceManager Errors = new(ErrorSet, typeof(ShellText).Assembly);
    private static readonly AsyncLocal<PseudoScope?> Pseudo = new();

    /// <summary>True while a <see cref="BeginPseudoLocalisation"/> scope is active on the current execution flow.</summary>
    public static bool IsPseudoLocalising => Pseudo.Value is not null;

    /// <summary>Resolves <paramref name="text"/> for <paramref name="culture"/> (the current UI culture by default).</summary>
    public static string Resolve(LocalizedText text, CultureInfo? culture = null)
    {
        ArgumentNullException.ThrowIfNull(text);
        CultureInfo effective = culture ?? CultureInfo.CurrentUICulture;
        string pattern = GetPattern(SurfaceSet, text.Key, effective);
        return ShellMessageFormatter.Format(pattern, text.Arguments, effective);
    }

    /// <summary>
    /// Renders every shell string resolved on this execution flow in the pseudo-locale until the returned scope is
    /// disposed. Product tests use it to run their own composition over the shared shell surfaces.
    /// </summary>
    public static IDisposable BeginPseudoLocalisation()
    {
        var scope = new PseudoScope(Pseudo.Value);
        Pseudo.Value = scope;
        return scope;
    }

    /// <summary>Reports whether the surface resource set defines <paramref name="key"/> for the neutral culture.</summary>
    internal static bool Defines(string key) =>
        Surfaces.GetString(key, CultureInfo.InvariantCulture) is not null;

    /// <summary>Returns the raw message pattern, or null when the set does not define the key.</summary>
    internal static string? TryGetPattern(string resourceSet, string key, CultureInfo culture)
    {
        ResourceManager manager = resourceSet switch
        {
            SurfaceSet => Surfaces,
            ErrorSet => Errors,
            _ => throw new ArgumentOutOfRangeException(nameof(resourceSet)),
        };
        string? pattern = manager.GetString(key, culture);
        return pattern is null || Pseudo.Value is null ? pattern : PseudoLocaliser.Transform(pattern);
    }

    /// <summary>Returns the raw message pattern; fails closed when the resource is unavailable.</summary>
    internal static string GetPattern(string resourceSet, string key, CultureInfo culture) =>
        TryGetPattern(resourceSet, key, culture)
        ?? throw new InvalidOperationException("The shell text resources are unavailable.");

    /// <summary>Returns a final display string for an argument-free resource, or null when the key is not defined.</summary>
    internal static string? TryGetText(string resourceSet, string key, CultureInfo culture)
    {
        string? pattern = TryGetPattern(resourceSet, key, culture);
        return pattern is null ? null : ShellMessageFormatter.Format(pattern, null, culture);
    }

    private sealed class PseudoScope(PseudoScope? previous) : IDisposable
    {
        private int _disposed;

        public void Dispose()
        {
            if (Interlocked.Exchange(ref _disposed, 1) == 0)
            {
                Pseudo.Value = previous;
            }
        }
    }
}
