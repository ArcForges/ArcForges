// SPDX-License-Identifier: AGPL-3.0-only
using System.Globalization;
using System.Reflection;
using System.Resources;

namespace ArcForges.Desktop.Shell.Localization;

/// <summary>An immutable binding to one real embedded resource set, using the shared shell text policy.</summary>
public sealed class ShellResourceScope
{
    private readonly ResourceManager _resources;

    /// <summary>Binds the exact neutral embedded resource set; unavailable resources are refused before use.</summary>
    public ShellResourceScope(string resourceBaseName, Assembly resourceAssembly)
    {
        ArgumentNullException.ThrowIfNull(resourceAssembly);
        if (string.IsNullOrWhiteSpace(resourceBaseName) || resourceBaseName.Length > 256 ||
            resourceBaseName.Any(static character => !(char.IsAsciiLetterOrDigit(character) || character is '.' or '_')))
        {
            throw new ArgumentException("A bounded embedded resource base name is required.", nameof(resourceBaseName));
        }

        if (resourceAssembly.GetManifestResourceInfo(resourceBaseName + ".resources") is null)
        {
            throw new MissingManifestResourceException("The neutral embedded text resource set is unavailable.");
        }

        _resources = new ResourceManager(resourceBaseName, resourceAssembly);
    }

    /// <summary>Resolves a whole localised message; missing, blank or invalid resources fail without returning a key or fallback sentence.</summary>
    public string Resolve(LocalizedText text, CultureInfo? culture = null)
    {
        ArgumentNullException.ThrowIfNull(text);
        CultureInfo effective = culture ?? CultureInfo.CurrentUICulture;
        string pattern = _resources.GetString(text.Key, effective)
            ?? throw new InvalidOperationException("The embedded text resource is unavailable.");
        if (string.IsNullOrWhiteSpace(pattern))
        {
            throw new InvalidOperationException("The embedded text resource is blank.");
        }

        string output = ShellMessageFormatter.Format(pattern, text.Arguments, effective);
        if (string.IsNullOrWhiteSpace(output))
        {
            throw new InvalidOperationException("The embedded text resource resolves to blank text.");
        }

        return ShellText.IsPseudoLocalising
            ? ShellMessageFormatter.Format(PseudoLocaliser.Transform(pattern), text.Arguments, effective)
            : output;
    }

    internal bool Defines(string key) => _resources.GetString(key, CultureInfo.InvariantCulture) is not null;
}
