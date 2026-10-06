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

        // Integer counts keep their actual immutable types for plural selection. Other values are lazily
        // formatted through the shared policy once, including repeated placeholders and pseudo validation.
        var arguments = new Dictionary<string, object?>(StringComparer.Ordinal);
        foreach (var argument in text.Arguments)
        {
            arguments.Add(argument.Key, argument.Value is null or string or long or int or short or byte or
                sbyte or uint or ushort or ulong ? argument.Value : new CachedArgument(argument.Value, effective));
        }

        try
        {
            string output = ShellMessageFormatter.Format(pattern, arguments, effective);
            if (string.IsNullOrWhiteSpace(output))
            {
                throw new InvalidOperationException("The embedded text resource resolves to blank text.");
            }

            return ShellText.IsPseudoLocalising
                ? ShellMessageFormatter.Format(PseudoLocaliser.Transform(pattern), arguments, effective)
                : output;
        }
        catch (FormatException)
        {
            throw new FormatException("The embedded text resource cannot be formatted.");
        }
    }

    internal bool Defines(string key) => _resources.GetString(key, CultureInfo.InvariantCulture) is not null;

    private sealed class CachedArgument(object value, CultureInfo culture) : IFormattable
    {
        private readonly Lazy<string> _text = new(() => ShellMessageFormatter.FormatValue(value, culture));
        public string ToString(string? format, IFormatProvider? formatProvider) => _text.Value;
    }
}
