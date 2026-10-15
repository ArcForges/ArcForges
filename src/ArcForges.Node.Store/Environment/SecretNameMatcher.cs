// SPDX-License-Identifier: AGPL-3.0-only
namespace ArcForges.Node.Store;

/// <summary>
/// Matches environment variable names against the policy's secret name patterns (<c>privacy.secret_name_patterns</c>,
/// 04-execution section 2). A pattern is a glob in which <c>*</c> matches any run of characters; matching ignores case,
/// because Windows variable names are case-insensitive and redacting more is the safe side (R-EXE-017).
/// </summary>
public sealed class SecretNameMatcher
{
    private readonly string[] _patterns;

    /// <summary>Creates a matcher for <paramref name="patterns"/>.</summary>
    public SecretNameMatcher(IEnumerable<string> patterns)
    {
        ArgumentNullException.ThrowIfNull(patterns);
        _patterns = [.. patterns];
        foreach (var pattern in _patterns)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(pattern, nameof(patterns));
        }
    }

    /// <summary>The matcher for the default patterns.</summary>
    public static SecretNameMatcher Default { get; } = new(Policy.DefaultPolicy.SecretNamePatterns);

    /// <summary>The patterns.</summary>
    public IReadOnlyList<string> Patterns => _patterns;

    /// <summary>Whether <paramref name="name"/> is secret-shaped.</summary>
    public bool IsSecret(string name)
    {
        ArgumentNullException.ThrowIfNull(name);
        foreach (var pattern in _patterns)
        {
            if (Glob(pattern, name))
            {
                return true;
            }
        }

        return false;
    }

    // Iterative glob match with backtracking to the last '*': O(pattern x name) in the worst case.
    private static bool Glob(ReadOnlySpan<char> pattern, ReadOnlySpan<char> text)
    {
        int p = 0, t = 0, star = -1, mark = 0;
        while (t < text.Length)
        {
            if (p < pattern.Length && pattern[p] == '*')
            {
                star = p++;
                mark = t;
            }
            else if (p < pattern.Length && char.ToUpperInvariant(pattern[p]) == char.ToUpperInvariant(text[t]))
            {
                p++;
                t++;
            }
            else if (star >= 0)
            {
                p = star + 1;
                t = ++mark;
            }
            else
            {
                return false;
            }
        }

        while (p < pattern.Length && pattern[p] == '*')
        {
            p++;
        }

        return p == pattern.Length;
    }
}
