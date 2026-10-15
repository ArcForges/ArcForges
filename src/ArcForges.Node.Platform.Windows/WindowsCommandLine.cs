// SPDX-License-Identifier: AGPL-3.0-only
using System.Buffers;
using System.Globalization;
using System.Text;

namespace ArcForges.Node.Platform.Windows;

/// <summary>
/// Windows command lines from argument vectors (architecture 04 section 2), pure logic that runs on every OS:
/// <list type="bullet">
/// <item>Ordinary programs: each argument is quoted with the rules inverse to <c>CommandLineToArgvW</c> (and the MSVC runtime): an
/// argument is quoted when it is empty or holds a space, tab or quote; backslashes are doubled only where they precede a quote or
/// the closing quote; an inner quote becomes <c>\"</c>. The program token is quoted without escapes (the first token has no escape
/// processing) and may not contain a quote.</item>
/// <item>Batch files (<c>.bat</c>, <c>.cmd</c>) run through <c>cmd.exe /d /s /c "..."</c>, whose own parsing sees the whole line. An
/// argument that holds a line break or NUL, a <c>!</c> (delayed expansion may be on in the user's registry), or a quote together
/// with a metacharacter (<c>% ! ^ &amp; | &lt; &gt;</c>) is refused with <c>VALIDATION/unsafe_batch_argument</c>, the class of risk
/// behind CVE-2024-24576. Other arguments are quoted when they hold a space, tab, metacharacter or cmd delimiter, inner quotes are
/// doubled, and every <c>%</c> is followed by <c>%cd:~,%</c> (an expansion to nothing), so cmd never expands a variable from
/// argument text.</item>
/// </list>
/// The whole command line must fit Windows' limit of 32,767 characters including the terminator.
/// </summary>
public static class WindowsCommandLine
{
    /// <summary>The longest command line <c>CreateProcessW</c> accepts, without the terminating NUL.</summary>
    public const int MaxLength = 32_766;

    private static readonly SearchValues<char> BatchMetacharacters = SearchValues.Create("%!^&|<>");
    private static readonly SearchValues<char> QuoteTriggers = SearchValues.Create(" \t\n\v\"");
    private static readonly SearchValues<char> BatchQuoteTriggers = SearchValues.Create(" \t\"^&|<>(),;=%");

    /// <summary>Quotes one argument (not the program token) for <c>CommandLineToArgvW</c>.</summary>
    public static string QuoteArgument(string argument)
    {
        ArgumentNullException.ThrowIfNull(argument);
        var builder = new StringBuilder(argument.Length + 2);
        AppendArgument(builder, argument);
        return builder.ToString();
    }

    /// <summary>The command line of <paramref name="argv"/> for an ordinary program.</summary>
    /// <exception cref="CommandRefusedException">The program token holds a quote, or the line is too long.</exception>
    public static string Build(IReadOnlyList<string> argv)
    {
        ArgumentNullException.ThrowIfNull(argv);
        if (argv.Count == 0)
        {
            throw new CommandRefusedException("invalid_argument", "command.argv: 1..4096 elements");
        }

        var builder = new StringBuilder();
        AppendProgram(builder, argv[0]);
        for (var index = 1; index < argv.Count; index++)
        {
            builder.Append(' ');
            AppendArgument(builder, argv[index]);
        }

        return Checked(builder);
    }

    /// <summary>The index of the first argument a batch file cannot receive safely (index 0 is the script), or -1.</summary>
    public static int FindUnsafeBatchArgument(IReadOnlyList<string> argv)
    {
        ArgumentNullException.ThrowIfNull(argv);
        for (var index = 0; index < argv.Count; index++)
        {
            if (!IsBatchSafe(argv[index]))
            {
                return index;
            }
        }

        return -1;
    }

    /// <summary>Whether a batch file can receive <paramref name="argument"/> through cmd.exe without its parsing acting on it.</summary>
    public static bool IsBatchSafe(string argument)
    {
        ArgumentNullException.ThrowIfNull(argument);
        if (argument.AsSpan().IndexOfAny('\r', '\n', '\0') >= 0 || argument.Contains('!', StringComparison.Ordinal))
        {
            return false;
        }

        return !(argument.Contains('"', StringComparison.Ordinal) && argument.AsSpan().IndexOfAny(BatchMetacharacters) >= 0);
    }

    /// <summary>
    /// The command line that runs the batch file <paramref name="script"/> (resolved, absolute) with the arguments of
    /// <paramref name="argv"/> after its program token: <c>cmd.exe /d /s /c ""script" args"</c>.
    /// </summary>
    /// <exception cref="CommandRefusedException"><c>unsafe_batch_argument</c> with the argument index, or a too long line.</exception>
    public static string BuildBatch(string cmd, string script, IReadOnlyList<string> argv)
    {
        ArgumentNullException.ThrowIfNull(cmd);
        ArgumentNullException.ThrowIfNull(script);
        ArgumentNullException.ThrowIfNull(argv);
        var unsafeIndex = FindUnsafeBatchArgument(argv);
        if (unsafeIndex >= 0)
        {
            throw new CommandRefusedException("unsafe_batch_argument", unsafeIndex.ToString(CultureInfo.InvariantCulture));
        }

        if (!IsBatchSafe(script) || script.Contains('"', StringComparison.Ordinal))
        {
            throw new CommandRefusedException("unsafe_batch_argument", "0");
        }

        var builder = new StringBuilder();
        AppendProgram(builder, cmd);
        builder.Append(" /d /s /c \"");
        builder.Append('"');
        AppendBatchText(builder, script);
        builder.Append('"');
        for (var index = 1; index < argv.Count; index++)
        {
            builder.Append(' ');
            AppendBatchArgument(builder, argv[index]);
        }

        builder.Append('"');
        return Checked(builder);
    }

    /// <summary>The command line of a cmd.exe shell script: <c>cmd.exe /d /s /c "script"</c> (the script runs as the user wrote it).</summary>
    public static string BuildCmdScript(string cmd, string script)
    {
        ArgumentNullException.ThrowIfNull(cmd);
        ArgumentNullException.ThrowIfNull(script);
        var builder = new StringBuilder();
        AppendProgram(builder, cmd);
        builder.Append(" /d /s /c \"").Append(script).Append('"');
        return Checked(builder);
    }

    /// <summary>
    /// The Unicode environment block of <paramref name="entries"/> (<c>NAME=value</c>), sorted by name in upper-case ordinal order as
    /// Windows expects, double-NUL terminated.
    /// </summary>
    public static char[] EnvironmentBlock(IReadOnlyList<string> entries)
    {
        ArgumentNullException.ThrowIfNull(entries);
        var sorted = entries.OrderBy(entry => entry.AsSpan()[..Math.Max(0, entry.IndexOf('=', 1))].ToString().ToUpperInvariant(), StringComparer.Ordinal).ToList();
        var builder = new StringBuilder();
        foreach (var entry in sorted)
        {
            if (entry.Contains('\0', StringComparison.Ordinal))
            {
                throw new ArgumentException("Environment entries cannot contain NUL.", nameof(entries));
            }

            builder.Append(entry).Append('\0');
        }

        if (sorted.Count == 0)
        {
            builder.Append('\0');
        }

        builder.Append('\0');
        return builder.ToString().ToCharArray();
    }

    /// <summary>Parses a command line the way <c>CommandLineToArgvW</c> does (used by tests and diagnostics).</summary>
    public static List<string> Parse(string commandLine)
    {
        ArgumentNullException.ThrowIfNull(commandLine);
        var result = new List<string>();
        var position = 0;

        // The program token: up to the next space or tab outside quotes, quotes removed, no escapes.
        var program = new StringBuilder();
        var quoted = false;
        while (position < commandLine.Length)
        {
            var character = commandLine[position];
            if (character == '"')
            {
                quoted = !quoted;
            }
            else if (!quoted && character is ' ' or '\t')
            {
                break;
            }
            else
            {
                program.Append(character);
            }

            position++;
        }

        result.Add(program.ToString());
        while (true)
        {
            while (position < commandLine.Length && commandLine[position] is ' ' or '\t')
            {
                position++;
            }

            if (position >= commandLine.Length)
            {
                return result;
            }

            var argument = new StringBuilder();
            quoted = false;
            while (position < commandLine.Length)
            {
                var character = commandLine[position];
                if (!quoted && character is ' ' or '\t')
                {
                    break;
                }

                if (character == '\\')
                {
                    var backslashes = 0;
                    while (position < commandLine.Length && commandLine[position] == '\\')
                    {
                        backslashes++;
                        position++;
                    }

                    if (position < commandLine.Length && commandLine[position] == '"')
                    {
                        argument.Append('\\', backslashes / 2);
                        if (backslashes % 2 == 1)
                        {
                            argument.Append('"');
                            position++;
                        }
                    }
                    else
                    {
                        argument.Append('\\', backslashes);
                    }

                    continue;
                }

                if (character == '"')
                {
                    if (quoted && position + 1 < commandLine.Length && commandLine[position + 1] == '"')
                    {
                        // A doubled quote inside quotes is a literal quote (and ends the quoted run), as the runtime parses it.
                        argument.Append('"');
                        position += 2;
                        quoted = false;
                        continue;
                    }

                    quoted = !quoted;
                    position++;
                    continue;
                }

                argument.Append(character);
                position++;
            }

            result.Add(argument.ToString());
        }
    }

    private static void AppendProgram(StringBuilder builder, string program)
    {
        if (program.Length == 0 || program.Contains('"', StringComparison.Ordinal) || program.AsSpan().IndexOfAny('\r', '\n', '\0') >= 0)
        {
            throw new CommandRefusedException("invalid_argument", "command.argv[0]: a program name without quotes or line breaks");
        }

        if (program.AsSpan().IndexOfAny(' ', '\t') >= 0)
        {
            builder.Append('"').Append(program).Append('"');
        }
        else
        {
            builder.Append(program);
        }
    }

    private static void AppendArgument(StringBuilder builder, string argument)
    {
        if (argument.AsSpan().IndexOf('\0') >= 0)
        {
            throw new CommandRefusedException("invalid_argument", "command.argv: arguments cannot contain NUL");
        }

        var quote = argument.Length == 0 || argument.AsSpan().IndexOfAny(QuoteTriggers) >= 0;
        if (!quote)
        {
            builder.Append(argument);
            return;
        }

        builder.Append('"');
        var backslashes = 0;
        foreach (var character in argument)
        {
            if (character == '\\')
            {
                backslashes++;
                continue;
            }

            if (character == '"')
            {
                // 2n+1 backslashes and the quote: n literal backslashes and a literal quote.
                builder.Append('\\', (backslashes * 2) + 1);
                builder.Append('"');
            }
            else
            {
                builder.Append('\\', backslashes);
                builder.Append(character);
            }

            backslashes = 0;
        }

        // Backslashes before the closing quote are doubled so they stay literal.
        builder.Append('\\', backslashes * 2);
        builder.Append('"');
    }

    private static void AppendBatchArgument(StringBuilder builder, string argument)
    {
        var quote = argument.Length == 0 || argument.AsSpan().IndexOfAny(BatchQuoteTriggers) >= 0;
        if (quote)
        {
            builder.Append('"');
        }

        AppendBatchText(builder, argument);
        if (quote)
        {
            builder.Append('"');
        }
    }

    private static void AppendBatchText(StringBuilder builder, string text)
    {
        foreach (var character in text)
        {
            switch (character)
            {
                case '"':
                    builder.Append("\"\"");
                    break;
                case '%':
                    // %cd:~,% expands to nothing, so this % never pairs with a later one into a variable reference.
                    builder.Append("%%cd:~,%");
                    break;
                default:
                    builder.Append(character);
                    break;
            }
        }
    }

    private static string Checked(StringBuilder builder)
    {
        if (builder.Length > MaxLength)
        {
            throw new CommandRefusedException("invalid_argument",
                string.Create(CultureInfo.InvariantCulture, $"command: the Windows command line is {builder.Length} characters; at most {MaxLength}"));
        }

        return builder.ToString();
    }
}
