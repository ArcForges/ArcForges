// SPDX-License-Identifier: AGPL-3.0-only
using System.Buffers;
using System.Globalization;
using System.Text;

namespace ArcForges.Node.Platform.Windows;

/// <summary>
/// Windows command lines from argument vectors (architecture 04 section 2). Arguments use the rules inverse to
/// <c>CommandLineToArgvW</c> and the MSVC runtime. The program token has no escape processing and cannot contain a quote.
/// The whole command line must fit Windows' limit of 32,767 characters including the terminator.
/// </summary>
public static class WindowsCommandLine
{
    /// <summary>The longest command line <c>CreateProcessW</c> accepts, without the terminating NUL.</summary>
    public const int MaxLength = 32_766;

    private static readonly SearchValues<char> QuoteTriggers = SearchValues.Create(" \t\n\v\"");

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
