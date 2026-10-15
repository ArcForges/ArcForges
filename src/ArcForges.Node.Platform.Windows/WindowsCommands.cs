// SPDX-License-Identifier: AGPL-3.0-only
using System.Globalization;
using System.Text;
using ArcForges.Contracts.Node.V1;

namespace ArcForges.Node.Platform.Windows;

/// <summary>
/// Prepares commands on Windows (architecture 04 section 2):
/// <list type="bullet">
/// <item>argv mode: the program resolves through <see cref="WindowsProgramResolver"/>; <c>.bat</c> and <c>.cmd</c> run through
/// <c>cmd.exe /d /s /c</c> with the batch refusal of <see cref="WindowsCommandLine"/>; everything else gets the
/// <c>CommandLineToArgvW</c>-inverse quoting.</item>
/// <item>shell mode: <c>CMD</c> is <c>cmd.exe /d /s /c "script"</c>; <c>POWERSHELL</c> and <c>PWSH</c> run the script with
/// <c>-EncodedCommand</c> (UTF-16LE base64, so no quoting can change it); <c>BASH</c> and <c>SH</c> are Git for Windows' shells (the
/// shells AI clients use on Windows), refused when absent; <c>SYSTEM_DEFAULT</c> is <c>PWSH</c> when detected, otherwise
/// <c>POWERSHELL</c>. A script over 8,000 characters (CMD) or 30,000 characters (others) is written to
/// <c>tmp/&lt;attempt&gt;/command.&lt;ext&gt;</c> and run as a file; a PowerShell script also runs as a file when its encoded form would
/// not fit Windows' 32,767-character command line.</item>
/// </list>
/// </summary>
public static class WindowsCommands
{
    /// <summary>The longest CMD script passed inline.</summary>
    public const int CmdInlineLimit = 8_000;

    /// <summary>The longest other script passed inline.</summary>
    public const int ScriptInlineLimit = 30_000;

    /// <summary>Prepares <paramref name="request"/>.</summary>
    /// <exception cref="CommandRefusedException">A catalogued refusal.</exception>
    public static PreparedCommand Prepare(CommandRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        return request.Argv is { } argv ? PrepareArgv(argv, request) : PrepareShell(request);
    }

    /// <summary>The shell executable for <paramref name="kind"/>, or <see langword="null"/> when it is not installed.</summary>
    public static string? FindShell(ShellKind kind, IReadOnlyDictionary<string, string> environment)
    {
        ArgumentNullException.ThrowIfNull(environment);
        var system = System.Environment.GetFolderPath(System.Environment.SpecialFolder.System);
        switch (kind)
        {
            case ShellKind.Cmd:
                return Existing(WindowsProgramResolver.Value(environment, "ComSpec")) ?? Existing(Path.Combine(system, "cmd.exe"));
            case ShellKind.Powershell:
                return Existing(Path.Combine(system, "WindowsPowerShell", "v1.0", "powershell.exe"));
            case ShellKind.Pwsh:
                return WindowsProgramResolver.Resolve("pwsh.exe", system, environment)
                    ?? Existing(Path.Combine(System.Environment.GetFolderPath(System.Environment.SpecialFolder.ProgramFiles), "PowerShell", "7", "pwsh.exe"));
            case ShellKind.Bash:
                return GitShell("bash.exe", environment);
            case ShellKind.Sh:
                return GitShell("sh.exe", environment);
            case ShellKind.SystemDefault:
                return FindShell(ShellKind.Pwsh, environment) ?? FindShell(ShellKind.Powershell, environment);
            default:
                return null;
        }
    }

    private static PreparedCommand PrepareArgv(IReadOnlyList<string> argv, CommandRequest request)
    {
        if (argv.Count == 0 || argv[0].Length == 0)
        {
            throw new CommandRefusedException("invalid_argument", "command.argv: 1..4096 elements; argv[0] non-empty");
        }

        var program = argv[0];
        var resolved = WindowsProgramResolver.Resolve(program, request.WorkingDirectory, request.Environment)
            ?? throw new CommandRefusedException("program_not_found", program);
        if (WindowsProgramResolver.IsBatch(resolved))
        {
            var cmd = FindShell(ShellKind.Cmd, request.Environment) ?? throw new CommandRefusedException("unsupported_shell", "CMD");
            return new PreparedCommand
            {
                Application = cmd,
                CommandLine = WindowsCommandLine.BuildBatch(cmd, resolved, argv),
                Argv = argv,
                Program = program,
                ViaBatch = true,
            };
        }

        return new PreparedCommand
        {
            Application = resolved,
            CommandLine = WindowsCommandLine.Build(argv),
            Argv = argv,
            Program = program,
        };
    }

    private static PreparedCommand PrepareShell(CommandRequest request)
    {
        var script = request.Script ?? throw new CommandRefusedException("invalid_argument", "command.shell.script: 1 byte..1 MiB");
        var kind = request.Shell == ShellKind.SystemDefault
            ? (FindShell(ShellKind.Pwsh, request.Environment) is not null ? ShellKind.Pwsh : ShellKind.Powershell)
            : request.Shell;
        string shell;
        if (request.ShellPath is { Length: > 0 } explicitPath)
        {
            shell = File.Exists(explicitPath) ? explicitPath : throw new CommandRefusedException("unsupported_shell", ShellName(kind));
        }
        else
        {
            shell = FindShell(kind, request.Environment) ?? throw new CommandRefusedException("unsupported_shell", ShellName(kind));
        }

        var temp = request.TempDirectory ?? Path.GetTempPath();
        switch (kind)
        {
            case ShellKind.Cmd:
                if (script.Length > CmdInlineLimit)
                {
                    var file = Path.Combine(temp, "command.cmd");
                    return Shell(shell, WindowsCommandLine.BuildCmdScript(shell, "\"" + file + "\""), kind, file, script);
                }

                return Shell(shell, WindowsCommandLine.BuildCmdScript(shell, script), kind, null, null);
            case ShellKind.Powershell:
            case ShellKind.Pwsh:
                {
                    var prefix = WindowsCommandLine.Build([shell, "-NoLogo", "-NoProfile", "-NonInteractive"]);
                    var encoded = Convert.ToBase64String(Encoding.Unicode.GetBytes(script));
                    if (script.Length <= ScriptInlineLimit && prefix.Length + encoded.Length + 20 <= WindowsCommandLine.MaxLength)
                    {
                        return Shell(shell, prefix + " -EncodedCommand " + encoded, kind, null, null);
                    }

                    var file = Path.Combine(temp, "command.ps1");
                    return Shell(shell, prefix + " -ExecutionPolicy Bypass -File " + WindowsCommandLine.QuoteArgument(file), kind, file, script);
                }

            case ShellKind.Bash:
            case ShellKind.Sh:
                if (script.Length > ScriptInlineLimit)
                {
                    var file = Path.Combine(temp, "command.sh");
                    return Shell(shell, WindowsCommandLine.Build([shell, file.Replace('\\', '/')]), kind, file, script);
                }

                return Shell(shell, WindowsCommandLine.Build([shell, "-c", script]), kind, null, null);
            default:
                throw new CommandRefusedException("unsupported_shell", ShellName(kind));
        }
    }

    private static PreparedCommand Shell(string shell, string commandLine, ShellKind kind, string? file, string? content) => new()
    {
        Application = shell,
        CommandLine = commandLine,
        Argv = WindowsCommandLine.Parse(commandLine),
        Program = ShellName(kind).ToLowerInvariant(),
        ScriptFile = file,
        ScriptContent = content,
    };

    private static string ShellName(ShellKind kind) => kind switch
    {
        ShellKind.Cmd => "CMD",
        ShellKind.Powershell => "POWERSHELL",
        ShellKind.Pwsh => "PWSH",
        ShellKind.Bash => "BASH",
        ShellKind.Sh => "SH",
        ShellKind.SystemDefault => "SYSTEM_DEFAULT",
        _ => ((int)kind).ToString(CultureInfo.InvariantCulture),
    };

    /// <summary>Git for Windows' bash or sh: beside the <c>git.exe</c> on <c>PATH</c>, or under Program Files. Never WSL's launcher.</summary>
    private static string? GitShell(string name, IReadOnlyDictionary<string, string> environment)
    {
        var system = System.Environment.GetFolderPath(System.Environment.SpecialFolder.System);
        if (WindowsProgramResolver.Resolve("git.exe", system, environment) is { } git)
        {
            // <root>\cmd\git.exe, <root>\bin\git.exe or <root>\mingw64\bin\git.exe.
            for (var directory = Path.GetDirectoryName(git); directory is not null; directory = Path.GetDirectoryName(directory))
            {
                if (Existing(Path.Combine(directory, "bin", name)) is { } found
                    && !found.StartsWith(System.Environment.GetFolderPath(System.Environment.SpecialFolder.Windows), StringComparison.OrdinalIgnoreCase))
                {
                    return found;
                }
            }
        }

        return Existing(Path.Combine(System.Environment.GetFolderPath(System.Environment.SpecialFolder.ProgramFiles), "Git", "bin", name));
    }

    private static string? Existing(string? path) => path is { Length: > 0 } && File.Exists(path) ? path : null;
}
