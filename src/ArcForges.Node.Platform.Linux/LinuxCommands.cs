// SPDX-License-Identifier: AGPL-3.0-only
using System.Globalization;
using ArcForges.Contracts.Node.V1;

namespace ArcForges.Node.Platform.Linux;

/// <summary>
/// Prepares commands on Linux (architecture 04 section 2):
/// <list type="bullet">
/// <item>argv mode: <c>execvp</c> semantics against the resolved <c>PATH</c> (glibc's default <c>/bin:/usr/bin</c> when it has none; an
/// empty entry is the working directory); a program with a slash is taken as it is, relative to the working directory. The program
/// receives <c>argv</c> exactly; <c>argv[0]</c> stays as the caller wrote it.</item>
/// <item>shell mode: <c>SH</c> (and <c>SYSTEM_DEFAULT</c>) is <c>/bin/sh -c script</c>; <c>BASH</c> and <c>PWSH</c> are found on
/// <c>PATH</c>; <c>CMD</c> and <c>POWERSHELL</c> are Windows shells and refused. A script over 30,000 characters is written to
/// <c>tmp/&lt;attempt&gt;/command.sh</c> (or <c>.ps1</c>) and run as a file, because one Linux argument is at most 128 KiB.</item>
/// </list>
/// </summary>
public static class LinuxCommands
{
    /// <summary>The longest script passed inline.</summary>
    public const int ScriptInlineLimit = 30_000;

    /// <summary>glibc's default search path (<c>confstr(_CS_PATH)</c>).</summary>
    public const string DefaultPath = "/bin:/usr/bin";

    /// <summary>Prepares <paramref name="request"/>.</summary>
    /// <exception cref="CommandRefusedException">A catalogued refusal.</exception>
    public static PreparedCommand Prepare(CommandRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        return request.Argv is { } argv ? PrepareArgv(argv, request) : PrepareShell(request);
    }

    /// <summary>
    /// Resolves <paramref name="program"/> like <c>execvp</c>: the first executable regular file on <c>PATH</c>; failing that, the first
    /// regular file (its start then fails with a permission error, as with <c>execvp</c>); null when there is none.
    /// </summary>
    public static string? Resolve(string program, string workingDirectory, IReadOnlyDictionary<string, string> environment)
    {
        ArgumentNullException.ThrowIfNull(program);
        ArgumentNullException.ThrowIfNull(environment);
        if (program.Contains('/', StringComparison.Ordinal))
        {
            var path = Path.IsPathFullyQualified(program) ? program : Path.GetFullPath(Path.Combine(workingDirectory, program));
            return File.Exists(path) ? path : null;
        }

        var search = environment.TryGetValue("PATH", out var value) ? value : DefaultPath;
        string? candidate = null;
        foreach (var entry in search.Split(':'))
        {
            var directory = entry.Length == 0 ? workingDirectory : entry;
            if (!Path.IsPathFullyQualified(directory))
            {
                directory = Path.GetFullPath(Path.Combine(workingDirectory, directory));
            }

            var path = Path.Combine(directory, program);
            if (!File.Exists(path))
            {
                continue;
            }

            if (IsExecutable(path))
            {
                return path;
            }

            candidate ??= path;
        }

        return candidate;
    }

    /// <summary>The shell executable for <paramref name="kind"/>, or null when it is not installed or is a Windows shell.</summary>
    public static string? FindShell(ShellKind kind, IReadOnlyDictionary<string, string> environment, string workingDirectory) => kind switch
    {
        ShellKind.Sh or ShellKind.SystemDefault => File.Exists("/bin/sh") ? "/bin/sh" : Resolve("sh", workingDirectory, environment),
        ShellKind.Bash => Resolve("bash", workingDirectory, environment) ?? (File.Exists("/bin/bash") ? "/bin/bash" : null),
        ShellKind.Pwsh => Resolve("pwsh", workingDirectory, environment),
        _ => null,
    };

    private static PreparedCommand PrepareArgv(IReadOnlyList<string> argv, CommandRequest request)
    {
        if (argv.Count == 0 || argv[0].Length == 0)
        {
            throw new CommandRefusedException("invalid_argument", "command.argv: 1..4096 elements; argv[0] non-empty");
        }

        var program = argv[0];
        var resolved = Resolve(program, request.WorkingDirectory, request.Environment) ?? throw new CommandRefusedException("program_not_found", program);
        return new PreparedCommand
        {
            Application = resolved,
            CommandLine = Display(argv),
            Argv = argv,
            Program = program,
        };
    }

    private static PreparedCommand PrepareShell(CommandRequest request)
    {
        var script = request.Script ?? throw new CommandRefusedException("invalid_argument", "command.shell.script: 1 byte..1 MiB");
        var kind = request.Shell == ShellKind.SystemDefault ? ShellKind.Sh : request.Shell;
        if (kind is not (ShellKind.Sh or ShellKind.Bash or ShellKind.Pwsh))
        {
            throw new CommandRefusedException("unsupported_shell", ShellName(kind));
        }

        string shell;
        if (request.ShellPath is { Length: > 0 } explicitPath)
        {
            shell = File.Exists(explicitPath) ? explicitPath : throw new CommandRefusedException("unsupported_shell", ShellName(kind));
        }
        else
        {
            shell = FindShell(kind, request.Environment, request.WorkingDirectory) ?? throw new CommandRefusedException("unsupported_shell", ShellName(kind));
        }

        var name = Path.GetFileName(shell);
        List<string> prefix = kind == ShellKind.Pwsh ? [name, "-NoLogo", "-NoProfile", "-NonInteractive"] : [name];
        if (script.Length > ScriptInlineLimit)
        {
            var file = Path.Combine(request.TempDirectory ?? Path.GetTempPath(), kind == ShellKind.Pwsh ? "command.ps1" : "command.sh");
            List<string> fileArgv = kind == ShellKind.Pwsh ? [.. prefix, "-File", file] : [.. prefix, file];
            return Shell(shell, fileArgv, kind, file, script);
        }

        List<string> inline = kind == ShellKind.Pwsh ? [.. prefix, "-Command", script] : [.. prefix, "-c", script];
        return Shell(shell, inline, kind, null, null);
    }

    private static PreparedCommand Shell(string shell, List<string> argv, ShellKind kind, string? file, string? content) => new()
    {
        Application = shell,
        CommandLine = Display(argv),
        Argv = argv,
        Program = ShellName(kind).ToLowerInvariant(),
        ScriptFile = file,
        ScriptContent = content,
    };

    private static string Display(IReadOnlyList<string> argv) =>
        string.Join(' ', argv.Select(argument => argument.Length == 0 || argument.Any(character => char.IsWhiteSpace(character) || character is '"' or '\'')
            ? "'" + argument.Replace("'", "'\\''", StringComparison.Ordinal) + "'"
            : argument));

    private static bool IsExecutable(string path)
    {
        if (OperatingSystem.IsWindows())
        {
            // The unit tests of the resolution rules also run on Windows, which has no execute bits.
            return !Directory.Exists(path);
        }

        try
        {
            var mode = File.GetUnixFileMode(path);
            return (mode & (UnixFileMode.UserExecute | UnixFileMode.GroupExecute | UnixFileMode.OtherExecute)) != 0 && !Directory.Exists(path);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or PlatformNotSupportedException)
        {
            return false;
        }
    }

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
}
