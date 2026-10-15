// SPDX-License-Identifier: AGPL-3.0-only
using System.CommandLine;

namespace ArcForges.CommandLine;

/// <summary>
/// <c>arcforges completion bash|zsh|fish|pwsh</c> (architecture 12 section 3; experience/cli.md C-10): prints a completion script.
/// Each script asks <c>arcforges</c> itself for the completions of the current line through System.CommandLine's
/// <c>[suggest:&lt;position&gt;]</c> directive, so commands, options and option values always match the binary.
/// </summary>
internal static class CompletionCommand
{
    /// <summary>The shells.</summary>
    internal static readonly string[] Shells = ["bash", "zsh", "fish", "pwsh"];

    public static Command Build(TextWriter output)
    {
        var shell = new Argument<string>("shell") { Description = "bash, zsh, fish or pwsh" };
        shell.AcceptOnlyFromAmong(Shells);
        var command = new Command("completion", "Print a shell completion script") { shell };
        command.SetAction(result =>
        {
            output.Write(Script(result.GetValue(shell)!).ReplaceLineEndings("\n"));
            return ExitCodes.Success;
        });
        return command;
    }

    /// <summary>The completion script of <paramref name="shell"/>.</summary>
    internal static string Script(string shell) => shell switch
    {
        "bash" => """
            # arcforges completion for bash: eval "$(arcforges completion bash)"
            _arcforges_complete() {
                local IFS=$'\n'
                local line="${COMP_LINE:0:${COMP_POINT}}"
                COMPREPLY=($(command arcforges "[suggest:${#line}]" "$line" 2>/dev/null))
            }
            complete -o default -F _arcforges_complete arcforges

            """,
        "zsh" => """
            # arcforges completion for zsh: eval "$(arcforges completion zsh)"
            _arcforges() {
                local line="${BUFFER[1,$CURSOR]}"
                local -a suggestions
                suggestions=("${(@f)$(command arcforges "[suggest:${#line}]" "$line" 2>/dev/null)}")
                compadd -a suggestions
            }
            compdef _arcforges arcforges

            """,
        "fish" => """
            # arcforges completion for fish: arcforges completion fish | source
            function __arcforges_complete
                set -l line (commandline -cp)
                command arcforges "[suggest:"(string length -- "$line")"]" "$line" 2>/dev/null
            end
            complete -c arcforges -f -a '(__arcforges_complete)'

            """,
        "pwsh" => """
            # arcforges completion for PowerShell: arcforges completion pwsh | Out-String | Invoke-Expression
            Register-ArgumentCompleter -Native -CommandName arcforges, arcforges.exe -ScriptBlock {
                param($wordToComplete, $commandAst, $cursorPosition)
                $line = $commandAst.ToString()
                $position = [Math]::Min($cursorPosition - $commandAst.Extent.StartOffset, $line.Length)
                & arcforges "[suggest:$position]" $line.Substring(0, $position) 2>$null | ForEach-Object {
                    [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_)
                }
            }

            """,
        _ => throw new ArgumentOutOfRangeException(nameof(shell), shell, "Unknown shell."),
    };
}
