// SPDX-License-Identifier: AGPL-3.0-only
using System.CommandLine;

namespace ArcForges.CommandLine;

/// <summary>Binds command bodies with the global options, usage errors (exit 2) and the connection failure mapping.</summary>
internal static class Actions
{
    public static void Set(Command command, Func<ParseResult, Cli> factory, Func<Cli, ParseResult, CancellationToken, Task<int>> body) =>
        command.SetAction(async (result, cancellationToken) =>
        {
            Cli cli;
            try
            {
                cli = factory(result);
            }
            catch (UsageException exception)
            {
                var error = result.InvocationConfiguration.Error;
                await error.WriteLineAsync("error: " + exception.Message).ConfigureAwait(false);
                await error.WriteLineAsync("Run 'arcforges --help' for usage.").ConfigureAwait(false);
                return ExitCodes.Usage;
            }

            try
            {
                return await cli.GuardAsync(() => body(cli, result, cancellationToken)).ConfigureAwait(false);
            }
            catch (UsageException exception)
            {
                return cli.Output.Usage(exception.Message);
            }
        });
}
