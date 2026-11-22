// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Client;
using ArcForges.CommandLine;
using ArcForges.Node.Api;
using ArcForges.Node.Store;

namespace ArcForges.Host;

/// <summary>The ArcForges CLI and <c>node run</c> entry point.</summary>
internal static class Program
{
    private static Task<int> Main(string[] args)
    {
        // A process started with --test-mode (before any '--' that ends the options) gets the OS secret-store tripwire unless the tier's
        // exact opt-in is set (16-testing-strategy section 1, item 2; 02 section 4). Production processes are unaffected.
        var options = args.TakeWhile(argument => argument != "--");
        NodeSecretStores.ApplyTestModeTripwire(options.Contains(NodeLocations.TestModeOption, StringComparer.Ordinal));
        return CliApplication.RunAsync(args, RunNodeAsync, updateRunner: NodeHost.UpdateAsync);
    }

    private static Task<int> RunNodeAsync(NodeRunRequest request, CancellationToken cancellationToken) =>
        NodeHost.RunAsync(new NodeHostOptions { TestMode = request.TestMode, Systemd = request.Systemd }, cancellationToken);
}
