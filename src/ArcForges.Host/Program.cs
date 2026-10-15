// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.CommandLine;
using ArcForges.Node.Api;

namespace ArcForges.Host;

/// <summary>
/// The multi-role executable <c>arcforges</c> (AD-0003): the CLI, and the node role through <c>arcforges node run</c>. A CLI
/// invocation never touches the node's service code; Native AOT initializes it only when <c>node run</c> calls it.
/// </summary>
internal static class Program
{
    private static Task<int> Main(string[] args) => CliApplication.RunAsync(args, RunNodeAsync);

    private static Task<int> RunNodeAsync(NodeRunRequest request, CancellationToken cancellationToken) =>
        NodeHost.RunAsync(new NodeHostOptions { TestMode = request.TestMode, Systemd = request.Systemd }, cancellationToken);
}
