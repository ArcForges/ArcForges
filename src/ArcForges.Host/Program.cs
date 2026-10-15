// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.CommandLine;
using ArcForges.Node.Api;
using ArcForges.Node.Platform.Windows;

namespace ArcForges.Host;

/// <summary>
/// The multi-role executable <c>arcforges</c> (AD-0003): the CLI, the node role through <c>arcforges node run</c>, and the node's internal
/// helper roles, hidden from help (experience/cli.md section 4): <c>node exec-wrap</c>, an attempt's holder, and <c>node signal</c>, the
/// console helper of the graceful phase (architecture 04 sections 3 and 6). The helper roles are dispatched before the CLI parser, so a
/// holder initializes neither the CLI nor the node's service code. A CLI invocation never touches the node's service code; Native AOT
/// initializes it only when <c>node run</c> calls it.
/// </summary>
internal static class Program
{
    private static Task<int> Main(string[] args)
    {
        if (args.Length >= 2 && args[0] == "node" && args[1] is "exec-wrap" or "signal")
        {
            return Task.FromResult(RunHelperRole(args[1], args[2..]));
        }

        return CliApplication.RunAsync(args, RunNodeAsync);
    }

    private static int RunHelperRole(string role, string[] args)
    {
        if (!OperatingSystem.IsWindows())
        {
            // The Linux helper roles (exit-record, exec-launch, exec-stop, node guard) arrive with AF-EXEC-02.
            Console.Error.WriteLine($"arcforges: node {role} is a Windows helper role");
            return 2;
        }

        return role == "exec-wrap" ? ExecWrapRole.Run(args) : SignalRole.Run(args);
    }

    private static Task<int> RunNodeAsync(NodeRunRequest request, CancellationToken cancellationToken) =>
        NodeHost.RunAsync(new NodeHostOptions { TestMode = request.TestMode, Systemd = request.Systemd }, cancellationToken);
}
