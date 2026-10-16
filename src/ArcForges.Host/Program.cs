// SPDX-License-Identifier: AGPL-3.0-only
using System.Runtime.InteropServices;
using ArcForges.Client;
using ArcForges.CommandLine;
using ArcForges.Node.Api;
using ArcForges.Node.Core.Platform;
using ArcForges.Node.Platform.Linux;
using ArcForges.Node.Platform.Windows;

namespace ArcForges.Host;

/// <summary>
/// The multi-role executable <c>arcforges</c> (AD-0003): the CLI, the node role through <c>arcforges node run</c>, and the node's internal
/// helper roles, hidden from help (experience/cli.md section 4): on Windows <c>node exec-wrap</c> (an attempt's holder) and
/// <c>node signal</c> (the console helper of the graceful phase); on Linux <c>node exec-launch</c> (an attempt unit's <c>ExecStart</c>),
/// <c>node exec-stop</c> (its <c>ExecStop</c>), <c>node exit-record</c> (its <c>ExecStopPost</c>) and <c>node guard</c> (the process of
/// <c>arcforges-guard.service</c>) (architecture 04 sections 3 and 6; 06 section 5). The helper roles are dispatched before the CLI
/// parser, so a helper initializes neither the CLI nor the node's service code. A CLI invocation never touches the node's service code;
/// Native AOT initializes it only when <c>node run</c> calls it.
/// </summary>
internal static class Program
{
    private static Task<int> Main(string[] args)
    {
        if (args.Length >= 2 && args[0] == "node" && args[1] is "exec-wrap" or "signal" or "exec-launch" or "exec-stop" or "exit-record" or "guard")
        {
            return Task.FromResult(RunHelperRole(args[1], args[2..]));
        }

        return CliApplication.RunAsync(args, RunNodeAsync);
    }

    private static int RunHelperRole(string role, string[] args)
    {
        if (OperatingSystem.IsWindows())
        {
            return role switch
            {
                "exec-wrap" => ExecWrapRole.Run(args),
                "signal" => SignalRole.Run(args),
                _ => Unsupported(role, "a Linux helper role"),
            };
        }

        if (OperatingSystem.IsLinux())
        {
            return role switch
            {
                "exec-launch" => ExecLaunchRole.Run(args),
                "exec-stop" => ExecStopRole.Run(args),
                "exit-record" => ExitRecordRole.Run(args),
                "guard" => RunGuard(args),
                _ => Unsupported(role, "a Windows helper role"),
            };
        }

        return Unsupported(role, "not available on this operating system");
    }

    /// <summary><c>arcforges node guard [--test-mode]</c>: guards the attempt units of the node's data root until SIGTERM.</summary>
    [System.Runtime.Versioning.SupportedOSPlatform("linux")]
    private static int RunGuard(string[] args)
    {
        var testMode = args.Contains(NodeLocations.TestModeOption, StringComparer.Ordinal);
        if (args.Any(argument => argument != NodeLocations.TestModeOption))
        {
            return Unsupported("guard", "takes no arguments other than --test-mode");
        }

        using var stop = new CancellationTokenSource();
        using var term = PosixSignalRegistration.Create(PosixSignal.SIGTERM, context =>
        {
            context.Cancel = true;
            stop.Cancel();
        });
        using var interrupt = PosixSignalRegistration.Create(PosixSignal.SIGINT, context =>
        {
            context.Cancel = true;
            stop.Cancel();
        });
        return GuardRole.Run(new GuardOptions
        {
            DataRoot = NodeLocations.ResolveDataRoot(testMode),
            ManagerAddress = LinuxTestHooks.Value(testMode, LinuxTestHooks.ManagerAddress),
            Stop = stop.Token,
        });
    }

    private static int Unsupported(string role, string why)
    {
        Console.Error.WriteLine($"arcforges: node {role}: {why}");
        return 2;
    }

    private static Task<int> RunNodeAsync(NodeRunRequest request, CancellationToken cancellationToken) =>
        NodeHost.RunAsync(new NodeHostOptions { TestMode = request.TestMode, Systemd = request.Systemd }, cancellationToken);
}
