// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics.CodeAnalysis;

namespace ArcForges.LocalRpc.Tests;

/// <summary>
/// The test assembly doubles as the helper processes of the opt-in launch checks. A helper child is started with
/// <c>DOTNET_STARTUP_HOOKS</c> naming this assembly and <see cref="Variable"/> naming a mode; the startup hook below runs that
/// mode before the test runner starts and exits. Neither variable is set in a normal test run, so it never takes this path.
/// </summary>
internal static class LaunchHelperProcess
{
    internal const string Variable = "ARCFORGES_LOCALRPC_HELPER";

    [SuppressMessage("Design", "CA1031", Justification = "A helper reports any failure on stderr and through its exit code.")]
    internal static void RunWhenAHelper()
    {
        var mode = Environment.GetEnvironmentVariable(Variable);
        if (string.IsNullOrEmpty(mode))
        {
            return;
        }

        int code;
        try
        {
            code = RunAsync(mode.Split('|')).GetAwaiter().GetResult();
        }
        catch (Exception exception)
        {
            Console.Error.WriteLine(exception);
            code = 1;
        }

        Environment.Exit(code);
    }

    private static async Task<int> RunAsync(string[] arguments)
    {
        switch (arguments[0])
        {
            case "burst":
                return await BurstAsync(arguments[1], int.Parse(arguments[2], System.Globalization.CultureInfo.InvariantCulture)).ConfigureAwait(false);
            case "orphan":
                return await OrphanAsync(arguments[1]).ConfigureAwait(false);
            case "register":
                return await RegistrationHelperProcess.RunAsync().ConfigureAwait(false);
            case "sleep":
                await Say("READY").ConfigureAwait(false);
                await Task.Delay(Timeout.InfiniteTimeSpan).ConfigureAwait(false);
                return 0;
            default:
                return 2;
        }
    }

    private static async Task Say(string line)
    {
        await Console.Out.WriteLineAsync(line).ConfigureAwait(false);
        await Console.Out.FlushAsync().ConfigureAwait(false);
    }

    private static async Task<int> BurstAsync(string root, int count)
    {
        var identity = Launches.Identity();
        await using var authority = LocalRpcLaunchAuthority.Create(root, null, new LaunchEnvironment { ForceUnixSocket = true });
        var launches = await Task.WhenAll(Enumerable.Range(0, count).Select(index => Task.Run(() =>
            authority.Launch("slot-" + (index % 3), identity)))).ConfigureAwait(false);
        foreach (var launch in launches)
        {
            await Say("L " + launch.Descriptor.LaunchId.ToString("N") + " " + launch.DirectoryPath);
        }

        await Say("INTACT " + launches.Count(launch => Directory.Exists(launch.DirectoryPath)));
        return 0;
    }

    [SuppressMessage("Reliability", "CA2000", Justification = "The orphan helper is killed without cleanup on purpose: it keeps its authority and server alive until the process dies.")]
    private static async Task<int> OrphanAsync(string root)
    {
        var authority = LocalRpcLaunchAuthority.Create(root, null, new LaunchEnvironment { ForceUnixSocket = true });
        var launch = authority.Launch("orphan", Launches.Identity());
        var service = new RecordingBootstrapService();
        var server = LocalRpcServer.CreateBuilder(launch.Endpoint!)
            .AddService(service)
            .AuthorizeConnectionsAsync(launch.AuthorizeConnectionAsync)
            .Build();
        await server.StartAsync().ConfigureAwait(false);
        await Say("READY " + Convert.ToBase64String(launch.Descriptor.Encode()) + " " + launch.DirectoryPath);
        GC.KeepAlive(authority);
        GC.KeepAlive(server);
        await Task.Delay(Timeout.InfiniteTimeSpan).ConfigureAwait(false);
        return 0;
    }
}
