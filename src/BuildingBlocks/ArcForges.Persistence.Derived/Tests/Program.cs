// SPDX-License-Identifier: AGPL-3.0-only
namespace ArcForges.Persistence.Derived.Tests;

internal static class Program
{
    public static int Main(string[] args) => args.Any(argument => argument is "--server" or "--internal-msbuild-node")
        ? Xunit.MicrosoftTestingPlatform.TestPlatformTestFramework.RunAsync(args, SelfRegisteredExtensions.AddSelfRegisteredExtensions).GetAwaiter().GetResult()
        : Xunit.Runner.InProc.SystemConsole.ConsoleRunner.Run(args).GetAwaiter().GetResult();
}
