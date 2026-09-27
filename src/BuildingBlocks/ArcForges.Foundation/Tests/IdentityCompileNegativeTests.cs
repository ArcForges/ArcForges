// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using ArcForges.Contracts.Foundation.Values;
using Xunit;

namespace ArcForges.Foundation.Tests;

public sealed class IdentityCompileNegativeTests
{
    private static readonly string[] CompilerOptions = ["-target:library", "-nologo", "-out:Invalid.dll"];
    [Fact]
    public void PublishedIdentifierKindsCannotBeAssignedOrCompared()
    {
        var directory = Path.Combine(Path.GetTempPath(), "arcforges-identity-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        try
        {
            File.WriteAllText(Path.Combine(directory, "Invalid.cs"), """
                using ArcForges.Contracts.Foundation.Values;
                public static class Invalid {
                  public static void Check(WorkspaceId workspace, CommandId command, InstanceId instance) {
                    RealmId realm = workspace;
                    command = instance;
                    bool equal = workspace == command;
                    bool revisionEqualsSequence = default(ArcForges.Foundation.Revision) == default(ArcForges.Foundation.SequenceNumber);
                  }
                }
                """);
            var host = Environment.GetEnvironmentVariable("DOTNET_HOST_PATH") ?? "dotnet";
            var sdkQuery = new ProcessStartInfo(host) { RedirectStandardOutput = true, UseShellExecute = false };
            sdkQuery.ArgumentList.Add("--list-sdks");
            using var sdkProcess = Process.Start(sdkQuery)!;
            var sdkLines = sdkProcess.StandardOutput.ReadToEnd().Split('\n', StringSplitOptions.RemoveEmptyEntries);
            sdkProcess.WaitForExit();
            var sdk = sdkLines.Last(line => line.StartsWith("10.", StringComparison.Ordinal)).Trim();
            var bracket = sdk.IndexOf('[', StringComparison.Ordinal);
            var sdkPath = Path.Combine(sdk[(bracket + 1)..^1], sdk[..bracket].Trim());
            var references = ((string)AppContext.GetData("TRUSTED_PLATFORM_ASSEMBLIES")!).Split(Path.PathSeparator)
                .Append(Path.Combine(AppContext.BaseDirectory, "ArcForges.Contracts.Foundation.dll"))
                .Append(Path.Combine(AppContext.BaseDirectory, "ArcForges.Foundation.dll")).Distinct(StringComparer.OrdinalIgnoreCase);
            var response = Path.Combine(directory, "compile.rsp");
            File.WriteAllLines(response, CompilerOptions
                .Concat(references.Select(path => "-r:\"" + path + "\""))
                .Append("Invalid.cs"));
            var compiler = new ProcessStartInfo(host)
            {
                WorkingDirectory = directory,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
            };
            compiler.ArgumentList.Add(Path.Combine(sdkPath, "Roslyn", "bincore", "csc.dll"));
            compiler.ArgumentList.Add("@" + response);
            using var process = Process.Start(compiler)!;
            var output = process.StandardOutput.ReadToEnd() + process.StandardError.ReadToEnd();
            process.WaitForExit();
            Assert.NotEqual(0, process.ExitCode);
            Assert.Equal(2, output.Split("error CS0029", StringSplitOptions.None).Length - 1);
            Assert.Equal(2, output.Split("error CS0019", StringSplitOptions.None).Length - 1);
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }
}
