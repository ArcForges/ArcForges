// SPDX-License-Identifier: AGPL-3.0-only

using System.Diagnostics;
using System.Globalization;
using System.Text;
using ArcForges.Foundation.Versions;
using Xunit;

namespace ArcForges.Foundation.Tests;

public sealed class VersionAxisCompileNegativeTests
{
    [Fact]
    public async Task EveryOrderedAxisPairRejectsAssignment()
    {
        string[] axes = [nameof(AppVersion), nameof(ContractSet), nameof(CapabilityVersion), nameof(NativeFormatVersion), nameof(StorageSchemaVersion), nameof(NativeAbiVersion), nameof(PolicySchemaVersion), nameof(ExtensionProtocolVersion), nameof(PackageVersion)];
        var sdkList = await RunAsync("dotnet", ["--list-sdks"]);
        Assert.Equal(0, sdkList.ExitCode);
        var sdk = sdkList.Output.Split('\n', StringSplitOptions.RemoveEmptyEntries).Last(line => line.TrimStart().StartsWith(Environment.Version.Major.ToString(CultureInfo.InvariantCulture) + ".", StringComparison.Ordinal));
        var bracket = sdk.IndexOf('[', StringComparison.Ordinal);
        var sdkRoot = sdk[(bracket + 1)..sdk.IndexOf(']', StringComparison.Ordinal)];
        var sdkVersion = sdk[..bracket].Trim();
        var compiler = Path.Combine(sdkRoot, sdkVersion, "Roslyn", "bincore", "csc.dll");
        Assert.True(File.Exists(compiler));
        var temporary = Path.Combine(Path.GetTempPath(), "arcforges-version-axis-" + Guid.NewGuid().ToString("N", CultureInfo.InvariantCulture));
        Directory.CreateDirectory(temporary);
        try
        {
            var references = ((string?)AppContext.GetData("TRUSTED_PLATFORM_ASSEMBLIES"))!.Split(Path.PathSeparator).Append(typeof(AppVersion).Assembly.Location).Distinct(StringComparer.Ordinal).ToArray();
            var response = new StringBuilder("/nologo\n/target:library\n/nostdlib+\n");
            foreach (var reference in references) response.Append("/reference:\"").Append(reference).AppendLine("\"");
            response.Append("/out:\"").Append(Path.Combine(temporary, "vectors.dll")).AppendLine("\"");
            var sourcePath = Path.Combine(temporary, "vectors.cs");
            response.Append('"').Append(sourcePath).AppendLine("\"");
            var responsePath = Path.Combine(temporary, "compiler.rsp");
            await File.WriteAllTextAsync(responsePath, response.ToString());
            var positive = new StringBuilder("using ArcForges.Foundation.Versions;\npublic static class Vectors { public static void Check() {\n");
            for (var index = 0; index < axes.Length; index++)
                positive.Append(axes[index]).Append(" p").Append(index).Append(" = default(").Append(axes[index]).AppendLine(");");
            positive.AppendLine("} }");
            await File.WriteAllTextAsync(sourcePath, positive.ToString());
            var control = await RunAsync("dotnet", [compiler, "@" + responsePath]);
            Assert.True(control.ExitCode == 0, control.Output);

            var negative = new StringBuilder("using ArcForges.Foundation.Versions;\npublic static class Vectors { public static void Check() {\n");
            var pair = 0;
            foreach (var target in axes)
                foreach (var source in axes)
                    if (target != source)
                        negative.Append(target).Append(" p").Append(pair++).Append(" = default(").Append(source).AppendLine(");");
            negative.AppendLine("} }");
            await File.WriteAllTextAsync(sourcePath, negative.ToString());
            var result = await RunAsync("dotnet", [compiler, "@" + responsePath]);
            Assert.NotEqual(0, result.ExitCode);
            var errors = result.Output.Split('\n').Where(line => line.Contains("error ", StringComparison.Ordinal)).ToArray();
            Assert.Equal(72, errors.Length);
            for (var index = 0; index < 72; index++)
            {
                var location = "vectors.cs(" + (index + 3).ToString(CultureInfo.InvariantCulture) + ",";
                Assert.Contains(errors, line => line.Contains(location, StringComparison.Ordinal) && line.Contains("error CS0029:", StringComparison.Ordinal));
            }
        }
        finally
        {
            Directory.Delete(temporary, recursive: true);
        }
    }

    private static async Task<(int ExitCode, string Output)> RunAsync(string executable, string[] arguments)
    {
        var start = new ProcessStartInfo(executable) { RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false, CreateNoWindow = true };
        foreach (var argument in arguments) start.ArgumentList.Add(argument);
        using var process = Process.Start(start)!;
        var output = process.StandardOutput.ReadToEndAsync();
        var error = process.StandardError.ReadToEndAsync();
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(60));
        try
        {
            await process.WaitForExitAsync(timeout.Token);
        }
        catch (OperationCanceledException)
        {
            process.Kill(entireProcessTree: true);
            throw;
        }
        return (process.ExitCode, await output + await error);
    }
}
