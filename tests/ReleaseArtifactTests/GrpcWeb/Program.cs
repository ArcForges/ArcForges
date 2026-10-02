// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics.CodeAnalysis;
using System.Text;

namespace ArcForges.ReleaseArtifactTests.GrpcWeb;

internal static class Program
{
    [SuppressMessage("Usage", "CA1031", Justification = "This executable is a test boundary: any unexpected failure is reported and returned as a failing exit code.")]
    public static async Task<int> Main(string[] args)
    {
        var parsed = ProbeOptionsParser.Parse(args, name => Environment.GetEnvironmentVariable(name));
        if (parsed.Options is not { } options)
        {
            await Console.Error.WriteLineAsync(parsed.Error).ConfigureAwait(false);
            await Console.Error.WriteLineAsync(ProbeOptionsParser.Usage).ConfigureAwait(false);
            return 2;
        }

        if (options.Mode == ProbeMode.Live && !RuntimeIdentity.IsNativeAot)
        {
            await Console.Error.WriteLineAsync(
                "Live evidence comes only from the published Native AOT executable: dotnet publish tests/ReleaseArtifactTests/GrpcWeb/GrpcWebAotProbe.csproj -c Release -r <rid>.")
                .ConfigureAwait(false);
            return 2;
        }

        CheckRecorder recorder;
        try
        {
            recorder = options.Mode == ProbeMode.Live ? await RunLiveAsync(options).ConfigureAwait(false) : await SelfTest.RunAsync().ConfigureAwait(false);
        }
        catch (Exception error)
        {
            await Console.Error.WriteLineAsync("FAIL: the probe stopped unexpectedly: " + error.GetType().Name + ": " + error.Message).ConfigureAwait(false);
            return 1;
        }

        foreach (var check in recorder.Results)
        {
            Console.WriteLine((check.Passed ? "pass " : "FAIL ") + check.Name + " - " + check.Detail);
        }

        bool aot = RuntimeIdentity.IsNativeAot;
        string runtime = aot ? "Native AOT executable" : "JIT run (not Native AOT evidence)";
        string subject = options.Mode == ProbeMode.Live
            ? "live gRPC-Web checks against " + options.BaseAddress!.GetLeftPart(UriPartial.Path)
            : "fixture self-test; this is not evidence about any real ingress";
        Console.WriteLine((recorder.AllPassed ? "PASS: " : "FAIL: ") + subject + " (" + runtime + ", " + recorder.Results.Count + " checks).");
        if (options.EvidencePath is { } path)
        {
            await File.WriteAllTextAsync(path, EvidenceWriter.Build(options, recorder, DateTimeOffset.UtcNow), new UTF8Encoding(false)).ConfigureAwait(false);
        }

        return recorder.AllPassed ? 0 : 1;
    }

    private static async Task<CheckRecorder> RunLiveAsync(ProbeOptions options)
    {
        var recorder = new CheckRecorder();
        var target = new ScenarioTarget
        {
            BaseAddress = options.BaseAddress!,
            CreateTransport = () => ProbeChannel.CreateRealTransport(useSystemProxy: true),
            Live = true,
            ExpectedRevision = options.ExpectedRevision,
        };
        await HelloScenarios.RunCommonAsync(target, recorder).ConfigureAwait(false);
        CodecPrimitives.Run(recorder);
        return recorder;
    }
}
