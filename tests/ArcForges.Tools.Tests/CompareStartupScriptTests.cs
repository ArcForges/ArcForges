// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using System.Globalization;
using System.IO.Compression;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;

namespace ArcForges.Tools.Tests;

/// <summary>
/// <c>eng/compare-startup.ps1</c>, the CI startup gate, run with the real <c>pwsh</c> and <c>arcforges-bench</c> against a local stand-in of
/// the GitHub REST API (a loopback HTTP server answering the three requests the script makes). The previous main run's CLI comes from its
/// <c>startup-host</c> artifact and is measured on this machine with the current CLI, interleaved; without a main run or without the
/// artifact the current result passes with the stated reason; any other API failure fails the step; the token reaches only the API.
/// <c>arcforges-testload</c> stands in for both CLIs (the measured command is a parameter).
/// </summary>
[Trait("tool", "pwsh")]
public sealed class CompareStartupScriptTests
{
    private const string Repository = "owner/repo";
    private const string Token = "test-token-not-a-secret";

    private static string Rid => (OperatingSystem.IsWindows() ? "win-" : "linux-") + (System.Runtime.InteropServices.RuntimeInformation.OSArchitecture == System.Runtime.InteropServices.Architecture.Arm64 ? "arm64" : "x64");

    private static string Suffix => OperatingSystem.IsWindows() ? ".exe" : string.Empty;

    [Fact(Timeout = 120_000)]
    public async Task ALocalBaselineExecutableIsMeasuredInterleavedOnThisMachine()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        var pwsh = RequirePwsh();
        using var directory = new TemporaryDirectory();
        var run = await RunScriptAsync(pwsh, directory.Path, ["-BaselineExecutable", ToolProcess.TestLoad], environment: new Dictionary<string, string?>());

        Assert.True(run.ExitCode == 0, run.Output);
        var comparison = Comparison(directory.Path);
        Assert.Equal("interleaved-same-runner", comparison.GetProperty("method").GetString());
        Assert.Equal("pass", comparison.GetProperty("status").GetString());
        Assert.Equal(4, comparison.GetProperty("current").GetProperty("samplesMs").GetArrayLength());
        Assert.Equal(4, comparison.GetProperty("baseline").GetProperty("samplesMs").GetArrayLength());
        Assert.Contains("measured on this machine", comparison.GetProperty("baselineSource").GetString(), StringComparison.Ordinal);
    }

    [Fact(Timeout = 120_000)]
    public async Task ThePreviousMainRunsCliIsDownloadedAndMeasuredHereAndTheTokenReachesOnlyTheApi()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        var pwsh = RequirePwsh();
        using var directory = new TemporaryDirectory();
        var archive = Path.Combine(directory.Path, "artifact.zip");
        using (var zip = ZipFile.Open(archive, ZipArchiveMode.Create))
        {
            // The stand-in CLI: testload under the CLI's name, with its managed files when it is the JIT build (its apphost loads them).
            zip.CreateEntryFromFile(ToolProcess.TestLoad, "arcforges" + Suffix);
            foreach (var file in Directory.EnumerateFiles(Path.GetDirectoryName(ToolProcess.TestLoad)!, "arcforges-testload.*")
                .Where(file => Path.GetExtension(file) is ".dll" or ".json"))
            {
                zip.CreateEntryFromFile(file, Path.GetFileName(file));
            }
        }

        await using var api = FakeApi.Start(request => request.Path switch
        {
            var path when path.StartsWith($"/repos/{Repository}/actions/workflows/ci.yml/runs", StringComparison.Ordinal) =>
                FakeApi.Json("""{"workflow_runs":[{"id":101,"head_sha":"abc123"}]}"""),
            var path when path.StartsWith($"/repos/{Repository}/actions/runs/101/artifacts?name=startup-host-{Rid}-abc123", StringComparison.Ordinal) =>
                FakeApi.Json($$"""{"artifacts":[{"expired":false,"archive_download_url":"{{request.Origin}}/download/1"}]}"""),
            "/download/1" => FakeApi.Redirect($"{request.Origin}/blob/1"),
            "/blob/1" => FakeApi.File(archive),
            _ => FakeApi.Status(404),
        });

        var run = await RunScriptAsync(pwsh, directory.Path, [], api.Environment);

        Assert.True(run.ExitCode == 0, run.Output);
        var comparison = Comparison(directory.Path);
        Assert.Equal("interleaved-same-runner", comparison.GetProperty("method").GetString());
        Assert.Contains("CI run 101 on main at abc123", comparison.GetProperty("baselineSource").GetString(), StringComparison.Ordinal);
        Assert.True(comparison.TryGetProperty("baselineP95Ms", out _));
        Assert.True(comparison.TryGetProperty("currentP95Ms", out _));
        Assert.All(api.Requests.Where(request => !request.Path.StartsWith("/blob/", StringComparison.Ordinal)),
            request => Assert.Equal("Bearer " + Token, request.Authorization));
        Assert.Null(Assert.Single(api.Requests, request => request.Path == "/blob/1").Authorization);
    }

    [Theory(Timeout = 120_000)]
    [InlineData(false, "No successful main-push CI run exists yet")]
    [InlineData(true, "has no unexpired startup-host-")]
    public async Task WithoutAMainRunOrItsCliTheCurrentResultPassesWithTheReason(bool runExists, string reason)
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        var pwsh = RequirePwsh();
        using var directory = new TemporaryDirectory();
        await File.WriteAllTextAsync(Path.Combine(directory.Path, "startup-arcforges-version.json"), StartupJson(14), TestContext.Current.CancellationToken);
        await using var api = FakeApi.Start(request => request.Path switch
        {
            var path when path.Contains("/actions/workflows/ci.yml/runs", StringComparison.Ordinal) =>
                FakeApi.Json(runExists ? """{"workflow_runs":[{"id":7,"head_sha":"def456"}]}""" : """{"workflow_runs":[]}"""),
            var path when path.Contains("/actions/runs/7/artifacts", StringComparison.Ordinal) => FakeApi.Json("""{"artifacts":[]}"""),
            _ => FakeApi.Status(404),
        });

        var run = await RunScriptAsync(pwsh, directory.Path, [], api.Environment);

        Assert.True(run.ExitCode == 0, run.Output);
        var comparison = Comparison(directory.Path);
        Assert.Equal("no-baseline", comparison.GetProperty("status").GetString());
        Assert.Contains(reason, comparison.GetProperty("reason").GetString(), StringComparison.Ordinal);
        Assert.Equal(14, comparison.GetProperty("currentP50Ms").GetDouble());
    }

    [Fact(Timeout = 120_000)]
    public async Task AnyOtherApiFailureFailsTheStep()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        var pwsh = RequirePwsh();
        using var directory = new TemporaryDirectory();
        await using var api = FakeApi.Start(_ => FakeApi.Status(500));

        var run = await RunScriptAsync(pwsh, directory.Path, [], api.Environment);

        Assert.NotEqual(0, run.ExitCode);
        Assert.False(File.Exists(Path.Combine(directory.Path, "startup-comparison.json")));
    }

    [Fact(Timeout = 120_000)]
    public async Task WithoutTheTokenTheGateFailsInsteadOfPassing()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        var pwsh = RequirePwsh();
        using var directory = new TemporaryDirectory();

        var run = await RunScriptAsync(pwsh, directory.Path, [], new Dictionary<string, string?> { ["GITHUB_TOKEN"] = null, ["GITHUB_REPOSITORY"] = Repository });

        Assert.NotEqual(0, run.ExitCode);
        Assert.Contains("GITHUB_TOKEN and GITHUB_REPOSITORY are required", run.Output, StringComparison.Ordinal);
    }

    private static string RequirePwsh()
    {
        var name = OperatingSystem.IsWindows() ? "pwsh.exe" : "pwsh";
        var found = (Environment.GetEnvironmentVariable("PATH") ?? string.Empty).Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries)
            .Select(directory => Path.Combine(directory, name)).FirstOrDefault(File.Exists);
        Assert.SkipWhen(found is null, "pwsh is not installed (not found on PATH).");
        return found!;
    }

    private static JsonElement Comparison(string results)
    {
        using var document = JsonDocument.Parse(File.ReadAllBytes(Path.Combine(results, "startup-comparison.json")));
        return document.RootElement.Clone();
    }

    private static async Task<(int ExitCode, string Output)> RunScriptAsync(string pwsh, string results, string[] extra, IReadOnlyDictionary<string, string?> environment)
    {
        var script = Path.Combine(RepositoryRoot(), "eng", "compare-startup.ps1");
        var start = new ProcessStartInfo(pwsh)
        {
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
        };
        // -Command, so -Arguments is a real array (the measured command: testload cpu --iterations 1).
        static string Quote(string value) => "'" + value.Replace("'", "''", StringComparison.Ordinal) + "'";
        var invocation = new StringBuilder("& ").Append(Quote(script));
        foreach (var argument in (string[])["-RuntimeIdentifier", Rid, "-ResultsDirectory", results, "-Bench", ToolProcess.Bench,
            "-CurrentExecutable", ToolProcess.TestLoad, "-Runs", "4", "-NoiseFloorMs", "60000", "-Name", "testload cpu", .. extra])
        {
            invocation.Append(' ').Append(argument.StartsWith('-') ? argument : Quote(argument));
        }

        invocation.Append(" -Arguments @('cpu', '--iterations', '1'); exit $LASTEXITCODE");
        foreach (var argument in (string[])["-NoProfile", "-NonInteractive", "-Command", invocation.ToString()])
        {
            start.ArgumentList.Add(argument);
        }

        foreach (var name in (string[])["GITHUB_TOKEN", "GITHUB_REPOSITORY", "GITHUB_API_URL", "GITHUB_RUN_ID"])
        {
            start.Environment.Remove(name);
        }

        foreach (var (name, value) in environment)
        {
            if (value is null)
            {
                start.Environment.Remove(name);
            }
            else
            {
                start.Environment[name] = value;
            }
        }

        using var process = Process.Start(start)!;
        var output = process.StandardOutput.ReadToEndAsync(TestContext.Current.CancellationToken);
        var error = process.StandardError.ReadToEndAsync(TestContext.Current.CancellationToken);
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(TestContext.Current.CancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(90));
        try
        {
            await process.WaitForExitAsync(timeout.Token);
        }
        finally
        {
            if (!process.HasExited)
            {
                process.Kill(entireProcessTree: true);
            }
        }

        return (process.ExitCode, await output + await error);
    }

    private static string RepositoryRoot()
    {
        for (var directory = new DirectoryInfo(AppContext.BaseDirectory); directory is not null; directory = directory.Parent)
        {
            if (File.Exists(Path.Combine(directory.FullName, "eng", "compare-startup.ps1")))
            {
                return directory.FullName;
            }
        }

        throw new InvalidOperationException("The repository root (eng/compare-startup.ps1) was not found above the test binaries.");
    }

    private static string StartupJson(double p50) => string.Create(CultureInfo.InvariantCulture, $$"""
        {"tool":"arcforges-bench","schemaVersion":1,"benchmark":"startup","name":"arcforges --version","command":["arcforges"],
         "runs":1,"warmup":0,"samplesMs":[{{p50}}],"p50Ms":{{p50}},"p95Ms":{{p50}},"minMs":{{p50}},"maxMs":{{p50}},"meanMs":{{p50}},
         "pass":true,"environment":{"os":"test","architecture":"X64","runtimeIdentifier":"{{Rid}}","processorCount":4,"framework":".NET 10"} }
        """);

    /// <summary>A request the stand-in API received: the path with its query, and the Authorization header (null when absent).</summary>
    private sealed record FakeRequest(string Path, string? Authorization, string Origin);

    /// <summary>A response: status, headers and body.</summary>
    private sealed record FakeResponse(int Status, string ContentType, byte[] Body, string? Location = null);

    /// <summary>A loopback HTTP/1.1 server answering each request with <c>Connection: close</c>; it records the requests.</summary>
    private sealed class FakeApi : IAsyncDisposable
    {
        private readonly TcpListener _listener;
        private readonly Func<FakeRequest, FakeResponse> _handler;
        private readonly CancellationTokenSource _stop = new();
        private readonly Task _loop;
        private readonly List<FakeRequest> _requests = [];

        private FakeApi(Func<FakeRequest, FakeResponse> handler)
        {
            _handler = handler;
            _listener = new TcpListener(IPAddress.Loopback, 0);
            _listener.Start();
            _loop = Task.Run(LoopAsync);
        }

        public string Origin => $"http://127.0.0.1:{((IPEndPoint)_listener.LocalEndpoint).Port.ToString(CultureInfo.InvariantCulture)}";

        public IReadOnlyDictionary<string, string?> Environment => new Dictionary<string, string?>
        {
            ["GITHUB_TOKEN"] = Token,
            ["GITHUB_REPOSITORY"] = Repository,
            ["GITHUB_API_URL"] = Origin,
            ["GITHUB_RUN_ID"] = "999",
        };

        public IReadOnlyList<FakeRequest> Requests
        {
            get
            {
                lock (_requests)
                {
                    return [.. _requests];
                }
            }
        }

        public static FakeApi Start(Func<FakeRequest, FakeResponse> handler) => new(handler);

        public static FakeResponse Json(string body) => new(200, "application/json", Encoding.UTF8.GetBytes(body));

        public static FakeResponse File(string path) => new(200, "application/zip", System.IO.File.ReadAllBytes(path));

        public static FakeResponse Redirect(string location) => new(302, "text/plain", [], location);

        public static FakeResponse Status(int status) => new(status, "text/plain", Encoding.UTF8.GetBytes("error"));

        public async ValueTask DisposeAsync()
        {
            await _stop.CancelAsync();
            _listener.Stop();
            try
            {
                await _loop;
            }
            catch (Exception exception) when (exception is OperationCanceledException or SocketException or ObjectDisposedException)
            {
            }

            _stop.Dispose();
        }

        private async Task LoopAsync()
        {
            while (!_stop.IsCancellationRequested)
            {
                using var client = await _listener.AcceptTcpClientAsync(_stop.Token);
                await using var stream = client.GetStream();
                using var reader = new StreamReader(stream, Encoding.ASCII, leaveOpen: true);
                var requestLine = await reader.ReadLineAsync(_stop.Token) ?? string.Empty;
                string? authorization = null;
                while (await reader.ReadLineAsync(_stop.Token) is { Length: > 0 } header)
                {
                    if (header.StartsWith("Authorization:", StringComparison.OrdinalIgnoreCase))
                    {
                        authorization = header["Authorization:".Length..].Trim();
                    }
                }

                var parts = requestLine.Split(' ');
                var request = new FakeRequest(parts.Length > 1 ? parts[1] : "/", authorization, Origin);
                lock (_requests)
                {
                    _requests.Add(request);
                }

                var response = _handler(request);
                var head = new StringBuilder()
                    .Append(CultureInfo.InvariantCulture, $"HTTP/1.1 {response.Status} X\r\n")
                    .Append(CultureInfo.InvariantCulture, $"Content-Type: {response.ContentType}\r\n")
                    .Append(CultureInfo.InvariantCulture, $"Content-Length: {response.Body.Length}\r\n")
                    .Append("Connection: close\r\n");
                if (response.Location is { } location)
                {
                    head.Append(CultureInfo.InvariantCulture, $"Location: {location}\r\n");
                }

                head.Append("\r\n");
                await stream.WriteAsync(Encoding.ASCII.GetBytes(head.ToString()), _stop.Token);
                await stream.WriteAsync(response.Body, _stop.Token);
            }
        }
    }
}
