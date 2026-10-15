// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using System.Text.Json;

namespace ArcForges.Node.Store.Tests;

/// <summary>
/// The store growth bound (15-performance-targets section 2; node-store.md section 4) at CI scale: the real arcforges-bench
/// store-growth workload with 1,000 attempts from the captured environments stays within its scaled limit
/// (50 MB per 10,000 attempts). The full 10,000-attempt run is part of eng/bench.ps1.
/// </summary>
[Trait("env", "windows-real")]
[Trait("env", "linux-real")]
public sealed class StoreGrowthTests
{
    [Fact]
    public async Task ThousandAttemptsStayWithinTheScaledGrowthLimit()
    {
        TestSecretStores.RequireRealSecretStore();
        var written = Path.Combine(Path.GetTempPath(), "arcforges-store-growth-" + Guid.NewGuid().ToString("N") + ".json");
        using var process = Process.Start(BenchExecutable.StartInfo("store-growth", "--attempts", "1000", "--seed", "7", "--output", written))!;
        var output = process.StandardOutput.ReadToEndAsync(TestContext.Current.CancellationToken);
        var errors = process.StandardError.ReadToEndAsync(TestContext.Current.CancellationToken);
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(TestContext.Current.CancellationToken);
        timeout.CancelAfter(TimeSpan.FromMinutes(5));
        await process.WaitForExitAsync(timeout.Token);

        Assert.True(process.ExitCode == 0, await errors);
        var printed = await output;
        Assert.Equal(printed.TrimEnd(), (await File.ReadAllTextAsync(written, TestContext.Current.CancellationToken)).TrimEnd());
        File.Delete(written);
        using var result = JsonDocument.Parse(printed);
        var root = result.RootElement;
        Assert.Equal("store-growth", root.GetProperty("benchmark").GetString());
        Assert.Equal(1000, root.GetProperty("attempts").GetInt32());
        Assert.Equal(5_000_000, root.GetProperty("limitBytes").GetInt64());
        Assert.True(root.GetProperty("pass").GetBoolean());
        Assert.True(root.GetProperty("growthBytes").GetInt64() <= 5_000_000);
        Assert.True(root.GetProperty("sealedTasks").GetInt32() > 0);
        Assert.True(root.GetProperty("distinctEnvironments").GetInt64() < 100);
        Assert.Equal(1000L, root.GetProperty("tables").EnumerateArray().Single(table => table.GetProperty("table").GetString() == "attempt").GetProperty("rows").GetInt64());
    }
}
