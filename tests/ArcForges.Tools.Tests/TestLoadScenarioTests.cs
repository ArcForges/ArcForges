// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.TestLoad;

namespace ArcForges.Tools.Tests;

/// <summary>In-process scenario logic: determinism, parameter identity, text layout and bounds.</summary>
public sealed class TestLoadScenarioTests
{
    // Reference digests recorded once; equal results on Windows and Linux prove platform-independent bytes.
    private const string CpuReference = "eb1f04b42be349a3fb07e554574e41ed27cdf348f51ce89ae4b91cd99e0c7c94";
    private const string OutputReference = "0258c2d5ee1cac75510fa12434ec0f74417814644d2cff0b41ff92809f94f264";
    private const string MemoryReference = "e3d39ae5be2c70798c019aacda235bdfc30797c03cddd96a2e1f031ce410ece5";

    [Fact]
    public void CpuDigestIsReproducibleAndIdentifiesEveryParameter()
    {
        var first = Cpu("--threads", "2", "--iterations", "1000", "--seed", "7");
        var second = Cpu("--threads", "2", "--iterations", "1000", "--seed", "7");

        Assert.Equal(first.Digest, second.Digest);
        Assert.Equal(CpuReference, first.Digest);
        Assert.Equal(2000, first.Results["totalIterations"]);
        Assert.NotEqual(first.Digest, Cpu("--threads", "2", "--iterations", "1000", "--seed", "8").Digest);
        Assert.NotEqual(first.Digest, Cpu("--threads", "2", "--iterations", "1001", "--seed", "7").Digest);
        Assert.NotEqual(first.Digest, Cpu("--threads", "3", "--iterations", "1000", "--seed", "7").Digest);
    }

    [Fact]
    public void ReportsListResolvedDefaultsButNotTheReportPath()
    {
        var report = Cpu("--iterations", "10", "--report", "ignored.json");

        Assert.Equal(
            new Dictionary<string, string> { ["iterations"] = "10", ["seed"] = "1", ["threads"] = "1" },
            report.Parameters);
        Assert.Equal(report.Digest, Cpu("--iterations", "10").Digest);
    }

    [Fact]
    public void OutputTextIsFixedLengthLinesOfTheAlphabet()
    {
        var text = new byte[1000];
        OutputScenario.Fill(3, 10, 0, text);

        for (var i = 0; i < text.Length; i++)
        {
            if (i % 10 == 9)
            {
                Assert.Equal((byte)'\n', text[i]);
            }
            else
            {
                Assert.Contains((char)text[i], "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/");
            }
        }
    }

    [Theory]
    [InlineData(0, 1000)]
    [InlineData(1, 999)]
    [InlineData(7, 13)]
    [InlineData(8, 64)]
    [InlineData(333, 667)]
    public void OutputTextAtAnyOffsetEqualsTheSameSliceOfTheWholeText(int offset, int length)
    {
        var whole = new byte[1000];
        OutputScenario.Fill(3, 17, 0, whole);
        var part = new byte[length];

        OutputScenario.Fill(3, 17, offset, part);

        Assert.Equal(whole.AsSpan(offset, length).ToArray(), part);
    }

    [Fact]
    public void OutputDigestIsReproducible()
    {
        var report = OutputScenario.Run(Options("--bytes", "100000", "--line-bytes", "80", "--seed", "3", "--stream", "none"));

        Assert.Equal(OutputReference, report.Digest);
        Assert.Equal(100000, report.Results["bytes"]);
        Assert.Equal(1250, report.Results["lines"]);
        Assert.Equal(0, report.Results["stdoutBytes"]);
        Assert.Empty(report.StreamDigests!);
    }

    [Fact]
    public void MemoryRampAllocatesTheTargetInStepsReproducibly()
    {
        var first = MemoryRampScenario.Run(Options("--target-mb", "3", "--step-mb", "2", "--seed", "5"));
        var second = MemoryRampScenario.Run(Options("--target-mb", "3", "--step-mb", "2", "--seed", "5"));

        Assert.Equal(3L * 1024 * 1024, first.Results["allocatedBytes"]);
        Assert.Equal(2, first.Results["steps"]);
        Assert.Equal(first.Digest, second.Digest);
        Assert.Equal(MemoryReference, first.Digest);
    }

    [Theory]
    [InlineData(1, 0, 1)]
    [InlineData(1, 8, 9)]
    [InlineData(2, 2, 7)]
    [InlineData(3, 3, 40)]
    [InlineData(4, 4, 341)]
    public void ForkProcessCountFollowsTheTreeShape(long width, long depth, long expected) =>
        Assert.Equal(expected, ForkScenario.ExpectedProcesses(width, depth));

    [Theory]
    [InlineData("cpu", "--threads", "0")]
    [InlineData("cpu", "--threads", "257")]
    [InlineData("cpu", "--iterations", "-1")]
    [InlineData("cpu", "--iterations", "ten")]
    [InlineData("cpu", "--unknown", "1")]
    [InlineData("cpu", "--seed")]
    [InlineData("cpu", "threads", "1")]
    [InlineData("cpu", "--threads", "1", "--threads", "2")]
    [InlineData("mem-ramp", "--target-mb", "65537")]
    [InlineData("mem-ramp", "--target-mb", "4", "--step-mb", "5")]
    [InlineData("mem-ramp", "--target-mb", "4096", "--step-mb", "1025")]
    [InlineData("mem-ramp", "--target-mb", "4096", "--step-mb", "2048")]
    [InlineData("output", "--stream", "file")]
    [InlineData("output", "--line-bytes", "0")]
    [InlineData("fork", "--width", "4", "--depth", "5")]
    [InlineData("fork", "--depth", "9")]
    public void OutOfBoundsOrUnknownParametersAreRejected(string scenario, params string[] arguments)
    {
        void Run()
        {
            var options = ScenarioOptions.Parse(arguments);
            switch (scenario)
            {
                case "cpu":
                    CpuScenario.Run(options);
                    break;
                case "mem-ramp":
                    MemoryRampScenario.Run(options);
                    break;
                case "output":
                    OutputScenario.Run(options);
                    break;
                default:
                    ForkScenario.RunAsync(options).GetAwaiter().GetResult();
                    break;
            }
        }

        Assert.Throws<UsageException>(Run);
    }

    private static ScenarioReport Cpu(params string[] arguments) => CpuScenario.Run(Options(arguments));

    private static ScenarioOptions Options(params string[] arguments) => ScenarioOptions.Parse(arguments);
}
