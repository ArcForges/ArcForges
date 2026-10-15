// SPDX-License-Identifier: AGPL-3.0-only
using System.Runtime.Versioning;
using ArcForges.Node.Platform;
using ArcForges.Node.Platform.Windows;

namespace ArcForges.Node.Platform.Windows.Tests;

/// <summary>
/// F-W02 (A-W02): real <c>dotnet build</c>, <c>cargo build</c> and <c>cmake --build</c> runs of small projects generated in temporary
/// directories, each run as an attempt in a child job nested under the root job through a real holder. The tools start their own process
/// trees (MSBuild and compiler servers, rustc and the MSVC linker, MSBuild through CMake's Visual Studio generator; Cargo also creates a job
/// of its own for its children), so the builds prove that tools which create their own jobs run correctly inside ArcForges jobs. Every
/// build succeeds, its output runs, every process seen during the build is in the attempt's job, and the build servers left behind are
/// terminated as leftovers and listed in the exit record. Each test is skipped, with its reason, when its tool is missing.
/// </summary>
[Trait("env", "windows-real")]
[Collection(SerialPlatformTests.Name)]
[SupportedOSPlatform("windows")]
public sealed class BuildTests
{
    private static readonly TimeSpan BuildBound = TimeSpan.FromMinutes(5);

    [Fact(Timeout = 600_000)]
    [Trait("tool", "dotnet")]
    public void ADotnetBuildRunsInNestedJobs()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        Assert.SkipUnless(OperatingSystem.IsWindows(), "Builds in Windows nested job objects (Linux execution is AF-EXEC-02).");
        var dotnet = Tool("dotnet");
        using var harness = PlatformHarness.Start();
        var project = Directory.CreateDirectory(Path.Combine(harness.Root, "dotnet-hello")).FullName;
        File.WriteAllText(Path.Combine(project, "hello.csproj"), """
            <Project Sdk="Microsoft.NET.Sdk">
              <PropertyGroup>
                <OutputType>Exe</OutputType>
                <TargetFramework>net10.0</TargetFramework>
                <ImplicitUsings>enable</ImplicitUsings>
              </PropertyGroup>
            </Project>
            """);
        File.WriteAllText(Path.Combine(project, "Program.cs"), "System.Console.WriteLine(\"hello from dotnet\");\n");
        File.WriteAllText(Path.Combine(project, "global.json"), "{ \"sdk\": { \"rollForward\": \"latestMajor\" } }\n");
        var exit = Build(harness, [dotnet, "build", "-c", "Release", "-nologo"], project, out var images);
        Assert.Equal(0, exit.ExitStatus);
        Assert.Contains(images, image => image.Equals("dotnet.exe", StringComparison.OrdinalIgnoreCase));
        Run(harness, Path.Combine(project, "bin", "Release", "net10.0", "hello.exe"), "hello from dotnet");
    }

    [Fact(Timeout = 600_000)]
    [Trait("tool", "cargo")]
    public void ACargoBuildRunsInNestedJobs()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        Assert.SkipUnless(OperatingSystem.IsWindows(), "Builds in Windows nested job objects (Linux execution is AF-EXEC-02).");
        var cargo = Tool("cargo");
        using var harness = PlatformHarness.Start();
        var project = Directory.CreateDirectory(Path.Combine(harness.Root, "cargo-hello")).FullName;
        Directory.CreateDirectory(Path.Combine(project, "src"));
        File.WriteAllText(Path.Combine(project, "Cargo.toml"), "[package]\nname = \"hello\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dependencies]\n");
        File.WriteAllText(Path.Combine(project, "src", "main.rs"), "fn main() { println!(\"hello from cargo\"); }\n");
        var exit = Build(harness, [cargo, "build", "--release", "--offline"], project, out var images);
        Assert.Equal(0, exit.ExitStatus);
        Assert.Contains(images, image => image.Equals("rustc.exe", StringComparison.OrdinalIgnoreCase));
        Run(harness, Path.Combine(project, "target", "release", "hello.exe"), "hello from cargo");
    }

    [Fact(Timeout = 600_000)]
    [Trait("tool", "cmake")]
    public void ACmakeBuildRunsInNestedJobs()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        Assert.SkipUnless(OperatingSystem.IsWindows(), "Builds in Windows nested job objects (Linux execution is AF-EXEC-02).");
        var cmake = Tool("cmake");
        using var harness = PlatformHarness.Start();
        var project = Directory.CreateDirectory(Path.Combine(harness.Root, "cmake-hello")).FullName;
        File.WriteAllText(Path.Combine(project, "CMakeLists.txt"), "cmake_minimum_required(VERSION 3.20)\nproject(hello C)\nadd_executable(hello main.c)\n");
        File.WriteAllText(Path.Combine(project, "main.c"), "#include <stdio.h>\nint main(void) { puts(\"hello from cmake\"); return 0; }\n");
        File.WriteAllText(Path.Combine(project, "build.cmd"), $"@\"{cmake}\" -S . -B build || exit /b 1\r\n@\"{cmake}\" --build build --config Release || exit /b 1\r\n");
        var exit = Build(harness, [Path.Combine(project, "build.cmd")], project, out var images);
        Assert.Equal(0, exit.ExitStatus);
        Assert.Contains(images, image => image.Equals("cmake.exe", StringComparison.OrdinalIgnoreCase));
        Run(harness, Path.Combine(project, "build", "Release", "hello.exe"), "hello from cmake");
    }

    /// <summary>Runs a build as an attempt; every process sampled during it is in the attempt's job.</summary>
    private static ExitRecord Build(PlatformHarness harness, string[] argv, string project, out HashSet<string> images)
    {
        var environment = Environment.GetEnvironmentVariables().Cast<System.Collections.DictionaryEntry>()
            .ToDictionary(entry => (string)entry.Key, entry => (string?)entry.Value ?? string.Empty, StringComparer.OrdinalIgnoreCase);
        environment["DOTNET_CLI_TELEMETRY_OPTOUT"] = "1";
        environment["DOTNET_NOLOGO"] = "1";
        environment["MSBUILDDISABLENODEREUSE"] = "0";
        var handle = harness.Launch(argv, workingDirectory: project, environment: environment, leftoverGraceMs: 2_000);
        images = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var started = System.Diagnostics.Stopwatch.StartNew();
        while (handle.TryReadExit() is null)
        {
            Assert.True(started.Elapsed < BuildBound, "The build did not finish in time.");
            foreach (var process in handle.Processes())
            {
                images.Add(process.Image);
                using var opened = ProcessInfo.Open(process.Pid);
                if (opened is not null)
                {
                    Assert.True(handle.Job.Contains(opened), $"{process.Image} ({process.Pid}) runs outside the attempt's job.");
                    Assert.True(harness.Platform.RootJob!.Contains(opened), $"{process.Image} ({process.Pid}) runs outside the root job.");
                }
            }

            harness.Track(handle);
            Thread.Sleep(100);
        }

        var exit = handle.TryReadExit()!;
        var accounting = handle.Job.Accounting();
        TestContext.Current.TestOutputHelper?.WriteLine(
            $"exit {exit.ExitStatus}; {accounting.TotalProcesses} processes; seen: {string.Join(", ", images.Order())}; leftovers: {string.Join(", ", exit.LeftoversTerminated)}");
        if (exit.ExitStatus != 0)
        {
            TestContext.Current.TestOutputHelper?.WriteLine(PlatformHarness.ReadShared(handle.Files.StdoutPath));
            TestContext.Current.TestOutputHelper?.WriteLine(PlatformHarness.ReadShared(handle.Files.StderrPath));
        }

        Assert.True(accounting.TotalProcesses >= 2, "The build ran a process tree.");
        return exit;
    }

    private static void Run(PlatformHarness harness, string program, string expected)
    {
        var handle = harness.Launch([program]);
        var exit = harness.WaitExit(handle, TimeSpan.FromSeconds(30));
        Assert.Equal(0, exit.ExitStatus);
        Assert.Contains(expected, PlatformHarness.ReadShared(handle.Files.StdoutPath), StringComparison.Ordinal);
    }

    private static string Tool(string name)
    {
        var path = WindowsProgramResolver.Resolve(name, Environment.CurrentDirectory, Environment.GetEnvironmentVariables().Cast<System.Collections.DictionaryEntry>()
            .ToDictionary(entry => (string)entry.Key, entry => (string?)entry.Value ?? string.Empty, StringComparer.OrdinalIgnoreCase));
        Assert.SkipWhen(path is null, $"{name} is not installed (not found on PATH).");
        return path!;
    }
}
