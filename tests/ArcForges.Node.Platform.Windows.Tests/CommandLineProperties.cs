// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Text.Json;
using ArcForges.Node.Platform;
using ArcForges.Node.Platform.Windows;
using ArcForges.Tests;
using CsCheck;

namespace ArcForges.Node.Platform.Windows.Tests;

/// <summary>
/// Properties of the Windows command lines (architecture 04 section 2; R-EXE-003 identical arguments; threat T-03), over generated argument
/// vectors instead of a fixed corpus: arguments survive <see cref="WindowsCommandLine.Build"/> exactly, through the managed parser and the
/// real <c>CommandLineToArgvW</c>; a batch file receives every argument it accepts unchanged through the real <c>cmd.exe</c>, and every
/// other one is refused with <c>unsafe_batch_argument</c> at its index.
/// </summary>
public sealed partial class CommandLineProperties
{
    /// <summary>Characters whose handling differs between quoting rules, ordinary characters and non-ASCII ones (no NUL).</summary>
    private static readonly Gen<char> ArgumentChar = Gen.Frequency(
        (4, Gen.Char["\\\" \t"]),
        (4, Gen.Char.AlphaNumeric),
        (2, Gen.Char["%!^&|<>(),;=*?'`.-:/"]),
        (1, Gen.Char["\n\v\räöü中文"]));

    private static readonly Gen<string> Argument = Gen.String[ArgumentChar, 0, 12];

    /// <summary>A program token: no quote, line break or NUL (refused otherwise), sometimes with spaces and a trailing backslash.</summary>
    private static readonly Gen<string> Program = Gen.String[Gen.Frequency((6, Gen.Char.AlphaNumeric), (2, Gen.Char["\\ :._-"]), (1, Gen.Char["\t()ä"])), 1, 16];

    private static readonly Gen<string[]> Argv = Gen.Select(Program, Argument.Array[0, 6], (program, arguments) => (string[])[program, .. arguments]);

    [Fact]
    public void EveryArgumentVectorParsesBackFromItsCommandLine() =>
        Argv.Sample(argv => Assert.Equal(argv, WindowsCommandLine.Parse(WindowsCommandLine.Build(argv))), iter: PropertyRuns.Iter(2_000), print: Print);

    [Fact]
    public void AnArgumentWithNulOrAProgramWithAQuoteIsRefusedNeverMisquoted() =>
        Gen.Select(Argv, Gen.Int[0, 5], Gen.Bool, (argv, at, inProgram) => (argv, at, inProgram)).Sample(item =>
        {
            var argv = (string[])item.argv.Clone();
            var index = item.inProgram ? 0 : 1 + (item.at % Math.Max(1, argv.Length - 1));
            if (index >= argv.Length)
            {
                argv = [.. argv, string.Empty];
            }

            argv[index] = item.inProgram ? argv[index] + "\"" : argv[index] + "\0";
            var refused = Assert.Throws<CommandRefusedException>(() => WindowsCommandLine.Build(argv));
            Assert.Equal("invalid_argument", refused.Code);
        }, iter: PropertyRuns.Iter(500), print: item => Print(item.argv));

    [Fact]
    [Trait("env", "windows-real")]
    [SupportedOSPlatform("windows")]
    public void TheRealCommandLineToArgvWReadsBackEveryArgumentVector()
    {
        Assert.SkipUnless(OperatingSystem.IsWindows(), "CommandLineToArgvW (shell32).");
        Argv.Sample(argv => Assert.Equal(argv, CommandLineToArgv(WindowsCommandLine.Build(argv))), iter: PropertyRuns.Iter(2_000), print: Print);
    }

    [Fact]
    public void ABatchFileGetsEverySafeArgumentAndRefusesTheFirstUnsafeOne() =>
        Argument.Array[0, 6].Sample(arguments =>
        {
            string[] argv = ["run.cmd", .. arguments];
            var unsafeIndex = Array.FindIndex(argv, argument => !WindowsCommandLine.IsBatchSafe(argument));
            if (unsafeIndex >= 0)
            {
                var refused = Assert.Throws<CommandRefusedException>(() => WindowsCommandLine.BuildBatch(@"C:\Windows\System32\cmd.exe", @"C:\tools\run.cmd", argv));
                Assert.Equal(("unsafe_batch_argument", unsafeIndex.ToString(System.Globalization.CultureInfo.InvariantCulture)), (refused.Code, refused.Reason));
                return;
            }

            // What a program started by the batch file with %* reads: cmd expands each %cd:~,% to nothing, then CommandLineToArgvW rules.
            var line = WindowsCommandLine.BuildBatch(@"C:\Windows\System32\cmd.exe", @"C:\tools\run.cmd", argv);
            var forwarded = line[(line.IndexOf("run.cmd\"", StringComparison.Ordinal) + "run.cmd\"".Length)..^1].Replace("%cd:~,%", string.Empty, StringComparison.Ordinal);
            Assert.Equal(arguments, WindowsCommandLine.Parse("prog" + forwarded).Skip(1));
        }, iter: PropertyRuns.Iter(2_000), print: Print);

    /// <summary>The real cmd.exe and a real batch file forwarding <c>%*</c> to <c>arcforges-testload args</c>: what arrives is exact.</summary>
    [Fact(Timeout = 120_000)]
    [Trait("env", "windows-real")]
    [SupportedOSPlatform("windows")]
    public void ARealBatchFileForwardsEverySafeArgumentUnchanged()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        Assert.SkipUnless(OperatingSystem.IsWindows(), "cmd.exe and batch files.");
        var root = Directory.CreateTempSubdirectory("arcforges-batch-").FullName;
        try
        {
            var script = Path.Combine(root, "forward.cmd");
            File.WriteAllText(script, "@\"" + TestPrograms.TestLoad + "\" args %*\r\n");
            var cmd = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "cmd.exe");
            Gen.String[Gen.Frequency((4, Gen.Char["\\ \t"]), (4, Gen.Char.AlphaNumeric), (2, Gen.Char["%^&|<>(),;=*?'`.-:/"]), (1, Gen.Char["äöü中文"])), 0, 10]
                .Array[0, 4].Sample(arguments =>
                {
                    var line = WindowsCommandLine.BuildBatch(cmd, script, ["forward.cmd", .. arguments]);
                    var start = new ProcessStartInfo(cmd, line[(line.IndexOf(' ', StringComparison.Ordinal) + 1)..])
                    {
                        UseShellExecute = false,
                        RedirectStandardOutput = true,
                        RedirectStandardError = true,
                        CreateNoWindow = true,
                        StandardOutputEncoding = System.Text.Encoding.UTF8,
                    };
                    using var process = Process.Start(start)!;
                    var output = process.StandardOutput.ReadToEnd();
                    Assert.True(process.WaitForExit(30_000), "cmd.exe did not exit.");
                    using var json = JsonDocument.Parse(output);
                    var received = json.RootElement.GetProperty("argv").EnumerateArray().Select(element => element.GetString()!).ToArray();
                    Assert.Equal(arguments, received);
                }, iter: PropertyRuns.Iter(25), threads: 1, print: Print);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public void IndexRecordsRoundTripAndAnyBytesDecodeLosslessOrNotAtAll()
    {
        Gen.Select(Gen.Byte[1, 2], Gen.Long[0, long.MaxValue], Gen.UInt, Gen.Long, Gen.Byte, (stream, offset, length, nanos, marks) =>
            new OutputIndexRecord((OutputStreamKind)stream, offset, length, nanos, (OutputChunkMarks)marks)).Sample(record =>
        {
            var buffer = new byte[OutputIndexRecord.Size];
            record.Write(buffer);
            Assert.True(OutputIndexRecord.TryRead(buffer, out var read));
            Assert.Equal(record, read);
        }, iter: PropertyRuns.Iter(5_000));

        // A torn or foreign record is rejected, never misread: whatever 22 bytes say, a decoded record encodes back to the same bytes.
        Gen.Byte.Array[OutputIndexRecord.Size].Sample(bytes =>
        {
            var valid = bytes[0] is 1 or 2 && BitConverter.ToUInt64(bytes, 1) <= long.MaxValue;
            Assert.Equal(valid, OutputIndexRecord.TryRead(bytes, out var record));
            if (valid)
            {
                var buffer = new byte[OutputIndexRecord.Size];
                record.Write(buffer);
                Assert.Equal(bytes, buffer);
            }
        }, iter: PropertyRuns.Iter(5_000));
    }

    [Fact]
    public void AnIndexFileYieldsItsValidCompleteRecordsAndIgnoresATornTail()
    {
        var root = Directory.CreateTempSubdirectory("arcforges-index-").FullName;
        try
        {
            Gen.Select(Gen.Byte.Array[0, 22 * 40], Gen.Int[0, 50], Gen.Int[0, 50], (bytes, first, max) => (bytes, first, max)).Sample(item =>
            {
                var path = Path.Combine(root, Guid.NewGuid().ToString("N"));
                File.WriteAllBytes(path, item.bytes);
                var records = OutputIndexFile.Read(path, item.first, out var complete, item.max);
                var whole = item.bytes.Length / OutputIndexRecord.Size;
                Assert.Equal((long)whole * OutputIndexRecord.Size, complete);
                var expected = Enumerable.Range(item.first, Math.Max(0, Math.Min(whole - item.first, item.max)))
                    .Select(index => OutputIndexRecord.TryRead(item.bytes.AsSpan(index * OutputIndexRecord.Size, OutputIndexRecord.Size), out var record) ? record : (OutputIndexRecord?)null)
                    .OfType<OutputIndexRecord>().ToList();
                Assert.Equal(expected, records);
                File.Delete(path);
            }, iter: PropertyRuns.Iter(300), threads: 1);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    private static string Print(string[] argv) => JsonSerializer.Serialize(argv);

    [SupportedOSPlatform("windows")]
    private static string[] CommandLineToArgv(string commandLine)
    {
        var argv = CommandLineToArgvW(commandLine, out var count);
        if (argv == 0)
        {
            throw new InvalidOperationException($"CommandLineToArgvW failed ({Marshal.GetLastPInvokeError()}).");
        }

        try
        {
            return [.. Enumerable.Range(0, count).Select(index => Marshal.PtrToStringUni(Marshal.ReadIntPtr(argv, index * IntPtr.Size))!)];
        }
        finally
        {
            LocalFree(argv);
        }
    }

    [LibraryImport("shell32.dll", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
    private static partial nint CommandLineToArgvW(string commandLine, out int count);

    [LibraryImport("kernel32.dll")]
    private static partial nint LocalFree(nint memory);
}
