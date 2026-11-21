// SPDX-License-Identifier: AGPL-3.0-only
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Text.Json;
using ArcForges.Node.Platform;
using ArcForges.Node.Platform.Windows;
using ArcForges.Tests;
using CsCheck;

namespace ArcForges.Node.Platform.Windows.Tests;

/// <summary>
/// Generated argument vectors survive <see cref="WindowsCommandLine.Build"/> through both the managed parser and
/// real <c>CommandLineToArgvW</c>.
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
