// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Node.Platform;
using ArcForges.Node.Platform.Windows;

namespace ArcForges.Node.Platform.Windows.Tests;

/// <summary>
/// Windows command lines (architecture 04 section 2), pure logic on every OS: the quoting inverse to <c>CommandLineToArgvW</c>, the
/// command-line limit, and the batch-file refusal corpus of threat T-03 (11 section 4; CVE-2024-24576 class). The real-OS round trips
/// through <c>CommandLineToArgvW</c> and real batch files, over generated arguments, are in <see cref="CommandLineProperties"/>.
/// </summary>
public sealed class CommandLineTests
{
    /// <summary>Arguments whose quoting is easy to get wrong: spaces, quotes, backslash runs before quotes and at the end, Unicode.</summary>
    internal static readonly string[][] Corpus =
    [
        ["prog", "simple"],
        ["prog", ""],
        ["prog", "two words"],
        ["prog", "tab\there"],
        ["prog", "quote\"inside"],
        ["prog", "\"leading and trailing\""],
        ["prog", "back\\slash"],
        ["prog", "trailing\\"],
        ["prog", "trailing space\\"],
        ["prog", "\\\\server\\share\\"],
        ["prog", "a\\\"b"],
        ["prog", "a\\\\\"b"],
        ["prog", "\\\""],
        ["prog", "unicode äöü 中文 🚀"],
        ["prog", "%PATH%", "!x!", "^&|<>"],
        ["C:\\Program Files\\tool\\tool.exe", "arg"],
        ["prog", "line\nbreak"],
    ];

    /// <summary>The indexes of <see cref="Corpus"/>.</summary>
    public static TheoryData<int> QuotingCorpus => [.. Enumerable.Range(0, Corpus.Length)];

    /// <summary>
    /// The T-03 corpus: arguments that a batch file cannot receive safely through cmd.exe and that must be refused with
    /// <c>unsafe_batch_argument</c> (index of the first such argument).
    /// </summary>
    public static TheoryData<string> UnsafeBatchArguments => new()
    {
        "\"&calc.exe",
        "\\\"&whoami",
        "a\" & whoami & \"",
        "\"|calc",
        "\">out.txt",
        "x\"<in.txt",
        "\"^",
        "%\"%",
        "line\nbreak",
        "carriage\rreturn",
        "nul\0byte",
        "!PATH!",
        "delayed!",
        "\"\"&echo pwned",
        "& \"",

        // Any quote, with or without metacharacters: it cannot be represented for both cmd and a program reading %* (fail closed).
        "quote\"only",
        "\"",
        "\"\"",
        "a\"b",
        "\\\"",
        "\"two words\"",
        "C:\\dir with space\\\"",
        "\"C:\\dir\\\"",
        "x\\\"y",
    };

    /// <summary>Arguments a batch file receives unchanged.</summary>
    public static TheoryData<string> SafeBatchArguments => new()
    {
        "plain",
        "two words",
        "a&b",
        "a|b",
        "a<b>c",
        "caret^",
        "(parens)",
        "comma,semi;equals=",
        "%PATH%",
        "50%",
        "",
        "unicode äöü 中文",
        "C:\\dir with space\\",
        "trailing\\\\ two",
        "\\\\server\\share\\",
        "a\\b c",
    };

    [Theory]
    [InlineData("C:\\dir with space\\", "\"C:\\dir with space\\\\\"")]
    [InlineData("x y\\\\", "\"x y\\\\\\\\\"")]
    [InlineData("a\\b c", "\"a\\b c\"")]
    [InlineData("C:\\nospace\\", "C:\\nospace\\")]
    public void BackslashesBeforeTheClosingQuoteAreDoubled(string argument, string expected)
    {
        var line = WindowsCommandLine.BuildBatch("C:\\Windows\\System32\\cmd.exe", "C:\\tools\\run.bat", ["run.bat", argument, "next"]);
        Assert.EndsWith(" " + expected + " next\"", line, StringComparison.Ordinal);

        // A program receiving the batch file's %* reads the argument back unchanged and separate from the next one.
        var forwarded = line[(line.IndexOf("run.bat\" ", StringComparison.Ordinal) + "run.bat\" ".Length)..^1];
        Assert.Equal([argument, "next"], WindowsCommandLine.Parse("prog " + forwarded).Skip(1));
    }

    [Theory]
    [MemberData(nameof(QuotingCorpus))]
    public void TheCommandLineParsesBackToTheArgumentVector(int index)
    {
        var argv = Corpus[index];
        var line = WindowsCommandLine.Build(argv);
        Assert.Equal(argv, WindowsCommandLine.Parse(line));
    }

    [Fact]
    public void AProgramTokenWithAQuoteIsRefused()
    {
        var refusal = Assert.Throws<CommandRefusedException>(() => WindowsCommandLine.Build(["bad\"name", "x"]));
        Assert.Equal("invalid_argument", refusal.Code);
    }

    [Fact]
    public void ACommandLineOverTheWindowsLimitIsRefused()
    {
        var refusal = Assert.Throws<CommandRefusedException>(() => WindowsCommandLine.Build(["prog", new string('x', WindowsCommandLine.MaxLength)]));
        Assert.Equal("invalid_argument", refusal.Code);
        Assert.Contains("32766", refusal.Reason.Replace(",", string.Empty, StringComparison.Ordinal), StringComparison.Ordinal);
    }

    [Theory]
    [MemberData(nameof(UnsafeBatchArguments))]
    public void UnsafeBatchArgumentsAreRefusedWithTheirIndex(string argument)
    {
        Assert.False(WindowsCommandLine.IsBatchSafe(argument));
        var refusal = Assert.Throws<CommandRefusedException>(() =>
            WindowsCommandLine.BuildBatch("C:\\Windows\\System32\\cmd.exe", "C:\\tools\\run.bat", ["run.bat", "ok", argument]));
        Assert.Equal("unsafe_batch_argument", refusal.Code);
        Assert.Equal("2", refusal.Reason);
    }

    [Theory]
    [MemberData(nameof(SafeBatchArguments))]
    public void SafeBatchArgumentsAreQuotedForCmd(string argument)
    {
        Assert.True(WindowsCommandLine.IsBatchSafe(argument));
        var line = WindowsCommandLine.BuildBatch("C:\\Windows\\System32\\cmd.exe", "C:\\tools\\run.bat", ["run.bat", argument]);
        Assert.StartsWith("C:\\Windows\\System32\\cmd.exe /d /s /c \"\"C:\\tools\\run.bat\" ", line, StringComparison.Ordinal);
        Assert.EndsWith("\"", line, StringComparison.Ordinal);

        // Every % is followed by %cd:~,% (an expansion to nothing), so no %NAME% can form.
        Assert.Equal(argument.Count(character => character == '%'), System.Text.RegularExpressions.Regex.Count(line, "%%cd:~,%"));
    }

    [Fact]
    public void AScriptPathWithAQuoteIsRefused()
    {
        var refusal = Assert.Throws<CommandRefusedException>(() =>
            WindowsCommandLine.BuildBatch("C:\\Windows\\System32\\cmd.exe", "C:\\to\"ols\\run.bat", ["run.bat"]));
        Assert.Equal("unsafe_batch_argument", refusal.Code);
        Assert.Equal("0", refusal.Reason);
    }

    [Fact]
    public void ProgramResolutionUsesPathAndPathExtButNotTheWorkingDirectory()
    {
        Assert.SkipUnless(OperatingSystem.IsWindows(), "Windows program resolution (PATH and PATHEXT).");
        var root = Directory.CreateTempSubdirectory("arcforges-resolve-").FullName;
        try
        {
            var bin = Directory.CreateDirectory(Path.Combine(root, "bin")).FullName;
            var work = Directory.CreateDirectory(Path.Combine(root, "work")).FullName;
            File.WriteAllText(Path.Combine(bin, "tool.cmd"), "@echo off");
            File.WriteAllText(Path.Combine(work, "local.exe"), string.Empty);
            File.WriteAllText(Path.Combine(work, "tool.exe"), string.Empty);
            var environment = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase) { ["Path"] = bin, ["PATHEXT"] = ".EXE;.CMD" };

            // A bare name searches PATH only, never the working directory (NoDefaultCurrentDirectoryInExePath).
            Assert.Equal(Path.Combine(bin, "tool.cmd"), WindowsProgramResolver.Resolve("tool", work, environment), ignoreCase: true);
            Assert.Null(WindowsProgramResolver.Resolve("local", work, environment));

            // A name with a directory part resolves against the working directory.
            Assert.Equal(Path.Combine(work, "local.exe"), WindowsProgramResolver.Resolve(".\\local", work, environment), ignoreCase: true);
            Assert.True(WindowsProgramResolver.IsBatch(Path.Combine(bin, "tool.cmd")));
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public void TheEnvironmentBlockIsSortedAndDoubleNulTerminated()
    {
        var block = new string(WindowsCommandLine.EnvironmentBlock(["b=2", "A=1", "=C:=C:\\"]));
        Assert.Equal("=C:=C:\\\0A=1\0b=2\0\0", block);
        Assert.Equal("\0\0", new string(WindowsCommandLine.EnvironmentBlock([])));
    }
}
