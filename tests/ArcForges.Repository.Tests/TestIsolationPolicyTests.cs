// SPDX-License-Identifier: AGPL-3.0-only
using System.Text.RegularExpressions;

namespace ArcForges.Repository.Tests;

/// <summary>
/// Test nodes are isolated from the machine's other load by default (<c>MachineIsolation</c>; 16 section 4). A test that opts into the live
/// machine (<c>LiveMachine</c> set to anything but false, <c>WithLiveMachine()</c>, the isolation variable removed or the in-process option
/// cleared) sees every other test's load, so it must run alone: <c>isolation=exclusive</c> with <c>DisableParallelization = true</c>. The
/// scripted-machine seam (<c>MachineScript</c>, <c>WrapSampler</c>) is for the resource tests of <c>ResourceServiceTests</c> only (AGENTS.md
/// section 4).
/// </summary>
public sealed partial class TestIsolationPolicyTests
{
    /// <summary>The fixture that defines the scripted-machine seam and the one test class that may use it.</summary>
    private static readonly string[] ScriptedMachineFiles = ["tests/ArcForges.Node.Core.Tests/InProcessNode.cs", "tests/ArcForges.Node.Core.Tests/ResourceServiceTests.cs"];

    [Fact]
    public void EveryTestOnTheLiveMachineIsExclusive()
    {
        var checkedTests = new HashSet<string>(StringComparer.Ordinal);
        foreach (var project in RepositoryFiles.Projects("tests"))
        {
            var members = Sources(project).SelectMany(file => Members(file, File.ReadAllLines(RepositoryFiles.PathOf(file)))).ToList();
            foreach (var live in members.Where(member => LiveUse().IsMatch(member.Body)))
            {
                // Every member that calls or names the live member (a body passed as a method group), transitively.
                var reached = new HashSet<string>(StringComparer.Ordinal) { live.Name };
                for (var changed = true; changed;)
                {
                    changed = false;
                    foreach (var member in members.Where(member => !reached.Contains(member.Name)
                        && reached.Any(name => Regex.IsMatch(member.Body, $@"\b{Regex.Escape(name)}\b", RegexOptions.None, TimeSpan.FromSeconds(1)))))
                    {
                        changed |= reached.Add(member.Name);
                    }
                }

                var tests = members.Where(member => member.IsTest && reached.Contains(member.Name)).ToList();
                Assert.True(tests.Count > 0,
                    $"{live.File}: {live.Name} uses the live machine, but no test reaches it (a member the check cannot name fails closed here).");
                foreach (var test in tests)
                {
                    Assert.True(test.Attributes.Contains("[Trait(\"isolation\", \"exclusive\")]", StringComparison.Ordinal)
                        && test.Attributes.Contains("DisableParallelization = true", StringComparison.Ordinal),
                        $"{test.File}: {test.Name} uses the live machine ({live.Name}) and must carry [Trait(\"isolation\", \"exclusive\")] and DisableParallelization = true.");
                    checkedTests.Add(test.File + ":" + test.Name);
                }
            }
        }

        // The rule is not vacuous: the tests of the measured budgets and of pressure use the live machine.
        Assert.True(checkedTests.Count >= 10, $"Only {checkedTests.Count} live-machine tests were found.");
    }

    [Fact]
    public void OnlyTheResourceServiceTestsScriptTheMachine()
    {
        var uses = new List<string>();
        foreach (var file in RepositoryFiles.Projects("tests").SelectMany(Sources))
        {
            var text = File.ReadAllText(RepositoryFiles.PathOf(file));
            if (ScriptedMachine().IsMatch(text))
            {
                Assert.True(ScriptedMachineFiles.Contains(file, StringComparer.Ordinal) || file.EndsWith("/TestIsolationPolicyTests.cs", StringComparison.Ordinal),
                    $"{file} uses the scripted-machine seam (MachineScript, WrapSampler); only ResourceServiceTests may (AGENTS.md section 4).");
                uses.Add(file);
            }
        }

        Assert.Contains(ScriptedMachineFiles[1], uses);
    }

    /// <summary>The C# sources of a test project, relative to the repository root.</summary>
    private static IEnumerable<string> Sources(string project) =>
        Directory.EnumerateFiles(RepositoryFiles.PathOf(Path.GetDirectoryName(project)!), "*.cs", SearchOption.AllDirectories)
            .Where(file => !file.Contains($"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}", StringComparison.Ordinal)
                && !file.Contains($"{Path.DirectorySeparatorChar}bin{Path.DirectorySeparatorChar}", StringComparison.Ordinal))
            .Select(file => Path.GetRelativePath(RepositoryFiles.Root, file).Replace('\\', '/'));

    /// <summary>
    /// The members of a class file at four spaces of indentation: their attributes, their name and their body (comment lines left out).
    /// Every line at that indentation that starts with a letter starts a member: a method or constructor is named by the identifier before
    /// its parameter list, a field, property or event by the identifier before <c>=</c>, <c>=&gt;</c>, <c>{</c> or <c>;</c>, and any other
    /// by its line number (such a member is called by nothing, so a live use in it fails the check closed). A member ends where the next
    /// one, its attributes or a type at the top level start.
    /// </summary>
    private static List<Member> Members(string file, string[] lines)
    {
        var members = new List<Member>();
        var attributes = new List<string>();
        string? name = null;
        var memberAttributes = string.Empty;
        var body = new List<string>();
        void Close()
        {
            if (name is not null)
            {
                members.Add(new Member(file, name, memberAttributes, string.Join('\n', body)));
            }

            name = null;
            body.Clear();
        }

        for (var index = 0; index < lines.Length; index++)
        {
            var line = lines[index];
            if (line.TrimStart().StartsWith("//", StringComparison.Ordinal))
            {
                continue;
            }

            if (line.StartsWith("    [", StringComparison.Ordinal))
            {
                Close();
                attributes.Add(line);
            }
            else if (line.Length > 4 && line.StartsWith("    ", StringComparison.Ordinal) && char.IsLetter(line[4]))
            {
                Close();
                name = Method().Match(line) is { Success: true } method ? method.Groups["name"].Value
                    : Other().Match(line) is { Success: true } other ? other.Groups["name"].Value
                    : $"<{file}:{index + 1}>";
                memberAttributes = string.Join('\n', attributes);
                attributes.Clear();
                body.Add(line);
            }
            else if (line.Length > 0 && !char.IsWhiteSpace(line[0]) && line[0] != '}' && line[0] != '{')
            {
                // A type at the top level ends the members before it.
                Close();
                attributes.Clear();
            }
            else if (name is not null)
            {
                body.Add(line);
            }
        }

        Close();

        // The declaration line itself names the member; only what follows its name counts as a use.
        return [.. members.Select(member => member with { Body = DropName(member) })];
    }

    private static string DropName(Member member)
    {
        var at = member.Body.IndexOf(member.Name, StringComparison.Ordinal);
        return at < 0 ? member.Body : member.Body[(at + member.Name.Length)..];
    }

    [GeneratedRegex(@"\bLiveMachine\s*=(?!=)(?!\s*false\b)|\.WithLiveMachine\(\)|MachineIsolation\.Variable\]\s*=\s*null|IsolatedFromMachineLoad\s*=\s*false",
        RegexOptions.None, matchTimeoutMilliseconds: 1000)]
    private static partial Regex LiveUse();

    [GeneratedRegex(@"\b(?:MachineScript|WithMachineScript|WrapSampler|ScriptedMachineSampler)\b", RegexOptions.None, matchTimeoutMilliseconds: 1000)]
    private static partial Regex ScriptedMachine();

    [GeneratedRegex(@"^    [^=(]*?\b(?<name>\w+)\s*(?:<[^>()]*>)?\(", RegexOptions.None, matchTimeoutMilliseconds: 1000)]
    private static partial Regex Method();

    [GeneratedRegex(@"^    [^=(]*?\b(?<name>\w+)\s*(?:=>|=|\{|;|$)", RegexOptions.None, matchTimeoutMilliseconds: 1000)]
    private static partial Regex Other();

    private sealed record Member(string File, string Name, string Attributes, string Body)
    {
        public bool IsTest => Attributes.Contains("[Fact", StringComparison.Ordinal) || Attributes.Contains("[Theory", StringComparison.Ordinal);
    }
}
