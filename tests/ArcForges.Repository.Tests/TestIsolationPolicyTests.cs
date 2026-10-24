// SPDX-License-Identifier: AGPL-3.0-only
using System.Text.RegularExpressions;

namespace ArcForges.Repository.Tests;

/// <summary>
/// Test nodes are isolated from the machine's other load by default (<c>MachineIsolation</c>; 16 section 4). A test that opts into the live
/// machine (<c>LiveMachine = true</c>, <c>WithLiveMachine()</c>) sees every other test's load, so it must run alone: <c>isolation=exclusive</c>
/// with <c>DisableParallelization = true</c> (AGENTS.md section 4).
/// </summary>
public sealed partial class TestIsolationPolicyTests
{
    [Fact]
    public void EveryTestOnTheLiveMachineIsExclusive()
    {
        var checkedTests = 0;
        foreach (var project in RepositoryFiles.Projects("tests"))
        {
            var members = Directory.EnumerateFiles(RepositoryFiles.PathOf(Path.GetDirectoryName(project)!), "*.cs", SearchOption.AllDirectories)
                .Where(file => !file.Contains($"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}", StringComparison.Ordinal)
                    && !file.Contains($"{Path.DirectorySeparatorChar}bin{Path.DirectorySeparatorChar}", StringComparison.Ordinal))
                .SelectMany(file => Members(Path.GetRelativePath(RepositoryFiles.Root, file).Replace('\\', '/'), File.ReadAllLines(file)))
                .ToList();

            // The members that use the live machine, and every member that calls or names one of them (a body passed as a method group),
            // transitively.
            var live = members.Where(member => LiveUse().IsMatch(member.Body)).ToList();
            var reached = live.Select(member => member.Name).ToHashSet(StringComparer.Ordinal);
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
            Assert.True(live.Count == 0 || tests.Count > 0, $"{project}: {string.Join(", ", live.Select(member => member.Name))} use the live machine, but no test reaches them.");
            foreach (var test in tests)
            {
                Assert.True(test.Attributes.Contains("[Trait(\"isolation\", \"exclusive\")]", StringComparison.Ordinal)
                    && test.Attributes.Contains("DisableParallelization = true", StringComparison.Ordinal),
                    $"{test.File}: {test.Name} uses the live machine (LiveMachine) and must carry [Trait(\"isolation\", \"exclusive\")] and DisableParallelization = true.");
                checkedTests++;
            }
        }

        // The rule is not vacuous: the tests of the measured budgets and of pressure use the live machine.
        Assert.True(checkedTests >= 10, $"Only {checkedTests} live-machine tests were found.");
    }

    /// <summary>
    /// The members of a class file at four spaces of indentation: their attributes, their name and their body (comment lines left out). A
    /// member starts at its first attribute or at its declaration and ends where the next one starts.
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

        foreach (var line in lines)
        {
            if (line.TrimStart().StartsWith("//", StringComparison.Ordinal))
            {
                continue;
            }

            if (line.StartsWith("    [", StringComparison.Ordinal))
            {
                Close();
                attributes.Add(line);
            }
            else if (Declaration().Match(line) is { Success: true } declaration)
            {
                Close();
                name = declaration.Groups["name"].Value;
                memberAttributes = string.Join('\n', attributes);
                attributes.Clear();
                body.Add(line[declaration.Length..]);
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
        return members;
    }

    [GeneratedRegex(@"\bLiveMachine\s*=\s*true\b|\.WithLiveMachine\(\)", RegexOptions.None, matchTimeoutMilliseconds: 1000)]
    private static partial Regex LiveUse();

    [GeneratedRegex(@"^    (?:public|private|internal|protected)\b[^=(]*?\b(?<name>\w+)\s*(?:<[^>()]*>)?\(", RegexOptions.None, matchTimeoutMilliseconds: 1000)]
    private static partial Regex Declaration();

    private sealed record Member(string File, string Name, string Attributes, string Body)
    {
        public bool IsTest => Attributes.Contains("[Fact", StringComparison.Ordinal) || Attributes.Contains("[Theory", StringComparison.Ordinal);
    }
}
