// SPDX-License-Identifier: AGPL-3.0-only
using System.IO.Enumeration;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace ArcForges.Repository.Tests;

/// <summary>
/// The repository check of the OS secret-store test guard (ArcForges-Design 16-testing-strategy section 1, guard item 3; AD-0016
/// amendment of 2026-10-17), following DesktopPlatform's ArchitectureTests policy (OsSecretStoreTierPolicyTests). It runs in the
/// host verification and in external-PR CI with the other repository tests: test, tool, benchmark and script sources outside the tier never
/// name the real OS stores; production names them only at the reviewed composition root, which follows the <c>--test-mode</c> rule;
/// every in-process node of a test overrides its secret store and every node process of a test runs with <c>--test-mode</c>; only the
/// tier's own runner and workflow select the tier, whose opt-in is set only on the hosted tier job's test step; and every test project,
/// and no production project, sets the tripwire switch in its built runtime configuration.
/// </summary>
public sealed partial class OsSecretStoreGuardPolicyTests
{
    private const string TierDirectory = "tests/ArcForges.OsSecretStoreTier/";
    private const string TierName = "ArcForges.OsSecretStoreTier";
    private const string TierProject = TierDirectory + TierName + ".csproj";
    private const string TierWorkflow = ".github/workflows/os-secret-store-tier.yml";
    private const string TierRunner = "eng/os_secret_store_tier.py";
    private const string ThisFile = "tests/ArcForges.Repository.Tests/OsSecretStoreGuardPolicyTests.cs";
    private const string CompositionRoot = "src/ArcForges.Node.Store/Secrets/NodeSecretStores.cs";
    private const string TestNodeFile = "tests/ArcForges.ClosedLoop.Tests/TestNode.cs";
    private const string OptIn = "ARCFORGES_OS_SECRET_STORE_TESTS";
    private const string DenySwitch = "ArcForges.Security.Secrets.DenyOsStores";
    private const string TierCondition = "github.event_name == 'schedule' || github.event_name == 'workflow_dispatch' || "
        + "github.event_name == 'merge_group' || (github.event_name == 'pull_request' && github.event.pull_request.user.login != 'deku2026')";

    /// <summary>
    /// The reviewed allow-list: test, tool, benchmark or script sources outside the tier that name the real adapters, each with the reason
    /// it cannot reach the user's store. Every entry must still contain such a reference, so the list cannot go stale.
    /// </summary>
    private static readonly Dictionary<string, string> AllowList = new(StringComparer.Ordinal)
    {
        ["tests/ArcForges.Node.Store.Tests/OsSecretStoreGuardTests.cs"] =
            "The guard's negative tests (16 section 1 item 4): every call is made only after asserting that this routine process denies the "
            + "OS stores and carries no opt-in, and each is refused by the tripwire before any OS call (on Windows a construction or a "
            + "selection that only constructs; on Linux a TCP bus address on which no Secret Service listens).",
        [ThisFile] = "This check's own patterns.",
    };

    /// <summary>
    /// Lines of test sources that name <c>node run</c> without starting a node, each with its reason (the line check below otherwise
    /// requires <c>--test-mode</c> on every such line).
    /// </summary>
    private static readonly (string Path, string Fragment, string Reason)[] NodeRunMentions =
    [
        ("tests/ArcForges.Client.Tests/CommandLineTests.cs", "[InlineData(\"node run --", "The CLI grammar is parsed in process; nothing starts."),
        ("tests/ArcForges.Client.Tests/CommandLineTests.cs", "start it with 'arcforges node run --background'", "An asserted error message."),
        ("tests/ArcForges.ClosedLoop.Tests/NodeLifecycleTests.cs", "start it with 'arcforges node run --background'", "An asserted error message."),
        ("tests/ArcForges.Repository.Tests/RepositoryLayoutTests.cs", "ExecStart=%h/.local/share/arcforges/app/current/arcforges node run --systemd",
            "The shipped unit file's content, read as text."),

    ];

    private static string Root => RepositoryFiles.Root;

    [Fact]
    public void TestToolBenchmarkAndScriptSourcesOutsideTheTierNeverNameTheRealOsStores()
    {
        var offenders = new List<string>();
        var allowedHits = new HashSet<string>(StringComparer.Ordinal);
        foreach (var path in Sources().Where(path => !IsProduction(path) && !InTier(path)))
        {
            var text = File.ReadAllText(Path.Combine(Root, path));
            if (!AdapterReference().IsMatch(text) && !DirectStoreAccess().IsMatch(text))
            {
                continue;
            }

            if (AllowList.ContainsKey(path))
            {
                allowedHits.Add(path);
            }
            else
            {
                offenders.Add(path);
            }
        }

        Assert.True(offenders.Count == 0, "Only the OS secret-store tier (" + TierDirectory + ") may name OsSecretStore.*, "
            + "WindowsCredentialManagerSecretStore, SecretServiceSecretStore, the Cred* API, cmdkey or secret-tool: " + string.Join(", ", offenders));
        Assert.Equal(AllowList.Keys.Order(StringComparer.Ordinal), allowedHits.Order(StringComparer.Ordinal));
        Assert.All(AllowList.Values, reason => Assert.False(string.IsNullOrWhiteSpace(reason)));
    }

    [Theory]
    [InlineData("var store = ArcForges.Security.Secrets.OsSecretStore.CreateForCurrentPlatform();")]
    [InlineData("_ = global::ArcForges.Security.Secrets.OsSecretStore.SelectForCurrentPlatform(root);")]
    [InlineData("using static ArcForges.Security.Secrets.OsSecretStore;")]
    [InlineData("using S = ArcForges.Security.Secrets.OsSecretStore;")]
    [InlineData("var type = typeof(OsSecretStore);")]
    [InlineData("string name = nameof(OsSecretStore);")]
    [InlineData("OsSecretStore . CreateForCurrentPlatform()")]
    [InlineData("new ArcForges.Security.Secrets.WindowsCredentialManagerSecretStore()")]
    [InlineData("using W = global::ArcForges.Security.Secrets.WindowsCredentialManagerSecretStore;")]
    [InlineData("var type = typeof(global::ArcForges.Security.Secrets.SecretServiceSecretStore);")]
    [InlineData("using static ArcForges.Security.Secrets.SecretServiceSecretStore;")]
    public void TheReferenceCheckCatchesEveryFormOfNamingTheAdaptersAndTheirSelection(string source) =>
        Assert.Matches(AdapterReference(), source);

    [Theory]
    [InlineData("if (OsSecretStoreGuard.IsDenied) return;")]
    [InlineData("OsSecretStoreGuard.ThrowIfDenied(\"a CNG user key store\");")]
    [InlineData("catch (ArcForges.Security.Secrets.OsSecretStoreDeniedException) { }")]
    [InlineData("var protection = SecretStoreProtection.OsSecretStore;")]
    [InlineData("public sealed class OsSecretStoreTier : IDisposable")]
    [InlineData("tests/ArcForges.OsSecretStoreTier/ArcForges.OsSecretStoreTier.csproj")]
    public void TheReferenceCheckIgnoresTheGuardItsErrorTheProtectionLabelAndTheTierName(string source) =>
        Assert.DoesNotMatch(AdapterReference(), source);

    [Theory]
    [InlineData("CredReadW(target, 1, 0, out var credential)")]
    [InlineData("[LibraryImport(\"Advapi32.dll\", EntryPoint = \"CredEnumerateW\")]")]
    [InlineData("Process.Start(\"cmdkey.exe\", \"/list\")")]
    [InlineData("secret-tool lookup application arcforges")]
    [InlineData("[DllImport(\"advapi32.dll\", SetLastError = true)]\n    private static extern bool CredProtectW(bool asSelf, string credentials);")]
    [InlineData("[LibraryImport(\"advapi32.dll\", EntryPoint = \"CredMarshalCredentialW\", StringMarshalling = StringMarshalling.Utf16)]")]
    [InlineData("[LibraryImport(\"advapi32\")] internal static partial int CredUnprotectW(int a, char* b, int c, char* d, ref int e);")]
    [InlineData("vaultcmd /listcreds:\"Windows Credentials\"")]
    [InlineData("var vault = new Windows.Security.Credentials.PasswordVault();")]
    [InlineData("& cmdkey.exe /list")]
    public void TheDirectStoreCheckCatchesTheCredentialApiAndTheStoreClients(string source) =>
        Assert.Matches(DirectStoreAccess(), source);

    [Theory]
    [InlineData("the Windows Credential Manager holds the node data key")]
    [InlineData("public bool CredentialInOsStore => Protection == SecretStoreProtection.OsSecretStore;")]
    [InlineData("[LibraryImport(\"kernel32.dll\")] private static partial int CreateJobObjectW(nint a, string b);")]
    public void TheDirectStoreCheckIgnoresProseAndOtherNativeCalls(string source) =>
        Assert.DoesNotMatch(DirectStoreAccess(), source);

    [Fact]
    public void ProductionSourcesNameTheOsStoresOnlyAtTheReviewedCompositionRootWhichFollowsTheTestModeRule()
    {
        var offenders = Sources().Where(path => IsProduction(path) && path != CompositionRoot).Where(path =>
        {
            var text = File.ReadAllText(Path.Combine(Root, path));
            return AdapterReference().IsMatch(text) || DirectStoreAccess().IsMatch(text);
        }).ToList();
        Assert.True(offenders.Count == 0, "Production sources outside the composition root " + CompositionRoot + " name a real OS store: "
            + string.Join(", ", offenders));

        // The composition root selects the OS store only through the --test-mode rule: production (no test mode), or test mode with the
        // tier's exact opt-in; otherwise the isolated store of the test data root (02-node-service section 4).
        var root = File.ReadAllText(Path.Combine(Root, CompositionRoot));
        Assert.Matches(AdapterReference(), root);
        Assert.Contains("Environment.GetEnvironmentVariable(OsSecretStoreGuard.OptInVariable)", root, StringComparison.Ordinal);
        Assert.Contains("UsesOsSecretStore(bool testMode, string? optIn) => !testMode || optIn == \"1\";", root, StringComparison.Ordinal);
        Assert.Single(Regex.Matches(root, @"\bOsSecretStore\.SelectForCurrentPlatform\("));
        Assert.Matches(new Regex(@"UsesOsSecretStore\(testMode, optIn\)\s*\?\s*NodeSecretStore\.FromSelection\(OsSecretStore\.SelectForCurrentPlatform\(dataRoot\)\)\s*:\s*ForTestDataRoot\(dataRoot\);"), root);

        // The node host takes its store from the composition root unless a test overrides it.
        var host = File.ReadAllText(Path.Combine(Root, "src/ArcForges.Node.Api/NodeHost.cs"));
        Assert.Contains("options.SecretStore?.Invoke(dataRoot) ?? NodeSecretStores.ForNode(dataRoot, options.TestMode)", host, StringComparison.Ordinal);

        // Every --test-mode process of the arcforges host and the supervisor sets the runtime tripwire at startup unless the exact opt-in
        // is set; production is unaffected (16 section 1, item 2).
        Assert.Contains("AppContext.SetSwitch(OsSecretStoreGuard.DenyOsStoresSwitch, true);", root, StringComparison.Ordinal);
        var program = File.ReadAllText(Path.Combine(Root, "src/ArcForges.Host/Program.cs"));
        Assert.Contains("NodeSecretStores.ApplyTestModeTripwire(options.Contains(NodeLocations.TestModeOption, StringComparer.Ordinal));", program,
            StringComparison.Ordinal);
        var supervisor = File.ReadAllText(Path.Combine(Root, "src/ArcForges.Supervisor/Program.cs"));
        Assert.Contains("DenyOsStoresSwitch = \"" + DenySwitch + "\";", supervisor, StringComparison.Ordinal);
        Assert.Contains("OsSecretStoreOptIn = \"" + OptIn + "\";", supervisor, StringComparison.Ordinal);
        Assert.Contains("if (testMode && Environment.GetEnvironmentVariable(OsSecretStoreOptIn) != \"1\")", supervisor, StringComparison.Ordinal);
        Assert.Contains("AppContext.SetSwitch(DenyOsStoresSwitch, true);", supervisor, StringComparison.Ordinal);
    }

    [Fact]
    public void EveryNodeHostBuiltInTestsOverridesItsSecretStore()
    {
        var built = 0;
        foreach (var path in Sources().Where(path => !IsProduction(path) && path.EndsWith(".cs", StringComparison.Ordinal) && path != ThisFile))
        {
            var text = File.ReadAllText(Path.Combine(Root, path));
            var (count, offenders) = NodeHostsWithoutSecretStore(text);
            Assert.True(offenders.Count == 0, $"{path}: a NodeHostOptions built at offset {string.Join(", ", offenders)} does not override "
                + "SecretStore with an isolated backend");
            built += count;
        }

        Assert.True(built > 0, "No test builds a NodeHost: the check would pass unchecked.");
    }

    [Theory]
    [InlineData("var options = new NodeHostOptions { TestMode = true };")]
    [InlineData("var options = new NodeHostOptions() { Endpoint = endpoint };")]
    [InlineData("var options = new NodeHostOptions();")]
    [InlineData("NodeHostOptions options = new() { TestMode = true };")]
    [InlineData("NodeHostOptions options = new(){ Endpoint = endpoint };")]
    [InlineData("NodeHostOptions options = new();")]
    [InlineData("NodeHostOptions? options = new() { ConfigPath = path };")]
    [InlineData("await NodeHost.RunAsync(new() { ConfigPath = path }, token);")]
    [InlineData("var copy = options with { SecretStore = null };")]
    public void TheNodeHostCheckCatchesEveryConstructionWithoutAnIsolatedSecretStore(string source) =>
        Assert.NotEmpty(NodeHostsWithoutSecretStore(source).Offenders);

    [Theory]
    [InlineData("var options = new NodeHostOptions { SecretStore = _ => secrets.Selection, TestMode = false };")]
    [InlineData("NodeHostOptions options = new() { Endpoint = endpoint, SecretStore = _ => secrets.Selection };")]
    [InlineData("await NodeHost.RunAsync(new() { SecretStore = _ => secrets.Selection }, token);")]
    public void TheNodeHostCheckAcceptsAConstructionWithAnIsolatedSecretStore(string source)
    {
        var (count, offenders) = NodeHostsWithoutSecretStore(source);
        Assert.Equal(1, count);
        Assert.Empty(offenders);
    }

    [Fact]
    public void EveryNodeProcessATestStartsRunsWithTestMode()
    {
        // Every closed-loop process start goes through TestNode.Start, which refuses the node, CLI and supervisor binaries without
        // --test-mode and strips the tier opt-in; its CLI helpers append --test-mode.
        var testNode = File.ReadAllText(Path.Combine(Root, TestNodeFile));
        Assert.Contains("binary is \"arcforges\" or \"arcforges-supervisor\" && !argumentList.Contains(NodeLocations.TestModeOption", testNode, StringComparison.Ordinal);
        Assert.Contains("start.Environment.Remove(OsSecretStoreGuard.OptInVariable);", testNode, StringComparison.Ordinal);
        Assert.Contains("Start(Host, [.. args, NodeLocations.TestModeOption])", testNode, StringComparison.Ordinal);
        Assert.Contains("Start(Host, [NodeLocations.TestModeOption, .. args])", testNode, StringComparison.Ordinal);

        var mentions = new HashSet<(string, string)>();
        foreach (var path in Sources().Where(path => !IsProduction(path) && path != ThisFile))
        {
            var lines = File.ReadAllLines(Path.Combine(Root, path));
            foreach (var line in lines)
            {
                // No process start of the host or supervisor binaries bypasses TestNode.Start.
                if (path != TestNodeFile)
                {
                    Assert.DoesNotMatch(new Regex(@"(ProcessStartInfo|Process\.Start)\(\s*(TestNode\.Host|Host|Supervisor|InProcessNode\.HelperExecutable)\b"), line);
                }

                if (!NodeRun().IsMatch(line) || line.Contains("--test-mode", StringComparison.Ordinal)
                    || line.Contains("TestModeOption", StringComparison.Ordinal)
                    || Regex.IsMatch(line, @"\bCli(Bytes)?Async\("))
                {
                    continue;
                }

                var reviewed = NodeRunMentions.FirstOrDefault(mention => mention.Path == path && line.Contains(mention.Fragment, StringComparison.Ordinal));
                Assert.True(reviewed.Path is not null, $"{path}: starts or names 'node run' without --test-mode: {line.Trim()}");
                mentions.Add((reviewed.Path, reviewed.Fragment));
            }
        }

        Assert.Equal(NodeRunMentions.Select(mention => (mention.Path, mention.Fragment)).Order(), mentions.Order());
        Assert.All(NodeRunMentions, mention => Assert.False(string.IsNullOrWhiteSpace(mention.Reason)));
    }

    [Fact]
    public void OnlyTheTiersOwnRunnerAndWorkflowSelectTheTiersTests()
    {
        // The default suites take tests/*/*.Tests.csproj ('*'); the tier's project name is outside that pattern, and no suite names it.
        Assert.True(File.Exists(Path.Combine(Root, TierProject)));
        Assert.False(FileSystemName.MatchesSimpleExpression("*.Tests.csproj", Path.GetFileName(TierProject)));
        Assert.False(FileSystemName.MatchesSimpleExpression("*Tests.csproj", Path.GetFileName(TierProject)));
        Assert.DoesNotContain("OsSecretStoreTier", File.ReadAllText(Path.Combine(Root, "eng/test-suites.conf")), StringComparison.Ordinal);
        Assert.Contains("all_projects+=", File.ReadAllText(Path.Combine(Root, "eng/test.sh")), StringComparison.Ordinal);
        Assert.Contains("\"$repository\"/tests/*/*.Tests.csproj", File.ReadAllText(Path.Combine(Root, "eng/test.sh")), StringComparison.Ordinal);
        Assert.Contains("-Filter '*.Tests.csproj'", File.ReadAllText(Path.Combine(Root, "eng/test.ps1")), StringComparison.Ordinal);

        // Workflows, hooks and scripts do not name the tier (its own workflow and runner aside), and run `dotnet test` only per project.
        var selectors = TrackedFiles().Where(path => path.StartsWith(".github/workflows/", StringComparison.Ordinal)
            || path.StartsWith(".githooks/", StringComparison.Ordinal)
            || (path.StartsWith("eng/", StringComparison.Ordinal) && (path.EndsWith(".py", StringComparison.Ordinal)
                || path.EndsWith(".ps1", StringComparison.Ordinal) || path.EndsWith(".sh", StringComparison.Ordinal))));
        foreach (var path in selectors)
        {
            var text = File.ReadAllText(Path.Combine(Root, path));
            Assert.True(path is TierWorkflow or TierRunner || !text.Contains("OsSecretStoreTier", StringComparison.Ordinal),
                path + " selects the OS secret-store tier");
            // Command lines in workflows, hooks and shell scripts; argument lists in the Python scripts (whose prose may name the command).
            if (!path.EndsWith(".py", StringComparison.Ordinal))
            {
                Assert.True(Regex.Count(text, @"\bdotnet\s+test\b") == Regex.Count(text, @"\bdotnet\s+test\s+--project\s+\S"),
                    path + " runs `dotnet test` without --project");
            }

            Assert.True(Regex.Count(text, "\"dotnet\",\\s*\"test\"") == Regex.Count(text, "\"dotnet\",\\s*\"test\",\\s*\"--project\""),
                path + " runs `dotnet test` without --project");
        }

        // No other project references the tier (the store tests compile its fixture file for the guard's negative test, nothing else).
        foreach (var project in RepositoryFiles.Projects("src", "tools", "tests").Where(project => project != TierProject))
        {
            var references = RepositoryFiles.Xml(project).Descendants("ProjectReference").Select(reference => (string?)reference.Attribute("Include") ?? string.Empty);
            Assert.DoesNotContain(references, reference => reference.Contains(TierName, StringComparison.Ordinal));
            var compiled = RepositoryFiles.Xml(project).Descendants("Compile").Select(item => (string?)item.Attribute("Include") ?? string.Empty)
                .Where(include => include.Contains(TierName, StringComparison.Ordinal)).ToList();
            Assert.True(compiled.Count == 0 || (project == "tests/ArcForges.Node.Store.Tests/ArcForges.Node.Store.Tests.csproj"
                && compiled.SequenceEqual(["../" + TierName + "/OsSecretStoreTier.cs"])), project + " compiles tier sources");
        }

        // Every test class of the tier carries the tier's trait, and no test outside the tier does.
        foreach (var path in Sources().Where(path => path.EndsWith(".cs", StringComparison.Ordinal)))
        {
            var text = File.ReadAllText(Path.Combine(Root, path));
            var hasTests = text.Contains("[Fact", StringComparison.Ordinal) || text.Contains("[Theory", StringComparison.Ordinal);
            var trait = TierTrait().IsMatch(text);
            if (InTier(path) && hasTests)
            {
                Assert.True(trait, path + " lacks [Trait(\"env\", \"os-secret-store\")]");
            }

            if (!InTier(path) && path != ThisFile)
            {
                Assert.False(trait, path + " carries the OS secret-store tier's trait");
            }
        }

        // The tier workflow builds and runs only the tier project, and the runner runs exactly it.
        var workflow = File.ReadAllText(Path.Combine(Root, TierWorkflow));
        var commands = DotnetProjectCommand().Matches(workflow);
        Assert.Equal(3, commands.Count);
        Assert.All(commands, command => Assert.Equal(TierProject, command.Groups["project"].Value));
        Assert.Contains("dotnet test --project " + TierProject, workflow, StringComparison.Ordinal);
        Assert.Contains("PROJECT = \"" + TierProject + "\"", File.ReadAllText(Path.Combine(Root, TierRunner)), StringComparison.Ordinal);
    }

    [Fact]
    public void TheOptInIsSetOnlyOnTheHostedTierJobsTestStepUnderTheAmendedCondition()
    {
        foreach (var path in TrackedFiles().Where(path => path.StartsWith(".github/", StringComparison.Ordinal) && path != TierWorkflow))
        {
            Assert.DoesNotContain(OptIn, File.ReadAllText(Path.Combine(Root, path)), StringComparison.Ordinal);
        }

        var lines = File.ReadAllLines(Path.Combine(Root, TierWorkflow));
        var settings = lines.Select((line, index) => (line, index))
            .Where(item => item.line.Contains(OptIn, StringComparison.Ordinal) && !item.line.TrimStart().StartsWith('#')).ToList();
        var (setting, at) = Assert.Single(settings);
        Assert.Equal("          " + OptIn + ": '1'", setting);

        // Its parent is a step's env (8 spaces), never a job's (4) or the workflow's (0), and that step runs the tier's tests.
        var parent = Enumerable.Range(0, at).Reverse().First(index => Indent(lines[index]) < Indent(setting) && lines[index].Trim().Length > 0);
        Assert.Equal("        env:", lines[parent]);
        var step = Enumerable.Range(0, parent).Reverse().First(index => lines[index].StartsWith("      - ", StringComparison.Ordinal));
        var next = Enumerable.Range(at + 1, lines.Length - at - 1).FirstOrDefault(index => lines[index].StartsWith("      - ", StringComparison.Ordinal)
            || (Indent(lines[index]) < 6 && lines[index].Trim().Length > 0), lines.Length);
        Assert.Contains("dotnet test --project " + TierProject, string.Join('\n', lines[step..next]), StringComparison.Ordinal);
        Assert.Contains(lines[step..next], line => line.Trim() == "timeout-minutes: 7");
        Assert.Contains("--no-build --minimum-expected-tests 1 --fail-skips on ", string.Join('\n', lines[step..next]), StringComparison.Ordinal);
        Assert.Contains("\"--minimum-expected-tests\", \"1\", \"--fail-skips\", \"on\"", File.ReadAllText(Path.Combine(Root, TierRunner)),
            StringComparison.Ordinal);

        // Triggers and the job condition of the AD-0016 amendment: external PRs, merge_group, dispatch and a weekly schedule; never a
        // push, and skipped for the owner's PRs.
        var workflow = string.Join('\n', lines);
        var triggers = workflow.Split("\non:\n", 2)[1].Split("\npermissions:", 2)[0];
        Assert.Equal(["merge_group", "pull_request", "schedule", "workflow_dispatch"],
            TopLevelTrigger().Matches(triggers).Select(match => match.Groups["name"].Value).Order(StringComparer.Ordinal));
        Assert.Contains("- cron: ", triggers, StringComparison.Ordinal);
        var conditions = JobCondition().Matches(workflow).Select(match => match.Groups["condition"].Value.Trim()).ToList();
        Assert.NotEmpty(conditions);
        Assert.All(conditions, condition => Assert.Equal("${{ " + TierCondition + " }}", condition));
        Assert.Contains("runs-on: windows-latest", workflow, StringComparison.Ordinal);

        // The routine scripts remove a stray opt-in, and the host verification refuses to run with one.
        Assert.Contains("Remove-Item Env:" + OptIn, File.ReadAllText(Path.Combine(Root, "eng/test.ps1")), StringComparison.Ordinal);
        Assert.Contains("unset " + OptIn, File.ReadAllText(Path.Combine(Root, "eng/test.sh")), StringComparison.Ordinal);
        Assert.Contains("if OS_SECRET_STORE_OPT_IN in os.environ:\n    raise SystemExit(", File.ReadAllText(Path.Combine(Root, "eng/verify_steps.py")),
            StringComparison.Ordinal);
    }

    [Fact]
    public void EveryTestProjectDeniesTheOsStoresAndNoProductionProjectDoes()
    {
        // This test process itself (a test project).
        Assert.True(AppContext.TryGetSwitch(DenySwitch, out var deny) && deny);
        var props = File.ReadAllText(Path.Combine(Root, "tests/Directory.Build.props"));
        Assert.Contains("<RuntimeHostConfigurationOption Include=\"" + DenySwitch + "\" Value=\"true\" />", props, StringComparison.Ordinal);
        foreach (var file in (string[])["Directory.Build.props", "Directory.Build.targets"])
        {
            Assert.DoesNotContain(DenySwitch, File.ReadAllText(Path.Combine(Root, file)), StringComparison.Ordinal);
        }

        // The built runtime configuration of every project in the solution: tests set the switch, production executables never do. The
        // gate builds the whole solution first; a test project without a build output fails here instead of passing unchecked.
        var configuration = new DirectoryInfo(AppContext.BaseDirectory).Parent!.Name;
        var solution = RepositoryFiles.Xml("ArcForges.slnx").Descendants("Project").Select(element => (string)element.Attribute("Path")!).ToList();
        var checkedTests = 0;
        var checkedProduction = 0;
        foreach (var project in solution)
        {
            var directory = Path.Combine(Root, Path.GetDirectoryName(project)!, "bin", configuration);
            var own = (RepositoryFiles.Property(project, "AssemblyName") ?? Path.GetFileNameWithoutExtension(project)) + ".runtimeconfig.json";
            var configurations = Directory.Exists(directory)
                ? Directory.EnumerateFiles(directory, own, SearchOption.AllDirectories).ToList()
                : [];
            if (project.StartsWith("tests/", StringComparison.Ordinal))
            {
                Assert.True(configurations.Count > 0, project + " has no built runtime configuration in " + directory + "; build ArcForges.slnx ("
                    + configuration + ") first");
                Assert.All(configurations, file => Assert.True(Denies(file), file + " does not set " + DenySwitch));
                checkedTests++;
            }
            else
            {
                Assert.All(configurations, file => Assert.False(Denies(file), file + " (production) sets " + DenySwitch));
                checkedProduction += configurations.Count > 0 ? 1 : 0;
            }
        }

        Assert.True(checkedTests >= 10, "only " + checkedTests + " test projects were checked");
        Assert.True(checkedProduction >= 4, "only " + checkedProduction + " production executables were checked");
    }

    /// <summary>
    /// The NodeHostOptions constructions in <paramref name="text"/> (explicit, target-typed, or passed to <c>NodeHost.RunAsync</c>) and the
    /// offsets of those whose initializer does not set <c>SecretStore</c>, plus any <c>with</c> expression that resets it to null.
    /// </summary>
    private static (int Count, List<int> Offenders) NodeHostsWithoutSecretStore(string text)
    {
        var count = 0;
        var offenders = new List<int>();
        foreach (var pattern in (string[])[@"\bnew\s+NodeHostOptions\b", @"\bNodeHostOptions\??\s+\w+\s*=\s*new\b(?!\s+\w)",
            @"\bNodeHost\.RunAsync\(\s*new\b(?!\s+\w)"])
        {
            foreach (Match match in Regex.Matches(text, pattern))
            {
                count++;
                var initializer = Initializer(text, match.Index + match.Length);
                if (initializer is null || !Regex.IsMatch(initializer, @"\bSecretStore\s*="))
                {
                    offenders.Add(match.Index);
                }
            }
        }

        offenders.AddRange(Regex.Matches(text, @"\bwith\s*\{[^}]*\bSecretStore\s*=\s*null").Select(match => match.Index));
        return (count, offenders);
    }

    private static bool Denies(string runtimeConfiguration)
    {
        using var document = JsonDocument.Parse(File.ReadAllText(runtimeConfiguration));
        return document.RootElement.TryGetProperty("runtimeOptions", out var options)
            && options.TryGetProperty("configProperties", out var properties)
            && properties.TryGetProperty(DenySwitch, out var value)
            && value.ValueKind == JsonValueKind.True;
    }

    /// <summary>The object initializer that follows a constructor call at <paramref name="start"/>, or null when there is none.</summary>
    private static string? Initializer(string text, int start)
    {
        var index = start;
        while (index < text.Length && char.IsWhiteSpace(text[index]))
        {
            index++;
        }

        if (index < text.Length && text[index] == '(')
        {
            index = text.IndexOf(')', index) + 1;
            while (index < text.Length && char.IsWhiteSpace(text[index]))
            {
                index++;
            }
        }

        if (index <= 0 || index >= text.Length || text[index] != '{')
        {
            return null;
        }

        var depth = 0;
        for (var end = index; end < text.Length; end++)
        {
            depth += text[end] switch { '{' => 1, '}' => -1, _ => 0 };
            if (depth == 0)
            {
                return text[index..(end + 1)];
            }
        }

        return null;
    }

    private static int Indent(string line) => line.Length - line.TrimStart(' ').Length;

    // Test, tool, benchmark and script sources are everything outside src/.
    private static bool IsProduction(string path) => path.StartsWith("src/", StringComparison.Ordinal);

    private static bool InTier(string path) => path.StartsWith(TierDirectory, StringComparison.Ordinal) || path == TierRunner || path == TierWorkflow;

    // Code, build and script sources: C#, Python, PowerShell scripts and modules, shell and cmd scripts, MSBuild project, props and
    // targets files, the hooks and the workflows.
    private static readonly string[] SourceExtensions = [".cs", ".py", ".ps1", ".psm1", ".sh", ".cmd", ".csproj", ".props", ".targets"];

    private static IEnumerable<string> Sources() => TrackedFiles().Where(path =>
        SourceExtensions.Any(extension => path.EndsWith(extension, StringComparison.Ordinal))
        || path.StartsWith(".githooks/", StringComparison.Ordinal)
        || (path.StartsWith(".github/workflows/", StringComparison.Ordinal) && (path.EndsWith(".yml", StringComparison.Ordinal)
            || path.EndsWith(".yaml", StringComparison.Ordinal))));

    private static IEnumerable<string> TrackedFiles() =>
        Directory.EnumerateFiles(Root, "*", SearchOption.AllDirectories)
            .Select(path => Path.GetRelativePath(Root, path).Replace('\\', '/'))
            .Where(path => !path.Split('/').Any(part => part is ".git" or ".worktree" or "artifacts" or "bin" or "obj" or "third-party"));

    // The bare type names in any form (qualified, global::, using static, aliases, typeof/nameof, member access); a word character after
    // the name (OsSecretStoreGuard, OsSecretStoreDeniedException, OsSecretStoreTier) is another identifier, and the protection label
    // SecretStoreProtection.OsSecretStore names no adapter.
    [GeneratedRegex(@"(?<!SecretStoreProtection\.)\bOsSecretStore\b|\bWindowsCredentialManagerSecretStore\b|\bSecretServiceSecretStore\b")]
    private static partial Regex AdapterReference();

    // The Credential Manager API by name, any Cred* export bound through DllImport or LibraryImport (an attribute naming it as its entry
    // point, or the declaration that follows the attribute), and the store's command-line and WinRT clients.
    [GeneratedRegex(@"\bCred(?:Read|Write|Delete|Enumerate|Free|Rename|GetTargetInfo)[AW]?\b|\bcmdkey\b|\bsecret-tool\b|\bvaultcmd\b|\bPasswordVault\b"
        + @"|\b(?:DllImport|LibraryImport)\s*\([^)]*\bEntryPoint\s*=\s*""Cred[A-Z]\w*""|\b(?:DllImport|LibraryImport)\s*\([^)]*\)\s*\][^;{]*?\bCred[A-Z]\w*\s*\(",
        RegexOptions.IgnoreCase)]
    private static partial Regex DirectStoreAccess();

    [GeneratedRegex(@"\[Trait\(\s*""env""\s*,\s*""os-secret-store""\s*\)\]")]
    private static partial Regex TierTrait();

    [GeneratedRegex(@"""node""\s*,\s*""run""|\bnode run\b")]
    private static partial Regex NodeRun();

    [GeneratedRegex(@"\bdotnet\s+(?:restore|build|test(?:\s+--project)?)\s+(?<project>[^\s]+\.csproj)")]
    private static partial Regex DotnetProjectCommand();

    [GeneratedRegex(@"^  (?<name>[a-z_]+):", RegexOptions.Multiline)]
    private static partial Regex TopLevelTrigger();

    [GeneratedRegex(@"^    if: (?<condition>.+)$", RegexOptions.Multiline)]
    private static partial Regex JobCondition();
}
