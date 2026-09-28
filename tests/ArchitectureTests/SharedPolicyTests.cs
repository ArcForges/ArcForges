// SPDX-License-Identifier: AGPL-3.0-only

using System.Security.Cryptography;
using System.Text.Json;
using ArcForges.Build.Policy.Architecture;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;

namespace ArcForges.Tests.ArchitectureTests;

public sealed class SharedPolicyTests
{
    public static IEnumerable<object[]> RuleCases => PolicyEngine.Rules.Select(rule => new object[] { rule });

    [Xunit.Theory]
    [Xunit.MemberData(nameof(RuleCases))]
    public void EveryRuleAcceptsItsValidFixtureAndRejectsItsViolation(string rule)
    {
        using var valid = Case.Create(rule, violation: false);
        Xunit.Assert.Empty(valid.Check());
        using var invalid = Case.Create(rule, violation: true);
        Xunit.Assert.Contains(invalid.Check(), finding => finding.Rule == rule);
    }

    [Xunit.Fact]
    public void RuleManifestHasExactlyTheAuthoritativeTwentyFourRules()
    {
        Xunit.Assert.Equal(24, PolicyEngine.Rules.Distinct(StringComparer.Ordinal).Count());
        Xunit.Assert.Equal(Enumerable.Range(1, 14).Select(value => $"AT-{value:00}")
            .Concat(Enumerable.Range(1, 10).Select(value => $"RP-{value:00}")), PolicyEngine.Rules);
    }

    [Xunit.Fact]
    public void GraphRejectsMissingOwnersAndReferenceCycles()
    {
        using var fixture = Case.Create("AT-01", violation: false);
        var first = fixture.Projects[0];
        Xunit.Assert.Throws<InvalidOperationException>(() => new ProjectGraph([first with { ProjectReferences = ["missing.csproj"] }]));
        Xunit.Assert.Throws<InvalidOperationException>(() => new ProjectGraph([first with { ProjectReferences = [first.Classification.Path] }]));
    }

    [Xunit.Fact]
    public void ExceptionsAreExactOwnedExpiringAndCannotCoverAnotherPath()
    {
        using var fixture = Case.Create("RP-02", violation: true);
        var exception = new PolicyException("RP-02", fixture.Projects[^1].Classification.Path, "DesktopPlatform", "Bounded migration", new DateOnly(2030, 1, 1));
        fixture.Exceptions.Add(exception);
        Xunit.Assert.Empty(fixture.Check());
        fixture.Exceptions[0] = exception with { Path = "other.csproj" };
        Xunit.Assert.Contains(fixture.Check(), finding => finding.Rule == "RP-02");
        foreach (var invalid in new[] { exception with { Path = "*" }, exception with { Owner = "Other" }, exception with { Expires = new DateOnly(2020, 1, 1) } })
        {
            fixture.Exceptions[0] = invalid;
            Xunit.Assert.Throws<InvalidOperationException>(() => fixture.Check());
        }
    }

    [Xunit.Fact]
    public void ExternalGateEvidenceMustMatchTheExactSourceAndNotJustSayPassed()
    {
        using var fixture = Case.Create("RP-01", violation: false);
        var evidence = fixture.Evidence[0];
        fixture.Evidence[0] = evidence with { SourceCommit = new string('b', 40) };
        Xunit.Assert.Contains(fixture.Check(), finding => finding.Rule == "RP-01");
        fixture.Evidence[0] = evidence with { Findings = [new PolicyFinding("RP-01", "source.cs", "canonical finding")] };
        Xunit.Assert.Contains(fixture.Check(), finding => finding.Rule == "RP-01");
    }

    public static IEnumerable<object[]> BannedCases =>
    [
        ["BAN-REFLECTION", "using T = System.Type; class C { object? M() => typeof(string); }", "using T = System.Type; class C { object? M() => T.GetType(\"Example\"); }", ProjectRole.Foundation],
        ["BAN-CODEGEN", "class C { object M() => System.Linq.Expressions.Expression.Constant(1); }", "class C { object M() => new System.Reflection.Emit.DynamicMethod(\"example\", typeof(void), System.Type.EmptyTypes); }", ProjectRole.Foundation],
        ["BAN-BLOCKING", "class C { async System.Threading.Tasks.Task M() { await System.Threading.Tasks.Task.Delay(1); } }", "class C { async System.Threading.Tasks.Task M() { await System.Threading.Tasks.Task.Yield(); System.Threading.Tasks.Task.Delay(1).Wait(); } }", ProjectRole.Foundation],
        ["BAN-PROVIDER", "class C { int M() => 1; }", "namespace OpenAI { public static class Client { public static int Call() => 1; } } class C { int M() => OpenAI.Client.Call(); }", ProjectRole.Application],
        ["BAN-LOGGING", "class C { void M() { System.Console.WriteLine(42); } }", "class SecretValue {} class C { void M(SecretValue secret) { System.Console.WriteLine(secret); } }", ProjectRole.Foundation],
        ["BAN-MONEY", "class Money { decimal Add(decimal value) => value + 1m; }", "class Money { double Add(double value) => value + 1d; }", ProjectRole.Foundation],
        ["BAN-POINTER", "class C { internal System.Runtime.InteropServices.SafeHandle? Handle; }", "class C { internal System.IntPtr Handle; }", ProjectRole.NativeAdapter],
    ];

    [Xunit.Theory]
    [Xunit.MemberData(nameof(BannedCases))]
    public void BannedCategoriesUseCompiledSymbols(string rule, string good, string bad, object roleValue)
    {
        ArgumentNullException.ThrowIfNull(roleValue);
        var role = (ProjectRole)roleValue;
        var project = new ProjectClassification("fixture.csproj", role, "DesktopPlatform", Aot: true);
        var positive = FixtureCompiler.Compile("Allowed", new Dictionary<string, string> { ["allowed.cs"] = good });
        var negative = FixtureCompiler.Compile("Forbidden", new Dictionary<string, string> { ["forbidden.cs"] = bad });
        Xunit.Assert.Empty(BannedSymbolScanner.Scan(positive, project));
        Xunit.Assert.Contains(BannedSymbolScanner.Scan(negative, project), finding => finding.Rule == rule);
    }

    [Xunit.Fact]
    public void BannedApiCatalogHasTheSevenCanonicalPortableCategories()
    {
        string[] expected =
        [
            "BAN-REFLECTION",
            "BAN-CODEGEN",
            "BAN-BLOCKING",
            "BAN-PROVIDER",
            "BAN-LOGGING",
            "BAN-MONEY",
            "BAN-POINTER",
        ];

        Xunit.Assert.Equal(expected, BannedSymbolScanner.CategoryCatalog.Select(category => category.Id));
        Xunit.Assert.All(BannedSymbolScanner.CategoryCatalog, category =>
        {
            Xunit.Assert.False(string.IsNullOrWhiteSpace(category.Name));
            Xunit.Assert.False(string.IsNullOrWhiteSpace(category.Description));
        });
    }

    [Xunit.Theory]
    [Xunit.InlineData("BAN-REFLECTION", "using static System.Activator; class C { object? M() => CreateInstance(typeof(string)); }")]
    [Xunit.InlineData("BAN-REFLECTION", "class C { object M(dynamic value) => value.Run(); }")]
    [Xunit.InlineData("BAN-REFLECTION", "class C { object? M(System.Reflection.MethodInfo method) => method.Invoke(null, null); }")]
    [Xunit.InlineData("BAN-PROVIDER", "using static OpenAI.Client; namespace OpenAI { public static class Client { public static int Call() => 1; } } class C { int M() => Call(); }")]
    [Xunit.InlineData("BAN-CODEGEN", "class C { System.Reflection.Emit.DynamicMethod M() => new(\"x\", typeof(void), System.Type.EmptyTypes); }")]
    [Xunit.InlineData("BAN-LOGGING", "class C { void M(string secret) { var value = secret; System.Console.WriteLine(value); } }")]
    [Xunit.InlineData("BAN-BLOCKING", "class C { void Start() { System.Threading.Tasks.Task.Run(async () => { System.Threading.Tasks.Task.Delay(1).Wait(); await System.Threading.Tasks.Task.Yield(); }); } }")]
    [Xunit.InlineData("BAN-BLOCKING", "class C { async System.Threading.Tasks.Task M() { await System.Threading.Tasks.Task.Yield(); System.Threading.Tasks.Task.Delay(1).ConfigureAwait(false).GetAwaiter().GetResult(); } }")]
    [Xunit.InlineData("BAN-BLOCKING", "class C { void Start() { async System.Threading.Tasks.Task Local() { await System.Threading.Tasks.Task.Yield(); System.Threading.Tasks.Task.Delay(1).Wait(); } _ = Local(); } }")]
    public void AlternateSpellingsAndLocalAliasesCannotBypassBannedSymbols(string rule, string source)
    {
        var compilation = FixtureCompiler.Compile("Alternative", new Dictionary<string, string> { ["fixture.cs"] = source });
        Xunit.Assert.Contains(BannedSymbolScanner.Scan(compilation,
            new ProjectClassification("fixture.csproj", ProjectRole.Foundation, "DesktopPlatform", Aot: true)), finding => finding.Rule == rule);
    }

    [Xunit.Theory]
    [Xunit.InlineData("class C { byte[] M() => System.Array.Empty<byte>(); }")]
    [Xunit.InlineData("class C { object M() { byte[] Local() => System.Array.Empty<byte>(); return Local(); } }")]
    [Xunit.InlineData("class C { object M() { System.Func<byte[]> value = () => System.Array.Empty<byte>(); return value(); } }")]
    public void SynchronousArrayReturnTypesDoNotRequireAContainingNamespace(string source)
    {
        var compilation = FixtureCompiler.Compile("ArrayReturn", new Dictionary<string, string> { ["fixture.cs"] = source });
        Xunit.Assert.Empty(BannedSymbolScanner.Scan(compilation,
            new ProjectClassification("fixture.csproj", ProjectRole.Foundation, "DesktopPlatform", Aot: true)));
    }

    [Xunit.Fact]
    public void CommentsAndStringTextAreNotSemanticInvocations()
    {
        var compilation = FixtureCompiler.Compile("Text", new Dictionary<string, string>
        {
            ["allowed.cs"] = "class C { string M() => \"System.Activator.CreateInstance OpenAI.Client.Call secret\"; /* System.Reflection.Emit */ }",
        });
        Xunit.Assert.Empty(BannedSymbolScanner.Scan(compilation,
            new ProjectClassification("fixture.csproj", ProjectRole.Foundation, "DesktopPlatform", Aot: true)));
    }

    [Xunit.Fact]
    public void NativeGraphUsesEvaluatedTargetTypeAndRejectsStaleEvidence()
    {
        string file = Path.GetTempFileName();
        try
        {
            string receipt = """
                {"commit":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","dirty":false,"result":"passed",
                "evidenceClass":"evaluated-cmake-target-declarations","targets":[{"target":"worker",
                "sourceDirectory":"native/worker","targetType":"EXECUTABLE","spdxLicense":"AGPL-3.0-only",
                "licenceBoundary":"AGPL","testOnly":false,"references":[]}]}
                """;
            File.WriteAllText(file, receipt);
            var projects = NativeProjectGraph.Read(file, new string('a', 40), "DesktopPlatform");
            Xunit.Assert.Equal(ProjectRole.NativeWorker, Xunit.Assert.Single(projects).Classification.Role);
            Xunit.Assert.True(projects[0].Classification.Production);
            File.WriteAllText(file, receipt.Replace("\"testOnly\":false", "\"testOnly\":true", StringComparison.Ordinal));
            Xunit.Assert.False(NativeProjectGraph.Read(file, new string('a', 40), "DesktopPlatform")[0].Classification.Production);
            File.WriteAllText(file, receipt);
            Xunit.Assert.Throws<InvalidOperationException>(() => NativeProjectGraph.Read(file, new string('b', 40), "DesktopPlatform"));
            File.WriteAllText(file, receipt.Replace("EXECUTABLE", "UNKNOWN", StringComparison.Ordinal));
            Xunit.Assert.Throws<InvalidOperationException>(() => NativeProjectGraph.Read(file, new string('a', 40), "DesktopPlatform"));
        }
        finally
        {
            File.Delete(file);
        }
    }

    [Xunit.Theory]
    [Xunit.InlineData("Microsoft.Data.Sqlite", "Persistence")]
    [Xunit.InlineData("Microsoft.EntityFrameworkCore", "Infrastructure")]
    [Xunit.InlineData("Avalonia", "UserInterface")]
    [Xunit.InlineData("Grpc.Net.Client", "PublicApiAdapter")]
    public void LayersRejectResolvedPackageEdgesWithoutProjectReferences(string package, string dependencyRole)
    {
        foreach (var layer in new[] { ProjectRole.Domain, ProjectRole.Application })
        {
            using var fixture = Case.Create("AT-01", violation: false);
            fixture.SetDomainLayer(layer);
            fixture.AddDomainPackage(package, Enum.Parse<ProjectRole>(dependencyRole));
            Xunit.Assert.Contains(fixture.Check(), finding => finding.Rule == "AT-01");
            fixture.AddDomainPackage("Pure.Foundation.Fixture", ProjectRole.Foundation);
            Xunit.Assert.DoesNotContain(fixture.Check(), finding => finding.Rule == "AT-01");
            fixture.DependencyRoles.Clear();
            Xunit.Assert.Contains(fixture.Check(), finding => finding.Rule == "AT-01");
        }
    }

    [Xunit.Theory]
    [Xunit.InlineData("public delegate System.IntPtr Callback();", true)]
    [Xunit.InlineData("public delegate void Callback(System.Runtime.InteropServices.SafeHandle value);", true)]
    [Xunit.InlineData("public delegate string Callback(int value);", false)]
    [Xunit.InlineData("public delegate Callback Callback();", false)]
    public void NativeCallbackSignaturesCannotCrossPublicBoundary(string declaration, bool rejected)
    {
        using var fixture = Case.Create("AT-06", violation: false);
        fixture.AddCallback(declaration);
        Xunit.Assert.Equal(rejected, fixture.Check().Any(finding => finding.Rule == "AT-06"));
    }

    [Xunit.Fact]
    public void SameNamedTestTypeCannotHideProductionApi()
    {
        using var fixture = Case.Create("RP-10", violation: false);
        fixture.AddCollidingApi();
        Xunit.Assert.Contains(fixture.Check(), finding => finding.Rule == "AT-06" && finding.Path == "collision/collision.csproj");
    }

    [Xunit.Fact]
    public void ProductionCannotReachTestOnlyNativeTarget()
    {
        using var fixture = Case.Create("AT-09", violation: false);
        var native = fixture.Projects.Single(project => project.Classification.Role == ProjectRole.NativeWorker);
        fixture.Projects[0] = fixture.Projects[0] with
        {
            Classification = fixture.Projects[0].Classification with { Production = true },
            ProjectReferences = [native.Classification.Path],
        };
        Xunit.Assert.Contains(fixture.Check(), finding => finding.Rule == "AT-09");
    }

    [Xunit.Fact]
    public void TraitOnlyMethodsAndNonTestProjectsCannotSatisfyPublicApiContracts()
    {
        using var fixture = Case.Create("RP-10", violation: false);
        fixture.ReplaceTestAttribute("Xunit.Trait(\"category\", \"contract\")");
        Xunit.Assert.Contains(fixture.Check(), finding => finding.Rule == "RP-10");
        fixture.ReplaceTestAttribute("Xunit.Fact");
        Xunit.Assert.Empty(fixture.Check());
        fixture.Projects[0] = fixture.Projects[0] with
        {
            Classification = fixture.Projects[0].Classification with { Role = ProjectRole.BuildTool },
        };
        Xunit.Assert.Contains(fixture.Check(), finding => finding.Rule == "RP-10");
    }

    [Xunit.Fact]
    public void UnresolvedPublicTypesCannotPassSemanticProjectEvaluation()
    {
        string file = Path.GetTempFileName();
        try
        {
            var project = new ProjectFacts(new("subject.csproj", ProjectRole.Foundation, "DesktopPlatform"),
                "net10.0", "Library", "AGPL-3.0-only", "AGPL", [], [file], [typeof(object).Assembly.Location],
                new Dictionary<string, string> { ["AssemblyName"] = "Subject" }, new Dictionary<string, string>());
            File.WriteAllText(file, "public class Api { public string Value => string.Empty; }");
            _ = ProjectGraph.ReadCompilation(project);
            File.WriteAllText(file, "public class Api { public MissingType Value => null; }");
            Xunit.Assert.Throws<InvalidOperationException>(() => ProjectGraph.ReadCompilation(project));
        }
        finally
        {
            File.Delete(file);
        }
    }

    private sealed class Case : IDisposable
    {
        private const string SourceCommit = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        private readonly string _root = Path.Combine(Path.GetTempPath(), "arcforges-policy-" + Guid.NewGuid().ToString("N"));
        private readonly Dictionary<string, CSharpCompilation> _compilations = new(StringComparer.Ordinal);
        private readonly Dictionary<string, string> _licenses = new(StringComparer.OrdinalIgnoreCase);
        public Dictionary<string, ProjectRole> DependencyRoles { get; } = new(StringComparer.OrdinalIgnoreCase);
        private readonly Dictionary<string, string> _toolchains = new(StringComparer.Ordinal);
        private readonly List<ContractTestBinding> _contractTests = [];
        private readonly List<LocalServiceBinding> _services = [];
        private readonly List<WireTypeBinding> _wireTypes = [];
        private bool _mobile;

        public List<ProjectFacts> Projects { get; } = [];
        public List<PolicyException> Exceptions { get; } = [];
        public List<ExternalPolicyEvidence> Evidence { get; } = [
            new("RP-01", SourceCommit, true, []), new("RP-08", SourceCommit, true, []), new("RP-09", SourceCommit, true, [])];

        private Case()
        {
            Directory.CreateDirectory(_root);
            string toolchain = Path.Combine(_root, "global.json");
            File.WriteAllText(toolchain, "{\"sdk\":{\"version\":\"10.0.400\"}}");
            _toolchains.Add("global.json", Hash(toolchain));
            Add("test", ProjectRole.Test, "namespace FixtureTests; public class Contracts { [Xunit.Fact] public void Verify() {} }", production: false);
        }

        public static Case Create(string rule, bool violation)
        {
            var fixture = new Case();
            switch (rule)
            {
                case "AT-01":
                    fixture.Add("dependency", violation ? ProjectRole.Infrastructure : ProjectRole.Abstractions);
                    fixture.Add("subject", ProjectRole.Domain, references: ["dependency/dependency.csproj"]);
                    break;
                case "AT-02":
                case "AT-03":
                    fixture.Add("dependency", violation ? ProjectRole.UserInterface : ProjectRole.Abstractions);
                    fixture.Add("subject", rule == "AT-02" ? ProjectRole.LocalRpcAdapter : ProjectRole.PublicApiAdapter, references: ["dependency/dependency.csproj"]);
                    break;
                case "AT-04":
                    fixture.Add("dependency", violation ? ProjectRole.NativeAdapter : ProjectRole.Foundation);
                    fixture.Add("subject", ProjectRole.Contracts, references: ["dependency/dependency.csproj"]);
                    break;
                case "AT-05":
                    fixture.Add("dependency", violation ? ProjectRole.Domain : ProjectRole.Abstractions, owner: "OtherProduct");
                    fixture.Add("subject", ProjectRole.Application, references: ["dependency/dependency.csproj"]);
                    break;
                case "AT-06":
                    fixture.Add("subject", ProjectRole.NativeAdapter, violation
                        ? "public static class Api { public static System.IntPtr Value() => System.IntPtr.Zero; }"
                        : "public static class Api { public static int Value() => 1; }");
                    break;
                case "AT-07":
                    fixture.Add("dependency", ProjectRole.Persistence, module: violation ? "OtherModule" : "Module");
                    fixture.Add("subject", ProjectRole.Infrastructure, references: ["dependency/dependency.csproj"], module: "Module");
                    break;
                case "AT-08":
                case "AT-11":
                    string argument = rule == "AT-08" && violation ? "object" : "int";
                    string port = rule == "AT-11" && violation ? "" : "private readonly IPort _port = new Port();";
                    fixture.Add("subject", ProjectRole.LocalRpcAdapter,
                        $$"""
                        [System.CodeDom.Compiler.GeneratedCode("grpc_csharp_plugin", "1")] public static class GeneratedRpc
                        { public abstract class ServiceBase { public abstract int Call({{argument}} value); } }
                        internal interface IPort { int Call(); } internal sealed class Port : IPort { int IPort.Call() => 1; }
                        public sealed class Service : GeneratedRpc.ServiceBase { {{port}} public override int Call({{argument}} value) => 1; }
                        """);
                    fixture._services.Add(new("Service", "GeneratedRpc.ServiceBase", "IPort"));
                    break;
                case "AT-09":
                    fixture.Add("subject", ProjectRole.NativeWorker, production: violation);
                    break;
                case "AT-10":
                    fixture.Add("subject", ProjectRole.Infrastructure, packages: new Dictionary<string, string> { [violation ? "Refit" : "Safe.Http"] = "1.0.0" });
                    break;
                case "AT-12":
                    string attribute = violation ? "" : "[System.CodeDom.Compiler.GeneratedCode(\"protoc\", \"1\")] ";
                    fixture.Add("subject", ProjectRole.Contracts, attribute + "public sealed class WireMessage { public int Value { get; set; } }");
                    string schema = Path.Combine(fixture._root, "message.proto");
                    File.WriteAllText(schema, "syntax = \"proto3\"; message WireMessage { int32 value = 1; }");
                    fixture._wireTypes.Add(new("WireMessage", "message.proto", Hash(schema)));
                    break;
                case "AT-13":
                    fixture.Add("dependency", violation ? ProjectRole.Infrastructure : ProjectRole.Abstractions, module: "OtherModule");
                    fixture.Add("subject", ProjectRole.Infrastructure, references: ["dependency/dependency.csproj"], module: "Module");
                    break;
                case "AT-14":
                    fixture.Add("dependency", violation ? ProjectRole.Domain : ProjectRole.Foundation);
                    fixture.Add("subject", ProjectRole.Shell, references: ["dependency/dependency.csproj"]);
                    break;
                case "RP-01":
                case "RP-08":
                case "RP-09":
                    fixture.Add("subject", ProjectRole.Foundation);
                    int index = fixture.Evidence.FindIndex(evidence => evidence.Rule == rule);
                    fixture.Evidence[index] = fixture.Evidence[index] with { Passed = !violation };
                    break;
                case "RP-02":
                    fixture.Add("subject", ProjectRole.Foundation, license: violation ? "" : "AGPL-3.0-only");
                    break;
                case "RP-03":
                    fixture.Add("dependency", ProjectRole.Foundation, boundary: violation ? "AGPL" : "Apache", license: violation ? "AGPL-3.0-only" : "Apache-2.0");
                    fixture.Add("subject", ProjectRole.Foundation, references: ["dependency/dependency.csproj"], boundary: "Apache", license: "Apache-2.0");
                    break;
                case "RP-04":
                    fixture._mobile = true;
                    fixture.Add("subject", ProjectRole.Infrastructure, packages: new Dictionary<string, string> { ["Library"] = "1.0.0" });
                    fixture._licenses["Library"] = violation ? "GPL-3.0-only" : "MIT";
                    break;
                case "RP-05":
                    fixture.Add("subject", ProjectRole.Foundation);
                    if (violation) fixture.SetProperty("ManagePackageVersionsCentrally", "false");
                    break;
                case "RP-06":
                    fixture.Add("subject", ProjectRole.Foundation);
                    if (violation) File.WriteAllText(Path.Combine(fixture._root, "global.json"), "{}");
                    break;
                case "RP-07":
                    fixture.Add("subject", ProjectRole.Foundation);
                    if (violation) fixture.SetProperty("SuppressTrimAnalysisWarnings", "true");
                    break;
                case "RP-10":
                    fixture.Add("subject", ProjectRole.Foundation, "public static class Api { public static int Value() => 1; }");
                    if (violation) fixture._contractTests.Clear();
                    break;
                default:
                    throw new ArgumentOutOfRangeException(nameof(rule));
            }

            return fixture;
        }

        public IReadOnlyList<PolicyFinding> Check() => PolicyEngine.Check(
            new RepositoryFacts(_root, "DesktopPlatform", Projects, Exceptions, _contractTests),
            new RepositoryPolicyConfiguration(SourceCommit, _toolchains, _licenses, new HashSet<string>(StringComparer.Ordinal) { "MIT", "Apache-2.0" },
                _services, _wireTypes, Evidence, MobileDistributable: _mobile, DependencyRoles: DependencyRoles), _compilations, new DateOnly(2026, 9, 27));

        public void AddCallback(string declaration) => Add("callback", ProjectRole.Foundation,
            declaration + " public class Api { public Callback? Value { get; } }");

        public void AddCollidingApi() => Add("collision", ProjectRole.Foundation,
            "namespace FixtureTests; public class Contracts { public System.IntPtr Handle() => default; }");

        public void SetDomainLayer(ProjectRole role)
        {
            int index = Projects.FindIndex(project => project.Classification.Role == ProjectRole.Domain);
            Projects[index] = Projects[index] with { Classification = Projects[index].Classification with { Role = role } };
        }

        public void AddDomainPackage(string package, ProjectRole role)
        {
            int index = Projects.FindIndex(project => project.Classification.Role is ProjectRole.Domain or ProjectRole.Application);
            Projects[index] = Projects[index] with { Packages = new Dictionary<string, string> { [package] = "1.0.0" } };
            _licenses[package] = "MIT";
            DependencyRoles[package] = role;
        }

        public void ReplaceTestAttribute(string attribute)
        {
            _compilations["test/test.csproj"] = FixtureCompiler.Compile("test", new Dictionary<string, string>
            {
                ["test.cs"] = "namespace FixtureTests; public class Contracts { [" + attribute + "] public void Verify() {} }",
            }, [typeof(Xunit.FactAttribute).Assembly.Location]);
        }

        private void Add(string name, ProjectRole role, string source = "internal sealed class Empty {}", string[]? references = null,
            string owner = "DesktopPlatform", string module = "", bool production = true, string license = "AGPL-3.0-only", string boundary = "AGPL",
            Dictionary<string, string>? packages = null)
        {
            string path = name + "/" + name + ".csproj";
            string directory = Path.Combine(_root, name);
            Directory.CreateDirectory(directory);
            File.WriteAllText(Path.Combine(_root, path), "<Project />");
            packages ??= new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            File.WriteAllText(Path.Combine(directory, "packages.lock.json"), JsonSerializer.Serialize(new
            {
                version = 1,
                dependencies = new Dictionary<string, object> { ["net10.0"] = packages.ToDictionary(package => package.Key, package => new { type = "Direct", resolved = package.Value }) },
            }));
            foreach (string package in packages.Keys) _licenses.TryAdd(package, "MIT");
            var facts = new ProjectFacts(new ProjectClassification(path, role, owner, module, production), "net10.0", "Library", license, boundary,
                references ?? [], [name + ".cs"], [], new Dictionary<string, string>(StringComparer.Ordinal)
                {
                    ["ManagePackageVersionsCentrally"] = "true",
                    ["RestorePackagesWithLockFile"] = "true",
                    ["EnableTrimAnalyzer"] = "true",
                    ["EnableAotAnalyzer"] = "true",
                }, packages);
            Projects.Add(facts);
            var compilation = FixtureCompiler.Compile(name, new Dictionary<string, string> { [name + ".cs"] = source }, [typeof(Xunit.FactAttribute).Assembly.Location]);
            _compilations.Add(path, compilation);
            if (production)
            {
                foreach (var tree in compilation.SyntaxTrees)
                {
                    var model = compilation.GetSemanticModel(tree);
                    foreach (var method in tree.GetRoot().DescendantNodes().OfType<Microsoft.CodeAnalysis.CSharp.Syntax.MethodDeclarationSyntax>())
                    {
                        if (model.GetDeclaredSymbol(method) is IMethodSymbol symbol && symbol.DeclaredAccessibility == Accessibility.Public)
                        {
                            _contractTests.Add(new(PolicyEngine.MethodIdentity(symbol), "test/test.csproj", "FixtureTests.Contracts.Verify()"));
                        }
                    }
                }
            }
        }

        private void SetProperty(string name, string value)
        {
            int index = Projects.Count - 1;
            var properties = new Dictionary<string, string>(Projects[index].Properties, StringComparer.Ordinal) { [name] = value };
            Projects[index] = Projects[index] with { Properties = properties };
        }

        private static string Hash(string path) => Convert.ToHexStringLower(SHA256.HashData(File.ReadAllBytes(path)));

        public void Dispose()
        {
            string expectedParent = Path.GetFullPath(Path.GetTempPath()).TrimEnd(Path.DirectorySeparatorChar);
            if (Path.GetDirectoryName(_root) != expectedParent || !Path.GetFileName(_root).StartsWith("arcforges-policy-", StringComparison.Ordinal))
            {
                throw new InvalidOperationException("Unexpected fixture cleanup path.");
            }

            Directory.Delete(_root, recursive: true);
        }
    }
}
