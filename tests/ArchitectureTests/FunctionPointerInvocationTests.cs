// SPDX-License-Identifier: AGPL-3.0-only

using ArcForges.Build.Policy.Architecture;

namespace ArcForges.Tests.ArchitectureTests;

/// <summary>
/// Regressions for the banned-symbol scanner's handling of an invocation through a function pointer (<c>delegate*</c>).
/// Such a call has no managed callee symbol, so the scan continues past it and still audits its arguments; every other
/// invocation the scanner cannot resolve still aborts the scan.
/// Explicit non-goal: a taken address (<c>&amp;Banned.Method</c>, a method group or an <c>ldftn</c>) is not audited as an
/// invocation, the same gap as an existing method-group conversion. The scanner classifies calls, not addresses, and
/// <see cref="ATakenAddressOfABannedMethodIsNotAudited"/> pins that behaviour so the gap is stated and cannot change silently.
/// </summary>
public sealed class FunctionPointerInvocationTests
{
    private static readonly ProjectClassification Project =
        new("fixture.csproj", ProjectRole.Foundation, "DesktopPlatform", Aot: true);

    // The shape of ArcScope's NativePackageProof.cs: an unmanaged export obtained at run time, then called.
    private const string Reproducer = """
        using System.Runtime.InteropServices;
        internal static unsafe class Proof
        {
            internal static int Run(nint library)
            {
                var negotiate = (delegate* unmanaged[Cdecl]<uint*, uint*, int>)NativeLibrary.GetExport(library, "arc_image_get_abi_version");
                uint minor = 0;
                return negotiate(null, &minor);
            }
        }
        """;

    [Xunit.Fact]
    public void TheExactReproducerScansWithoutThrowingAndHasNoFindings()
    {
        var compilation = FixtureCompiler.Compile("Reproducer", new Dictionary<string, string> { ["proof.cs"] = Reproducer });
        Xunit.Assert.Empty(BannedSymbolScanner.Scan(compilation, Project));
    }

    [Xunit.Theory]
    [Xunit.InlineData("internal static unsafe class C { static int Id(int v) => v; internal static int Run() { delegate*<int, int> f = &Id; return f(1); } }")]
    [Xunit.InlineData("internal static unsafe class C { static int Id(int v) => v; internal static int Run() { delegate* managed<int, int> f = &Id; return f(1); } }")]
    [Xunit.InlineData("internal static unsafe class C { internal static delegate* unmanaged<int, int> F; internal static int Run() => F(1); }")]
    public void ManagedAndUnmanagedFunctionPointerCallsAreNotUnresolved(string source)
    {
        var compilation = FixtureCompiler.Compile("Pointers", new Dictionary<string, string> { ["pointers.cs"] = source });
        Xunit.Assert.Empty(BannedSymbolScanner.Scan(compilation, Project));
    }

    [Xunit.Theory]
    [Xunit.InlineData("BAN-BLOCKING", "internal static class C { internal static unsafe delegate* unmanaged<int, int> F; internal static async System.Threading.Tasks.Task<int> Run() { await System.Threading.Tasks.Task.Yield(); int r; unsafe { r = F(System.Threading.Tasks.Task.FromResult(1).Result); } return r; } }")]
    [Xunit.InlineData("BAN-REFLECTION", "internal static unsafe class C { internal static delegate* unmanaged<int, int> F; internal static int Run() => F(typeof(string).GetMethod(\"Trim\")!.GetHashCode()); }")]
    [Xunit.InlineData("BAN-CODEGEN", "internal static unsafe class C { internal static delegate* unmanaged<int, int> F; internal static int Run() => F(new System.Reflection.Emit.DynamicMethod(\"x\", typeof(void), System.Type.EmptyTypes).GetHashCode()); }")]
    [Xunit.InlineData("BAN-MONEY", "internal static unsafe class Money { internal static delegate* unmanaged<int, int> F; internal static int Run(double price) => F((int)(price + 1d)); }")]
    public void BannedCodeNestedInAFunctionPointerCallIsStillReported(string rule, string source)
    {
        var compilation = FixtureCompiler.Compile("Nested", new Dictionary<string, string> { ["nested.cs"] = source });
        Xunit.Assert.Contains(BannedSymbolScanner.Scan(compilation, Project), finding => finding.Rule == rule);
    }

    [Xunit.Fact]
    public void ABannedCallElsewhereInTheSameFileIsStillReported()
    {
        string source = Reproducer + """

            internal static class Other
            {
                internal static async System.Threading.Tasks.Task Run()
                {
                    await System.Threading.Tasks.Task.Yield();
                    System.Threading.Tasks.Task.Delay(1).Wait();
                }
            }
            """;
        var compilation = FixtureCompiler.Compile("Same", new Dictionary<string, string> { ["same.cs"] = source });
        var findings = BannedSymbolScanner.Scan(compilation, Project);
        Xunit.Assert.Single(findings, finding => finding.Rule == "BAN-BLOCKING");
        Xunit.Assert.DoesNotContain(findings, finding => finding.Rule != "BAN-BLOCKING");
    }

    [Xunit.Theory]
    [Xunit.InlineData("class C { void M() { Missing(); } }", true)]
    [Xunit.InlineData("class C { void M(dynamic value) { value.Run(); } }", false)]
    public void OtherUnresolvedInvocationsStillFailClosed(string source, bool aot)
    {
        var compilation = FixtureCompiler.Create("Unresolved", new Dictionary<string, string> { ["unresolved.cs"] = source });
        var project = Project with { Aot = aot };
        var error = Xunit.Assert.Throws<InvalidOperationException>(() => BannedSymbolScanner.Scan(compilation, project));
        Xunit.Assert.Contains("Unresolved invocation cannot be audited", error.Message, StringComparison.Ordinal);
    }

    [Xunit.Fact]
    public void AnInvocationOfAnErroneousFunctionPointerShapeStillFailsClosed()
    {
        // The callee is not a function pointer, so the repair must not classify it: only a bound function-pointer
        // invocation is exempt.
        var compilation = FixtureCompiler.Create("NotAPointer", new Dictionary<string, string>
        {
            ["bad.cs"] = "internal static unsafe class C { internal static int Run() { int* p = null; return p(1); } }",
        });
        Xunit.Assert.Throws<InvalidOperationException>(() => BannedSymbolScanner.Scan(compilation, Project));
    }

    [Xunit.Fact]
    public void ATakenAddressOfABannedMethodIsNotAudited()
    {
        // Documented non-goal (see the class comment): the address is taken, not invoked, and the later call through the
        // pointer has no managed symbol. This mirrors the existing gap for method-group conversions.
        const string source = "internal static unsafe class C { internal static void Run() { delegate*<int, void> f = &System.Threading.Thread.Sleep; f(1); } }";
        var compilation = FixtureCompiler.Compile("TakenAddress", new Dictionary<string, string> { ["address.cs"] = source });
        Xunit.Assert.Empty(BannedSymbolScanner.Scan(compilation, Project));
    }
}
