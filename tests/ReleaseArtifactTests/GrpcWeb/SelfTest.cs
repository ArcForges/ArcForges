// SPDX-License-Identifier: AGPL-3.0-only
namespace ArcForges.ReleaseArtifactTests.GrpcWeb;

/// <summary>
/// Tests the probe itself: the option guards, the verifier against a well-behaved fixture, and the verifier against
/// a fixture that misbehaves in one named way at a time (each misbehavior must be caught by a named check).
/// Nothing here contacts a real ingress, so a pass is never evidence about one.
/// </summary>
internal static class SelfTest
{
    private static readonly Uri FixtureAddress = new("https://fixture.invalid/api/");

    /// <summary>Every check a complete run records, so a silently skipped check fails the self-test.</summary>
    public static readonly string[] ExpectedCheckNames =
    [
        "identity.health", "unary.success.message", "unary.success.trailers", "unary.success.request-shape",
        "unary.success.response-headers", "exact.unicode", "exact.boundary-256", "exact.boundary-256-utf16-pairs",
        "error.empty-name", "error.application-status-in-http-200", "error.too-long", "error.too-long-utf16-pairs",
        "cancel.in-flight", "cancel.reached-transport", "cancel.channel-recovers", "deadline.expired",
        "deadline.header-format", "target.unknown-method", "target.unreachable", "loss.single-attempt",
        "loss.explicit-retry-succeeds", "boundary.http-413", "boundary.http-415", "boundary.http-429", "boundary.http-503",
        "codec.int64-extremes", "codec.uint64-maximum", "codec.signed-and-unsigned-pair", "codec.decimal-string",
    ];

    private static readonly (FixtureFault Fault, string[] MustFail)[] Mutants =
    [
        (FixtureFault.OmitTrailerFrame, ["unary.success.trailers"]),
        (FixtureFault.EmptyNameSucceeds, ["error.empty-name"]),
        (FixtureFault.TooLongSucceeds, ["error.too-long", "error.too-long-utf16-pairs"]),
        (FixtureFault.CountUtf8BytesNotUtf16Units, ["exact.boundary-256-utf16-pairs"]),
        (FixtureFault.RewriteUnicode, ["exact.unicode"]),
        (FixtureFault.ApplicationErrorAsHttp400, ["error.application-status-in-http-200"]),
        (FixtureFault.NoWorkerRevisionHeader, ["unary.success.response-headers"]),
        (FixtureFault.WorkerRevisionMismatch, ["unary.success.response-headers"]),
        (FixtureFault.UnknownMethodSucceeds, ["target.unknown-method"]),
        (FixtureFault.HealthReportsJit, ["identity.health"]),
        (FixtureFault.HttpFailureAsSuccess, ["boundary.http-413", "boundary.http-415", "boundary.http-429", "boundary.http-503"]),
    ];

    public static async Task<CheckRecorder> RunAsync()
    {
        var meta = new CheckRecorder();
        CheckOptionGuards(meta);
        CheckTimeoutParser(meta);
        var baseline = await RunFixtureAsync(FixtureFault.None).ConfigureAwait(false);
        string[] failing = [.. baseline.Results.Where(result => !result.Passed).Select(result => result.Name + ": " + result.Detail)];
        meta.Expect("fixture.baseline-passes", baseline.AllPassed,
            "The verifier accepts the well-behaved fixture" + (failing.Length == 0 ? "." : "; failing: " + string.Join(" | ", failing)));
        string[] recorded = [.. baseline.Results.Select(result => result.Name).Order(StringComparer.Ordinal)];
        meta.Expect("fixture.baseline-records-every-check", recorded.SequenceEqual(ExpectedCheckNames.Order(StringComparer.Ordinal)),
            $"The fixture run recorded exactly the {ExpectedCheckNames.Length} expected checks, none skipped and none extra.");
        var runs = await Task.WhenAll(Mutants.Select(async mutant => (mutant, Recorder: await RunFixtureAsync(mutant.Fault).ConfigureAwait(false))))
            .ConfigureAwait(false);
        foreach (var ((fault, mustFail), recorder) in runs)
        {
            bool caught = mustFail.All(recorder.Failed) && !recorder.AllPassed;
            meta.Expect("mutant." + fault, caught,
                $"The verifier fails {string.Join(" and ", mustFail)} when the fixture misbehaves as {fault}.");
        }

        return meta;
    }

    private static async Task<CheckRecorder> RunFixtureAsync(FixtureFault fault)
    {
        var state = new FixtureState(fault);
        var target = new ScenarioTarget
        {
            BaseAddress = FixtureAddress,
            CreateTransport = () => new IngressFixtureHandler(state),
            Fixture = state,
        };
        var recorder = new CheckRecorder();
        await HelloScenarios.RunCommonAsync(target, recorder).ConfigureAwait(false);
        await HelloScenarios.RunFixtureOnlyAsync(target, recorder).ConfigureAwait(false);
        CodecPrimitives.Run(recorder);
        return recorder;
    }

    private static void CheckTimeoutParser(CheckRecorder meta)
    {
        meta.Expect("timeout-parser.units",
            HelloScenarios.ParseGrpcTimeout("5S") == 5000 && HelloScenarios.ParseGrpcTimeout("1500m") == 1500 &&
            HelloScenarios.ParseGrpcTimeout("2M") == 120_000 && HelloScenarios.ParseGrpcTimeout("1H") == 3_600_000 &&
            HelloScenarios.ParseGrpcTimeout("5000u") == 5 && HelloScenarios.ParseGrpcTimeout("3000000n") == 3,
            "Every gRPC timeout unit is converted to milliseconds exactly.");
        meta.Expect("timeout-parser.rejects-malformed",
            HelloScenarios.ParseGrpcTimeout(null) is null && HelloScenarios.ParseGrpcTimeout("5") is null &&
            HelloScenarios.ParseGrpcTimeout("0S") is null && HelloScenarios.ParseGrpcTimeout("123456789S") is null &&
            HelloScenarios.ParseGrpcTimeout("5s") is null && HelloScenarios.ParseGrpcTimeout("-5S") is null &&
            HelloScenarios.ParseGrpcTimeout("5S ") is null,
            "A missing, unitless, zero, nine digit, lower case or padded timeout is not accepted.");
    }

    private static void CheckOptionGuards(CheckRecorder meta)
    {
        static string? NoEnvironment(string name) => null;
        static Func<string, string?> With(string name, string value) => key => key == name ? value : null;
        const string good = "https://ingress.example/api";
        string revision = new('a', 40);

        var selfTest = ProbeOptionsParser.Parse(["--self-test"], NoEnvironment);
        meta.Expect("options.self-test", selfTest.Options is { Mode: ProbeMode.SelfTest, BaseAddress: null }, "--self-test selects the fixture run.");
        meta.Expect("options.requires-exactly-one-mode",
            ProbeOptionsParser.Parse([], NoEnvironment).Error is not null &&
            ProbeOptionsParser.Parse(["--self-test", "--live", good], NoEnvironment).Error is not null,
            "No mode, or both modes, is refused.");
        meta.Expect("options.unknown-and-duplicate-and-valueless",
            ProbeOptionsParser.Parse(["--bogus"], NoEnvironment).Error is not null &&
            ProbeOptionsParser.Parse(["--self-test", "--self-test"], NoEnvironment).Error is not null &&
            ProbeOptionsParser.Parse(["--live", good, "--live", good], NoEnvironment).Error is not null &&
            ProbeOptionsParser.Parse(["--live"], NoEnvironment).Error is not null &&
            ProbeOptionsParser.Parse(["--live", "--evidence", "x.json"], NoEnvironment).Error is not null,
            "An unknown argument, a repeated flag and a flag without a value are refused.");
        meta.Expect("options.live-accepts-https-address",
            ProbeOptionsParser.Parse(["--live", good], NoEnvironment).Options is { Mode: ProbeMode.Live, BaseAddress.AbsolutePath: "/api/" },
            "A plain https base address is accepted and its path ends with a slash.");
        meta.Expect("options.live-refused-when-CI-is-true",
            ProbeOptionsParser.Parse(["--live", good], With("CI", "true")).Error is not null &&
            ProbeOptionsParser.Parse(["--live", good], With("CI", "TRUE")).Error is not null &&
            ProbeOptionsParser.Parse(["--live", good], With("CI", "false")).Options is not null,
            "The live mode refuses CI=true and accepts CI=false.");
        meta.Expect("options.live-refused-when-GITHUB_ACTIONS-is-true",
            ProbeOptionsParser.Parse(["--live", good], With("GITHUB_ACTIONS", "true")).Error is not null,
            "The live mode refuses a GitHub Actions environment.");
        meta.Expect("options.self-test-is-not-refused-in-CI",
            ProbeOptionsParser.Parse(["--self-test"], With("CI", "true")).Options is not null,
            "The offline self-test is not a live service call and is allowed anywhere.");
        meta.Expect("options.address-requires-https-except-loopback",
            ProbeOptionsParser.ValidateBaseAddress("http://ingress.example/api/").Uri is null &&
            ProbeOptionsParser.ValidateBaseAddress("ftp://ingress.example/api/").Uri is null &&
            ProbeOptionsParser.ValidateBaseAddress("http://127.0.0.1:8080/api").Uri is not null &&
            ProbeOptionsParser.ValidateBaseAddress("http://localhost:8080/").Uri is not null,
            "Plain http is accepted only for a loopback host.");
        meta.Expect("options.address-refuses-credentials-query-fragment",
            ProbeOptionsParser.ValidateBaseAddress("https://user@ingress.example/api/").Uri is null &&
            ProbeOptionsParser.ValidateBaseAddress("https://ingress.example/api/?x=1").Uri is null &&
            ProbeOptionsParser.ValidateBaseAddress("https://ingress.example/api/#x").Uri is null &&
            ProbeOptionsParser.ValidateBaseAddress("https://ingress.example/api/?").Uri is null,
            "A base address with user information, a query (even an empty one) or a fragment is refused.");
        meta.Expect("options.address-must-be-absolute",
            ProbeOptionsParser.ValidateBaseAddress("ingress.example/api").Uri is null &&
            ProbeOptionsParser.ValidateBaseAddress(string.Empty).Uri is null,
            "A relative or empty base address is refused.");
        meta.Expect("options.revision-is-forty-lowercase-hex",
            ProbeOptionsParser.Parse(["--live", good, "--expect-revision", revision], NoEnvironment).Options?.ExpectedRevision == revision &&
            ProbeOptionsParser.Parse(["--live", good, "--expect-revision", revision.ToUpperInvariant()], NoEnvironment).Error is not null &&
            ProbeOptionsParser.Parse(["--live", good, "--expect-revision", revision[..39]], NoEnvironment).Error is not null &&
            ProbeOptionsParser.Parse(["--live", good, "--expect-revision", revision + "a"], NoEnvironment).Error is not null,
            "Only a full lowercase 40 character hexadecimal revision is accepted.");
        meta.Expect("options.revision-applies-only-to-live",
            ProbeOptionsParser.Parse(["--self-test", "--expect-revision", revision], NoEnvironment).Error is not null,
            "--expect-revision with --self-test is refused.");
        meta.Expect("options.evidence-needs-a-name",
            ProbeOptionsParser.Parse(["--self-test", "--evidence", " "], NoEnvironment).Error is not null &&
            ProbeOptionsParser.Parse(["--self-test", "--evidence", "out.json"], NoEnvironment).Options?.EvidencePath == "out.json",
            "A blank evidence file name is refused and a real one is kept.");
    }
}
