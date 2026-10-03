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
        "cancel.at-handoff", "cancel.at-handoff-no-response", "cancel.channel-recovers", "cancel.after-response-headers",
        "cancel.channel-recovers-after-response", "deadline.expired",
        "deadline.header-format", "target.unknown-method", "local.closed-port-unavailable", "loss.single-attempt",
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
        (FixtureFault.EmptyNameWrongCode, ["error.empty-name"]),
        (FixtureFault.EmptyNameNoMessage, ["error.empty-name"]),
        (FixtureFault.HealthServerError, ["identity.health"]),
        (FixtureFault.UnknownMethodForbidden, ["target.unknown-method"]),
        (FixtureFault.WrongResponseMediaType, ["unary.success.response-headers"]),
        (FixtureFault.BrokenAfterCancel, ["cancel.channel-recovers"]),
        (FixtureFault.HealthBadRevision, ["identity.health"]),
        (FixtureFault.CountCodePointsNotUtf16Units, ["error.too-long-utf16-pairs"]),
    ];

    /// <summary>Damage done to the client's own request, which a correct verifier must notice on the transport.</summary>
    private static readonly (string Name, Action<HttpRequestMessage> Mutate, string[] MustFail)[] ClientFaults =
    [
        ("DropPathBase", request => request.RequestUri = new UriBuilder(request.RequestUri!)
            { Path = request.RequestUri!.AbsolutePath.Replace("/api", string.Empty, StringComparison.Ordinal) }.Uri,
            ["unary.success.request-shape"]),
        ("WrongMethod", request => request.Method = HttpMethod.Put, ["unary.success.request-shape"]),
        ("WrongRequestMediaType", request => request.Content!.Headers.ContentType = new("text/plain"), ["unary.success.request-shape"]),
        ("OversizedTimeout", request =>
        {
            request.Headers.Remove("grpc-timeout");
            request.Headers.TryAddWithoutValidation("grpc-timeout", "99999S");
        }, ["deadline.header-format"]),
    ];

    public static async Task<CheckRecorder> RunAsync()
    {
        var meta = new CheckRecorder();
        CheckOptionGuards(meta);
        CheckTimeoutParser(meta);
        CheckRecorderGuards(meta);
        CheckCodecAndTransportGuards(meta);
        var baseline = await RunFixtureAsync(FixtureFault.None).ConfigureAwait(false);
        string[] failing = [.. baseline.Results.Where(result => !result.Passed).Select(result => result.Name + ": " + result.Detail)];
        meta.Expect("fixture.baseline-passes", baseline.AllPassed,
            "The verifier accepts the well-behaved fixture" + (failing.Length == 0 ? "." : "; failing: " + string.Join(" | ", failing)));
        meta.Expect("fixture.baseline-records-every-check", RecordedExactly(baseline),
            $"The fixture run recorded exactly the {ExpectedCheckNames.Length} expected checks, none skipped and none extra.");
        var serverRuns = Task.WhenAll(Mutants.Select(async mutant => (mutant.Fault.ToString(), mutant.MustFail,
            Recorder: await RunFixtureAsync(mutant.Fault).ConfigureAwait(false))));
        var clientRuns = Task.WhenAll(ClientFaults.Select(async fault => ("client-" + fault.Name, fault.MustFail,
            Recorder: await RunFixtureAsync(FixtureFault.None, fault.Mutate, failureInjection: false).ConfigureAwait(false))));
        var staleRuns = Task.WhenAll(RunStaleTargetAsync(matching: true), RunStaleTargetAsync(matching: false));
        foreach ((string name, string[] mustFail, var recorder) in (await serverRuns.ConfigureAwait(false))
            .Concat(await clientRuns.ConfigureAwait(false)))
        {
            meta.Expect("mutant." + name, Caught(recorder, mustFail),
                $"The verifier fails {string.Join(" and ", mustFail)} when the fixture or client misbehaves as {name}.");
        }

        var stale = await staleRuns.ConfigureAwait(false);
        meta.Expect("stale-target.matching-revision-passes", stale[0].Passed("identity.expected-revision"),
            "A deployment whose revision equals the expected revision passes.");
        meta.Expect("stale-target.other-revision-fails", stale[1].Failed("identity.expected-revision"),
            "A deployment whose revision differs from the expected revision fails as a stale target.");
        CheckVerdictHelpers(meta);
        return meta;
    }

    internal static bool Caught(CheckRecorder recorder, string[] mustFail) => mustFail.All(recorder.Failed) && !recorder.AllPassed;

    internal static bool RecordedExactly(CheckRecorder recorder) =>
        recorder.Results.Select(result => result.Name).Order(StringComparer.Ordinal).SequenceEqual(ExpectedCheckNames.Order(StringComparer.Ordinal));

    private static void CheckVerdictHelpers(CheckRecorder meta)
    {
        var onlyOne = new CheckRecorder();
        onlyOne.Expect("x", false, "bad");
        onlyOne.Expect("y", true, "ok");
        var allPass = new CheckRecorder();
        allPass.Expect("x", true, "ok");
        var both = new CheckRecorder();
        both.Expect("x", false, "bad");
        both.Expect("y", false, "bad");
        meta.Expect("verdict.a-mutant-is-caught-only-when-every-named-check-fails",
            Caught(both, ["x", "y"]) && !Caught(onlyOne, ["x", "y"]) && !Caught(allPass, ["x"]) && Caught(onlyOne, ["x"]),
            "A misbehavior counts as caught only when every named check failed.");
        var missing = new CheckRecorder();
        foreach (string name in ExpectedCheckNames.Skip(1))
        {
            missing.Expect(name, true, "ok");
        }

        var extra = new CheckRecorder();
        foreach (string name in ExpectedCheckNames.Append("unexpected"))
        {
            extra.Expect(name, true, "ok");
        }

        var exact = new CheckRecorder();
        foreach (string name in ExpectedCheckNames)
        {
            exact.Expect(name, true, "ok");
        }

        meta.Expect("verdict.a-skipped-or-extra-check-is-detected", RecordedExactly(exact) && !RecordedExactly(missing) && !RecordedExactly(extra),
            "A run that skips or adds a check does not match the expected check list.");
    }

    private static async Task<CheckRecorder> RunStaleTargetAsync(bool matching)
    {
        var state = new FixtureState(FixtureFault.None);
        var target = new ScenarioTarget
        {
            BaseAddress = FixtureAddress,
            CreateTransport = () => new IngressFixtureHandler(state),
            Fixture = state,
            ExpectedRevision = matching ? state.Revision : new string('e', 40),
        };
        var recorder = new CheckRecorder();
        await HelloScenarios.CheckIdentityAsync(target, recorder).ConfigureAwait(false);
        return recorder;
    }

    private static async Task<CheckRecorder> RunFixtureAsync(FixtureFault fault, Action<HttpRequestMessage>? mutate = null, bool failureInjection = true)
    {
        var state = new FixtureState(fault);
        var target = new ScenarioTarget
        {
            BaseAddress = FixtureAddress,
            CreateTransport = () => new IngressFixtureHandler(state),
            Fixture = state,
            MutateRequest = mutate,
        };
        var recorder = new CheckRecorder();
        await HelloScenarios.RunCommonAsync(target, recorder).ConfigureAwait(false);
        if (failureInjection)
        {
            await HelloScenarios.RunFixtureOnlyAsync(target, recorder).ConfigureAwait(false);
        }

        CodecPrimitives.Run(recorder);
        return recorder;
    }

    private static void CheckCodecAndTransportGuards(CheckRecorder meta)
    {
        var revision = new ArcForges.Contracts.Foundation.V1.Revision { Value = 7 };
        byte[] correct = [0x08, 0x07];
        meta.Expect("codec.verifier-accepts-the-exact-encoding-only",
            CodecPrimitives.Exact(revision, correct, ArcForges.Contracts.Foundation.V1.Revision.Parser) &&
            !CodecPrimitives.Exact(revision, [0x08, 0x08], ArcForges.Contracts.Foundation.V1.Revision.Parser) &&
            !CodecPrimitives.Exact(revision, [0x08, 0x07, 0x00], ArcForges.Contracts.Foundation.V1.Revision.Parser) &&
            !CodecPrimitives.Exact(new ArcForges.Contracts.Foundation.V1.Revision { Value = 8 }, correct, ArcForges.Contracts.Foundation.V1.Revision.Parser),
            "The codec verifier rejects a wrong wire value, trailing bytes and a decoded value that differs.");
        using var real = ProbeChannel.CreateRealTransport(useSystemProxy: false);
        meta.Expect("transport.real-handler-never-redirects-stores-cookies-or-decompresses",
            !real.AllowAutoRedirect && !real.UseCookies && real.AutomaticDecompression == System.Net.DecompressionMethods.None && !real.UseProxy,
            "The real socket transport follows no redirect, keeps no cookie and decompresses nothing (a proxy is used only when asked).");
        using var proxied = ProbeChannel.CreateRealTransport(useSystemProxy: true);
        meta.Expect("transport.system-proxy-only-when-requested", proxied.UseProxy,
            "The live transport uses the system proxy settings as they are, and the closed-port transport does not.");
    }

    private static void CheckRecorderGuards(CheckRecorder meta)
    {
        var empty = new CheckRecorder();
        var failed = new CheckRecorder();
        failed.Expect("a", true, "ok");
        failed.Expect("b", false, "bad");
        var twice = new CheckRecorder();
        twice.Expect("a", true, "ok");
        bool refusedRepeat = false;
        try
        {
            twice.Expect("a", true, "again");
        }
        catch (InvalidOperationException)
        {
            refusedRepeat = true;
        }

        meta.Expect("recorder.empty-run-is-not-a-pass", !empty.AllPassed, "A run that recorded no check is not a pass.");
        meta.Expect("recorder.one-failure-fails-the-run",
            !failed.AllPassed && failed.Passed("a") && failed.Failed("b") && !failed.Passed("b") && !failed.Failed("a"),
            "One failed check fails the run and is reported as failed, not as passed.");
        meta.Expect("recorder.refuses-a-repeated-name", refusedRepeat, "Recording the same check name twice is refused.");
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
        meta.Expect("options.flag-value-is-not-another-flag",
            ProbeOptionsParser.Parse(["--self-test", "--evidence", "--live"], NoEnvironment).Error is not null,
            "A flag cannot take another flag as its value.");
        meta.Expect("options.address-refuses-an-at-sign-anywhere",
            ProbeOptionsParser.ValidateBaseAddress("https://ingress.example/@x/").Uri is null,
            "An at sign anywhere in the base address is refused, whether or not it parses as user information.");
        meta.Expect("options.evidence-needs-a-name",
            ProbeOptionsParser.Parse(["--self-test", "--evidence", " "], NoEnvironment).Error is not null &&
            ProbeOptionsParser.Parse(["--self-test", "--evidence", "out.json"], NoEnvironment).Options?.EvidencePath == "out.json",
            "A blank evidence file name is refused and a real one is kept.");
    }
}
