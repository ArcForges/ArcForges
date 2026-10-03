// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Foundation.Errors;
using ArcForges.Security.Decisions;
using ArcForges.Security.Egress;
using Xunit;

namespace ArcForges.Security.Tests;

/// <summary>One named egress situation: the harness configured for it, the request, the destination asked about and the expected reason.</summary>
internal sealed record EgressScenario(EgressHarness Harness, DecisionRequest Request, string Destination, EgressReason Expected);

internal static class EgressScenarios
{
    internal static IEnumerable<string> Names { get; } =
    [
        "allowed", "allowed-aliased-destination", "not-declared", "declared-other", "declared-invalid", "malformed",
        "class-null", "class-none", "class-undefined", "secret", "not-allowlisted", "allowlist-other-scope",
        "allowlist-other-destination", "above-allowlist", "ai-ineligible", "no-grant", "grant-denied", "grant-denied-beats-granted",
        "grant-denied-expired", "grant-other-principal", "grant-other-capability", "grant-other-scope", "grant-other-destination",
        "grant-not-yet-valid", "grant-expired", "grant-until-boundary", "grant-from-boundary", "grant-above-class",
        "grant-expired-admits-more",
    ];

    public static TheoryData<string> Data
    {
        get
        {
            var data = new TheoryData<string>();
            foreach (var name in Names)
            {
                data.Add(name);
            }

            return data;
        }
    }

    internal static EgressScenario Build(string name)
    {
        var h = new EgressHarness();
        var request = h.Request();
        var destination = EgressHarness.Destination;
        var expected = EgressReason.None;
        h.Permit(request);
        switch (name)
        {
            case "allowed":
                break;
            case "allowed-aliased-destination":
                request = h.Request("HTTPS://API.Example.COM:443/");
                destination = "HTTPS://API.Example.COM:443/";
                h.Permit(request);
                break;
            case "not-declared":
                request = h.Request(null);
                h.Permit(request);
                expected = EgressReason.DestinationNotDeclared;
                break;
            case "declared-other":
                request = h.Request("https://other.example.com");
                h.Permit(request);
                expected = EgressReason.DestinationNotDeclared;
                break;
            case "declared-invalid":
                request = h.Request("api.example.com");
                h.Permit(request);
                expected = EgressReason.DestinationNotDeclared;
                break;
            case "malformed":
                destination = "http://api.example.com";
                expected = EgressReason.DestinationMalformed;
                break;
            case "class-null":
                h.Classifier.Behavior = (_, _, _) => ValueTask.FromResult<EgressContentFacts?>(null);
                expected = EgressReason.ContentUnclassified;
                break;
            case "class-none":
                h.Classify(EgressDataClass.None);
                expected = EgressReason.ContentUnclassified;
                break;
            case "class-undefined":
                h.Classify((EgressDataClass)99);
                expected = EgressReason.ContentUnclassified;
                break;
            case "secret":
                h.Classify(EgressDataClass.SecretMaterial);
                h.Permit(request, allowlistMax: EgressDataClass.SensitiveContent, grantMax: EgressDataClass.SensitiveContent);
                expected = EgressReason.SecretMaterial;
                break;
            case "not-allowlisted":
                h.Allowlist.Behavior = (_, _, _) => ValueTask.FromResult<EgressAllowlistEntry?>(null);
                expected = EgressReason.NotAllowlisted;
                break;
            case "allowlist-other-scope":
                h.Allowlist.Behavior = (_, _, _) => ValueTask.FromResult<EgressAllowlistEntry?>(EgressHarness.Entry(request, scopeKey: "realm:other/workspace:-"));
                expected = EgressReason.AllowlistMismatch;
                break;
            case "allowlist-other-destination":
                h.Allowlist.Behavior = (_, _, _) => ValueTask.FromResult<EgressAllowlistEntry?>(EgressHarness.Entry(request, "https://other.example.com"));
                expected = EgressReason.AllowlistMismatch;
                break;
            case "above-allowlist":
                h.Classify(EgressDataClass.SensitiveContent);
                h.Permit(request, allowlistMax: EgressDataClass.WorkspaceContent, grantMax: EgressDataClass.SensitiveContent);
                expected = EgressReason.DataClassAboveAllowlist;
                break;
            case "ai-ineligible":
                h.Classify(EgressDataClass.WorkspaceContent, aiEligible: false);
                h.Permit(request, destinationClass: EgressDestinationClass.CloudAiProvider);
                expected = EgressReason.AiIneligibleContent;
                break;
            case "no-grant":
                h.Grants.Behavior = (_, _, _) => ValueTask.FromResult<IReadOnlyList<EgressGrantRecord>>([]);
                expected = EgressReason.NoGrant;
                break;
            case "grant-denied":
                h.Grants.Behavior = (_, _, _) => Grants(h.Grant(request, state: EgressGrantState.Denied));
                expected = EgressReason.GrantExplicitlyDenied;
                break;
            case "grant-denied-beats-granted":
                h.Grants.Behavior = (_, _, _) => Grants(h.Grant(request), h.Grant(request, state: EgressGrantState.Denied, issuer: "owner.deny"));
                expected = EgressReason.GrantExplicitlyDenied;
                break;
            case "grant-denied-expired":
                h.Grants.Behavior = (_, _, _) => Grants(
                    h.Grant(request, state: EgressGrantState.Denied, validFromOffset: TimeSpan.FromDays(-2), validUntilOffset: TimeSpan.FromDays(-1)));
                expected = EgressReason.GrantExplicitlyDenied;
                break;
            case "grant-other-principal":
                h.Grants.Behavior = (_, _, _) => Grants(h.Grant(request, principalKey: "principal:someone-else"));
                expected = EgressReason.GrantMismatch;
                break;
            case "grant-other-capability":
                h.Grants.Behavior = (_, _, _) => Grants(h.Grant(request, capabilityKey: "other.capability.send"));
                expected = EgressReason.GrantMismatch;
                break;
            case "grant-other-scope":
                h.Grants.Behavior = (_, _, _) => Grants(h.Grant(request, scopeKey: "realm:other/workspace:-"));
                expected = EgressReason.GrantMismatch;
                break;
            case "grant-other-destination":
                h.Grants.Behavior = (_, _, _) => Grants(h.Grant(request, "https://other.example.com"));
                expected = EgressReason.GrantMismatch;
                break;
            case "grant-not-yet-valid":
                h.Grants.Behavior = (_, _, _) => Grants(h.Grant(request, validFromOffset: TimeSpan.FromSeconds(1), validUntilOffset: TimeSpan.FromHours(1)));
                expected = EgressReason.GrantOutsideLifetime;
                break;
            case "grant-expired":
                h.Grants.Behavior = (_, _, _) => Grants(h.Grant(request, validFromOffset: TimeSpan.FromHours(-2), validUntilOffset: TimeSpan.FromSeconds(-1)));
                expected = EgressReason.GrantOutsideLifetime;
                break;
            case "grant-until-boundary":
                h.Grants.Behavior = (_, _, _) => Grants(h.Grant(request, validFromOffset: TimeSpan.FromHours(-1), validUntilOffset: TimeSpan.Zero));
                expected = EgressReason.GrantOutsideLifetime;
                break;
            case "grant-from-boundary":
                h.Grants.Behavior = (_, _, _) => Grants(h.Grant(request, validFromOffset: TimeSpan.Zero, validUntilOffset: TimeSpan.FromHours(1)));
                break;
            case "grant-above-class":
                h.Classify(EgressDataClass.SensitiveContent);
                h.Permit(request, allowlistMax: EgressDataClass.SensitiveContent, grantMax: EgressDataClass.WorkspaceContent);
                expected = EgressReason.DataClassAboveGrant;
                break;
            case "grant-expired-admits-more":
                h.Classify(EgressDataClass.SensitiveContent);
                h.Allowlist.Behavior = (_, _, _) => ValueTask.FromResult<EgressAllowlistEntry?>(
                    EgressHarness.Entry(request, max: EgressDataClass.SensitiveContent));
                h.Grants.Behavior = (_, _, _) => Grants(
                    h.Grant(request, max: EgressDataClass.WorkspaceContent),
                    h.Grant(request, max: EgressDataClass.SensitiveContent, validFromOffset: TimeSpan.FromHours(-2), validUntilOffset: TimeSpan.FromSeconds(-1), issuer: "owner.old"));
                expected = EgressReason.DataClassAboveGrant;
                break;
            default:
                throw new ArgumentOutOfRangeException(nameof(name), name, "Unknown scenario.");
        }

        return new EgressScenario(h, request, destination, expected);
    }

    internal static ValueTask<IReadOnlyList<EgressGrantRecord>> Grants(params EgressGrantRecord[] records) => ValueTask.FromResult<IReadOnlyList<EgressGrantRecord>>(records);
}

/// <summary>The egress authorization matrix: each refusal reason, the data-class tiers, the destination-class rules and the source failures.</summary>
public sealed class EgressDecisionTests
{
    public static TheoryData<string> ScenarioNames => EgressScenarios.Data;

    public static TheoryData<EgressDataClass, EgressDataClass, EgressDataClass> Tiers
    {
        get
        {
            var data = new TheoryData<EgressDataClass, EgressDataClass, EgressDataClass>();
            EgressDataClass[] classes = [EgressDataClass.Public, EgressDataClass.Diagnostic, EgressDataClass.WorkspaceContent, EgressDataClass.SensitiveContent];
            foreach (var content in classes)
            {
                foreach (var allowlist in classes)
                {
                    foreach (var grant in classes)
                    {
                        data.Add(content, allowlist, grant);
                    }
                }
            }

            return data;
        }
    }

    [Theory]
    [MemberData(nameof(ScenarioNames))]
    public async Task EveryScenarioGivesItsOwnReasonAndOnlyTheAllowedOnesAreReleased(string name)
    {
        var scenario = EgressScenarios.Build(name);

        var decision = await scenario.Harness.Authority().DecideAsync(scenario.Request, scenario.Destination, TestContext.Current.CancellationToken);

        Assert.Equal(scenario.Expected, decision.Reason);
        Assert.Equal(scenario.Expected == EgressReason.None, decision.Allowed);
        if (decision.Allowed)
        {
            Assert.Null(decision.ReasonCode);
            Assert.Null(decision.RegisteredCode);
            Assert.Equal(BoundaryVerdict.Allowed, decision.ToBoundaryVerdict());
            Assert.True(DecisionHarness.Value(decision.ToAuthorizationOutcome()));
        }
        else
        {
            var info = EgressReasons.Describe(scenario.Expected);
            Assert.Equal(info.Code, decision.ReasonCode);
            Assert.Equal(info.RegisteredCode, decision.RegisteredCode);
            Assert.Equal(BoundaryVerdict.Denied, decision.ToBoundaryVerdict());
            Assert.Equal("perm.egress_denied", DecisionHarness.FailureCode(decision.ToAuthorizationOutcome()));
        }
    }

    [Fact]
    public async Task AnAllowedDecisionNamesTheDestinationClassDataClassAndTheAuthorityItRestsOn()
    {
        var h = new EgressHarness();
        var request = h.Request();
        h.Permit(request, destinationClass: EgressDestinationClass.Connector);
        h.Grants.Behavior = (_, _, _) => EgressScenarios.Grants(h.Grant(request, authority: EgressAuthorityKind.WorkspacePolicy, reference: "policy-7"));

        var decision = await h.Authority().DecideAsync(request, EgressHarness.Destination, TestContext.Current.CancellationToken);

        Assert.True(decision.Allowed);
        Assert.Equal("https://api.example.com", decision.Destination!.Origin);
        Assert.Equal(EgressDestinationClass.Connector, decision.DestinationClass);
        Assert.Equal(EgressDataClass.WorkspaceContent, decision.DataClass);
        Assert.Equal(EgressAuthorityKind.WorkspacePolicy, decision.Authority);
        Assert.Equal("policy-7", decision.AuthorityReference);
        Assert.Same(decision.Audit, Assert.Single(h.Audit.Records));
    }

    [Theory]
    [MemberData(nameof(Tiers))]
    public async Task ADataClassPassesOnlyWhenBothTheAllowlistAndTheGrantAdmitItOrAboveItsOwnLimit(
        EgressDataClass content,
        EgressDataClass allowlistMax,
        EgressDataClass grantMax)
    {
        var h = new EgressHarness();
        var request = h.Request();
        h.Classify(content);
        h.Permit(request, allowlistMax: allowlistMax, grantMax: grantMax);

        var decision = await h.Authority().DecideAsync(request, EgressHarness.Destination, TestContext.Current.CancellationToken);

        var expected = content > allowlistMax ? EgressReason.DataClassAboveAllowlist
            : content > grantMax ? EgressReason.DataClassAboveGrant
            : EgressReason.None;
        Assert.Equal(expected, decision.Reason);
    }

    [Theory]
    [InlineData(EgressDestinationClass.CloudAiProvider, true, EgressReason.None)]
    [InlineData(EgressDestinationClass.CloudAiProvider, false, EgressReason.AiIneligibleContent)]
    [InlineData(EgressDestinationClass.Connector, false, EgressReason.None)]
    [InlineData(EgressDestinationClass.ThirdParty, false, EgressReason.None)]
    [InlineData(EgressDestinationClass.Public, false, EgressReason.None)]
    public async Task OnlyACloudAiProviderDemandsAiEligibleContentAndTheEntryNotTheCallerNamesTheClass(
        EgressDestinationClass destinationClass,
        bool aiEligible,
        EgressReason expected)
    {
        var h = new EgressHarness();
        var request = h.Request();
        h.Classify(EgressDataClass.WorkspaceContent, aiEligible);
        h.Permit(request, destinationClass: destinationClass);

        var decision = await h.Authority().DecideAsync(request, EgressHarness.Destination, TestContext.Current.CancellationToken);

        Assert.Equal(expected, decision.Reason);
        if (expected == EgressReason.None)
        {
            Assert.Equal(destinationClass, decision.DestinationClass);
        }
    }

    [Fact]
    public async Task AMismatchedRecordNextToAValidGrantIsIgnoredNotAReasonToRefuse()
    {
        var h = new EgressHarness();
        var request = h.Request();
        h.Permit(request);
        h.Grants.Behavior = (_, _, _) => EgressScenarios.Grants(
            h.Grant(request, principalKey: "principal:someone-else", authority: EgressAuthorityKind.ProductRoute, reference: "route-9"),
            h.Grant(request, reference: "consent-ok"));

        var decision = await h.Authority().DecideAsync(request, EgressHarness.Destination, TestContext.Current.CancellationToken);

        Assert.True(decision.Allowed);
        Assert.Equal("consent-ok", decision.AuthorityReference);
        Assert.Equal(EgressAuthorityKind.UserConsent, decision.Authority);
    }

    [Fact]
    public async Task TheAdmittingGrantWithTheLatestEndWinsAndTiesBreakOnTheIssuer()
    {
        var h = new EgressHarness();
        var request = h.Request();
        h.Permit(request);
        h.Grants.Behavior = (_, _, _) => EgressScenarios.Grants(
            h.Grant(request, authority: EgressAuthorityKind.UserConsent, reference: "short", validUntilOffset: TimeSpan.FromHours(1), issuer: "a"),
            h.Grant(request, authority: EgressAuthorityKind.WorkspacePolicy, reference: "long", validUntilOffset: TimeSpan.FromHours(2), issuer: "b"));
        var authority = h.Authority();

        var longest = await authority.DecideAsync(request, EgressHarness.Destination, TestContext.Current.CancellationToken);

        Assert.Equal("long", longest.AuthorityReference);

        h.Grants.Behavior = (_, _, _) => EgressScenarios.Grants(
            h.Grant(request, reference: "from-z", validUntilOffset: TimeSpan.FromHours(1), issuer: "z"),
            h.Grant(request, reference: "from-a", validUntilOffset: TimeSpan.FromHours(1), issuer: "a"));

        var tie = await authority.DecideAsync(request, EgressHarness.Destination, TestContext.Current.CancellationToken);

        Assert.Equal("from-a", tie.AuthorityReference);
    }

    [Fact]
    public async Task OnlyAGrantThatAdmitsTheContentClassCanBeTheAuthority()
    {
        var h = new EgressHarness();
        var request = h.Request();
        h.Classify(EgressDataClass.SensitiveContent);
        h.Allowlist.Behavior = (_, _, _) => ValueTask.FromResult<EgressAllowlistEntry?>(EgressHarness.Entry(request, max: EgressDataClass.SensitiveContent));
        h.Grants.Behavior = (_, _, _) => EgressScenarios.Grants(
            h.Grant(request, max: EgressDataClass.WorkspaceContent, reference: "too-low", validUntilOffset: TimeSpan.FromHours(5)),
            h.Grant(request, max: EgressDataClass.SensitiveContent, reference: "enough", validUntilOffset: TimeSpan.FromHours(1)));

        var decision = await h.Authority().DecideAsync(request, EgressHarness.Destination, TestContext.Current.CancellationToken);

        Assert.True(decision.Allowed);
        Assert.Equal("enough", decision.AuthorityReference);
    }

    [Fact]
    public async Task AGrantIsJudgedAtTheInstantAfterTheSourceAnswered()
    {
        var h = new EgressHarness();
        var request = h.Request();
        h.Permit(request);
        h.Grants.Behavior = (_, _, _) =>
        {
            var grant = h.Grant(request, validUntilOffset: TimeSpan.FromMinutes(1));
            h.Decisions.Clock.Advance(TimeSpan.FromMinutes(5));
            return EgressScenarios.Grants(grant);
        };

        var decision = await h.Authority().DecideAsync(request, EgressHarness.Destination, TestContext.Current.CancellationToken);

        Assert.Equal(EgressReason.GrantOutsideLifetime, decision.Reason);
    }

    [Fact]
    public async Task TheDecisionIsStampedWithTheClockInstantAndIsRepeatedEveryTime()
    {
        var h = new EgressHarness();
        var request = h.Request();
        h.Permit(request);
        var authority = h.Authority();

        var first = await authority.DecideAsync(request, EgressHarness.Destination, TestContext.Current.CancellationToken);
        h.Decisions.Clock.Advance(TimeSpan.FromHours(2));
        var second = await authority.DecideAsync(request, EgressHarness.Destination, TestContext.Current.CancellationToken);

        Assert.True(first.Allowed);
        Assert.Equal(EgressReason.GrantOutsideLifetime, second.Reason);
        Assert.Equal(DecisionHarness.InstantOf(h.Now), second.Audit.OccurredAt);
        Assert.True(first.Audit.OccurredAt < second.Audit.OccurredAt);
        Assert.Equal(2, h.Log.Count("egress-grants"));
    }

    [Fact]
    public async Task SourcesAreAskedInOrderAndALaterOneIsNeverAskedAfterARefusal()
    {
        var secret = new EgressHarness();
        var secretRequest = secret.Request();
        secret.Classify(EgressDataClass.SecretMaterial).Permit(secretRequest);
        await secret.Authority().DecideAsync(secretRequest, EgressHarness.Destination, TestContext.Current.CancellationToken);
        Assert.Equal(["egress-classify", "egress-audit"], secret.Log.Entries);

        var listed = new EgressHarness();
        var listedRequest = listed.Request();
        await listed.Authority().DecideAsync(listedRequest, EgressHarness.Destination, TestContext.Current.CancellationToken);
        Assert.Equal(["egress-classify", "egress-allowlist", "egress-audit"], listed.Log.Entries);

        var granted = new EgressHarness();
        var grantedRequest = granted.Request();
        granted.Permit(grantedRequest);
        await granted.Authority().DecideAsync(grantedRequest, EgressHarness.Destination, TestContext.Current.CancellationToken);
        Assert.Equal(["egress-classify", "egress-allowlist", "egress-grants", "egress-audit"], granted.Log.Entries);

        var malformed = new EgressHarness();
        await malformed.Authority().DecideAsync(malformed.Request(), "not a destination", TestContext.Current.CancellationToken);
        Assert.Equal(["egress-audit"], malformed.Log.Entries);
    }

    [Fact]
    public async Task ARefusedMalformedDestinationIsAuditedWithoutEchoingTheText()
    {
        var h = new EgressHarness();
        var request = h.Request();

        var decision = await h.Authority().DecideAsync(request, "http://user:pw@evil.example/secret-token", TestContext.Current.CancellationToken);

        Assert.Equal(EgressReason.DestinationMalformed, decision.Reason);
        var audit = Assert.Single(h.Audit.Records);
        Assert.Null(audit.Destination);
        Assert.Equal(EgressDestinationClass.None, audit.DestinationClass);
        Assert.DoesNotContain("evil", audit.ToString(), StringComparison.Ordinal);
        Assert.DoesNotContain("secret-token", audit.ToString(), StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("classifier", "throws-synchronously", EgressReason.ClassifierUnavailable)]
    [InlineData("classifier", "faults-asynchronously", EgressReason.ClassifierUnavailable)]
    [InlineData("classifier", "honours-the-timeout", EgressReason.ClassifierUnavailable)]
    [InlineData("classifier", "ignores-the-token", EgressReason.ClassifierUnavailable)]
    [InlineData("allowlist", "throws-synchronously", EgressReason.AllowlistUnavailable)]
    [InlineData("allowlist", "faults-asynchronously", EgressReason.AllowlistUnavailable)]
    [InlineData("allowlist", "honours-the-timeout", EgressReason.AllowlistUnavailable)]
    [InlineData("allowlist", "ignores-the-token", EgressReason.AllowlistUnavailable)]
    [InlineData("grants", "throws-synchronously", EgressReason.GrantSourceUnavailable)]
    [InlineData("grants", "faults-asynchronously", EgressReason.GrantSourceUnavailable)]
    [InlineData("grants", "honours-the-timeout", EgressReason.GrantSourceUnavailable)]
    [InlineData("grants", "ignores-the-token", EgressReason.GrantSourceUnavailable)]
    public async Task ASourceThatCannotAnswerRefusesWithAnUnavailableReasonAndAnUnknownVerdict(string component, string failure, EgressReason expected)
    {
        var h = new EgressHarness();
        var request = h.Request();
        h.Permit(request);
        switch (component)
        {
            case "classifier":
                h.Classifier.Behavior = (_, _, token) => Failing<EgressContentFacts?>(failure, token);
                break;
            case "allowlist":
                h.Allowlist.Behavior = (_, _, token) => Failing<EgressAllowlistEntry?>(failure, token);
                break;
            default:
                h.Grants.Behavior = (_, _, token) => Failing<IReadOnlyList<EgressGrantRecord>>(failure, token);
                break;
        }

        var decision = await h.Authority(new EgressAuthorityOptions { StepTimeout = TimeSpan.FromMilliseconds(150) })
            .DecideAsync(request, EgressHarness.Destination, TestContext.Current.CancellationToken);

        Assert.Equal(expected, decision.Reason);
        Assert.Equal(BoundaryVerdict.Unknown, decision.ToBoundaryVerdict());
        Assert.Equal("resource.unavailable", DecisionHarness.FailureCode(decision.ToAuthorizationOutcome()));
        var audit = Assert.Single(h.Audit.Records);
        Assert.Equal(EgressAuditKind.Refused, audit.Kind);
        Assert.Equal(expected, audit.Reason);
    }

    [Fact]
    public async Task AGrantSourceThatReturnsNothingTooManyOrANullRecordIsTreatedAsFailing()
    {
        var h = new EgressHarness();
        var request = h.Request();
        h.Permit(request);
        var authority = h.Authority();
        var other = h.Grant(request, principalKey: "principal:someone-else");

        h.Grants.Behavior = (_, _, _) => ValueTask.FromResult<IReadOnlyList<EgressGrantRecord>>(null!);
        Assert.Equal(EgressReason.GrantSourceUnavailable, (await authority.DecideAsync(request, EgressHarness.Destination, TestContext.Current.CancellationToken)).Reason);

        h.Grants.Behavior = (_, _, _) => ValueTask.FromResult<IReadOnlyList<EgressGrantRecord>>([h.Grant(request), null!]);
        Assert.Equal(EgressReason.GrantSourceUnavailable, (await authority.DecideAsync(request, EgressHarness.Destination, TestContext.Current.CancellationToken)).Reason);

        h.Grants.Behavior = (_, _, _) => ValueTask.FromResult<IReadOnlyList<EgressGrantRecord>>(Enumerable.Repeat(other, EgressAuthority.MaximumGrantRecords + 1).ToArray());
        Assert.Equal(EgressReason.GrantSourceUnavailable, (await authority.DecideAsync(request, EgressHarness.Destination, TestContext.Current.CancellationToken)).Reason);

        h.Grants.Behavior = (_, _, _) => ValueTask.FromResult<IReadOnlyList<EgressGrantRecord>>(Enumerable.Repeat(other, EgressAuthority.MaximumGrantRecords).ToArray());
        Assert.Equal(EgressReason.GrantMismatch, (await authority.DecideAsync(request, EgressHarness.Destination, TestContext.Current.CancellationToken)).Reason);
    }

    private sealed class LiveGrantList(EgressGrantRecord grant) : IReadOnlyList<EgressGrantRecord>
    {
        private int _reads;

        internal int Reads => Volatile.Read(ref _reads);

        public int Count => Reads == 0 ? 1 : 0;

        public EgressGrantRecord this[int index] => Reads == 0 ? grant : throw new ArgumentOutOfRangeException(nameof(index));

        public IEnumerator<EgressGrantRecord> GetEnumerator()
        {
            // Only the first read sees the grant; any later read (Count, indexer or another pass) sees an emptied list.
            if (Interlocked.Increment(ref _reads) == 1)
            {
                yield return grant;
            }
        }

        System.Collections.IEnumerator System.Collections.IEnumerable.GetEnumerator() => GetEnumerator();
    }

    [Fact]
    public async Task ALiveGrantListIsCopiedOnceSoItCannotChangeBetweenTheChecks()
    {
        var h = new EgressHarness();
        var request = h.Request();
        h.Permit(request);
        var live = new LiveGrantList(h.Grant(request));
        h.Grants.Behavior = (_, _, _) => ValueTask.FromResult<IReadOnlyList<EgressGrantRecord>>(live);

        var decision = await h.Authority().DecideAsync(request, EgressHarness.Destination, TestContext.Current.CancellationToken);

        Assert.True(decision.Allowed);
        Assert.Equal(1, live.Reads);
    }

    [Fact]
    public async Task AGrantListThatThrowsWhileItIsReadIsAFailingSource()
    {
        var h = new EgressHarness();
        var request = h.Request();
        h.Permit(request);
        h.Grants.Behavior = (_, _, _) => ValueTask.FromResult<IReadOnlyList<EgressGrantRecord>>(new ThrowingGrantList());

        var decision = await h.Authority().DecideAsync(request, EgressHarness.Destination, TestContext.Current.CancellationToken);

        Assert.Equal(EgressReason.GrantSourceUnavailable, decision.Reason);
    }

    private sealed class ThrowingGrantList : IReadOnlyList<EgressGrantRecord>
    {
        public int Count => 1;

        public EgressGrantRecord this[int index] => throw new InvalidOperationException("list failed");

        public IEnumerator<EgressGrantRecord> GetEnumerator() => throw new InvalidOperationException("list failed");

        System.Collections.IEnumerator System.Collections.IEnumerable.GetEnumerator() => GetEnumerator();
    }

    [Fact]
    public async Task OnlyTheCallersOwnCancellationPropagates()
    {
        var h = new EgressHarness();
        var request = h.Request();
        h.Permit(request);
        using var cancel = new CancellationTokenSource();
        h.Classifier.Behavior = async (_, _, token) =>
        {
            await cancel.CancelAsync();
            await Task.Delay(Timeout.Infinite, token);
            return null;
        };

        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () =>
            await h.Authority().DecideAsync(request, EgressHarness.Destination, cancel.Token));

        Assert.Empty(h.Audit.Records);

        using var already = new CancellationTokenSource();
        await already.CancelAsync();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () =>
            await h.Authority().DecideAsync(request, EgressHarness.Destination, already.Token));
        Assert.Empty(h.Audit.Records);
    }

    [Fact]
    public void TheAuthorityRejectsMissingDependenciesAndUnboundedTimeouts()
    {
        var h = new EgressHarness();
        var clock = h.Decisions.Clock.Clock;
        Assert.Throws<ArgumentNullException>(() => new EgressAuthority(null!, h.Classifier, h.Allowlist, h.Grants, h.Audit));
        Assert.Throws<ArgumentNullException>(() => new EgressAuthority(clock, null!, h.Allowlist, h.Grants, h.Audit));
        Assert.Throws<ArgumentNullException>(() => new EgressAuthority(clock, h.Classifier, null!, h.Grants, h.Audit));
        Assert.Throws<ArgumentNullException>(() => new EgressAuthority(clock, h.Classifier, h.Allowlist, null!, h.Audit));
        Assert.Throws<ArgumentNullException>(() => new EgressAuthority(clock, h.Classifier, h.Allowlist, h.Grants, null!));
        Assert.Throws<ArgumentOutOfRangeException>(() => h.Authority(new EgressAuthorityOptions { StepTimeout = TimeSpan.Zero }));
        Assert.Throws<ArgumentOutOfRangeException>(() => h.Authority(new EgressAuthorityOptions { StepTimeout = TimeSpan.FromMinutes(5) + TimeSpan.FromTicks(1) }));
        _ = h.Authority(new EgressAuthorityOptions { StepTimeout = TimeSpan.FromMinutes(5) });
        _ = h.Authority(new EgressAuthorityOptions { StepTimeout = TimeSpan.FromTicks(1) });
    }

    private static ValueTask<T> Failing<T>(string failure, CancellationToken token) => failure switch
    {
        "throws-synchronously" => throw new InvalidOperationException("source failed"),
        "faults-asynchronously" => FaultAsync<T>(),
        "honours-the-timeout" => HonourAsync<T>(token),
        "ignores-the-token" => IgnoreAsync<T>(),
        _ => throw new ArgumentOutOfRangeException(nameof(failure)),
    };

    private static async ValueTask<T> FaultAsync<T>()
    {
        await Task.Yield();
        throw new InvalidOperationException("source faulted");
    }

    private static async ValueTask<T> HonourAsync<T>(CancellationToken token)
    {
        await Task.Delay(Timeout.Infinite, token);
        return default!;
    }

    private static async ValueTask<T> IgnoreAsync<T>()
    {
        await Task.Delay(TimeSpan.FromSeconds(30), CancellationToken.None);
        return default!;
    }
}
