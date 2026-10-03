// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics.CodeAnalysis;
using System.Reflection;
using ArcForges.Foundation.Errors;
using ArcForges.Security.Decisions;
using ArcForges.Security.Leases;
using ArcForges.Security.Trust;
using Xunit;

namespace ArcForges.Security.Tests;

/// <summary>The trust facts a test controls, and a record of exactly which kinds were read for which subject.</summary>
internal sealed class FakeTrustFacts : ITrustFactSource
{
    private readonly List<TrustKind> _reads = [];

    internal IReadOnlyList<TrustKind> Reads => _reads;

    internal TrustSubject? LastSubject { get; private set; }

    internal PublisherTrustState Publisher { get; set; } = PublisherTrustState.Verified;

    internal PackageTrustState Package { get; set; } = PackageTrustState.SignatureVerified;

    internal SoftwareIdentityState Software { get; set; } = SoftwareIdentityState.Matched;

    internal DeviceTrustState Device { get; set; } = DeviceTrustState.Trusted;

    internal ExtensionTrustState Extension { get; set; } = ExtensionTrustState.Enabled;

    internal bool Throw { get; set; }

    public ValueTask<PublisherTrustState> ReadPublisherAsync(TrustSubject subject, CancellationToken cancellationToken) =>
        Read(TrustKind.Publisher, subject, Publisher);

    public ValueTask<PackageTrustState> ReadPackageAsync(TrustSubject subject, CancellationToken cancellationToken) =>
        Read(TrustKind.Package, subject, Package);

    public ValueTask<SoftwareIdentityState> ReadSoftwareIdentityAsync(TrustSubject subject, CancellationToken cancellationToken) =>
        Read(TrustKind.SoftwareIdentity, subject, Software);

    public ValueTask<DeviceTrustState> ReadDeviceAsync(TrustSubject subject, CancellationToken cancellationToken) =>
        Read(TrustKind.Device, subject, Device);

    public ValueTask<ExtensionTrustState> ReadExtensionStateAsync(TrustSubject subject, CancellationToken cancellationToken) =>
        Read(TrustKind.ExtensionState, subject, Extension);

    private ValueTask<T> Read<T>(TrustKind kind, TrustSubject subject, T state)
    {
        _reads.Add(kind);
        LastSubject = subject;
        return Throw ? throw new InvalidOperationException("trust registry offline") : ValueTask.FromResult(state);
    }
}

public sealed class TrustTests
{
    private static CancellationToken Token => TestContext.Current.CancellationToken;

    private static readonly (TrustEvaluationPoint Point, TrustKind[] Kinds)[] Table =
    [
        (TrustEvaluationPoint.PackageInstallOrUpdate, [TrustKind.Publisher, TrustKind.Package]),
        (TrustEvaluationPoint.ExtensionHostStart, [TrustKind.Package]),
        (TrustEvaluationPoint.LocalRpcHandshake, [TrustKind.SoftwareIdentity]),
        (TrustEvaluationPoint.ExtensionHostHandshake, [TrustKind.SoftwareIdentity]),
        (TrustEvaluationPoint.CloudAuthentication, [TrustKind.Device]),
        (TrustEvaluationPoint.RemoteInvocation, [TrustKind.Device]),
        (TrustEvaluationPoint.ExtensionInvocation, [TrustKind.ExtensionState]),
    ];

    public static TheoryData<TrustEvaluationPoint> Points => [.. Table.Select(entry => entry.Point)];

    [Theory]
    [MemberData(nameof(Points))]
    public async Task EachPointEvaluatesExactlyItsOwnKindsOnceAndNoOthers(TrustEvaluationPoint point)
    {
        var expected = Table.Single(entry => entry.Point == point).Kinds;
        var facts = new FakeTrustFacts();
        var subject = Subject(DecisionOrigin.Local, null);

        var assessment = await new TrustEvaluator(facts).AssessAsync(point, subject, Token);

        Assert.Equal(expected, TrustPoints.KindsAt(point));
        Assert.Equal(expected, facts.Reads);
        Assert.Equal(point, assessment.Point);
        Assert.Equal(expected.Contains(TrustKind.Publisher), assessment.Publisher is not null);
        Assert.Equal(expected.Contains(TrustKind.Package), assessment.Package is not null);
        Assert.Equal(expected.Contains(TrustKind.SoftwareIdentity), assessment.Software is not null);
        Assert.Equal(expected.Contains(TrustKind.Device), assessment.Device is not null);
        Assert.Equal(expected.Contains(TrustKind.ExtensionState), assessment.Extension is not null);
        Assert.Equal(TrustEligibility.Eligible, assessment.Eligibility);
        Assert.Same(subject, facts.LastSubject);
    }

    [Fact]
    public void ThePointTableCoversEveryDefinedPointAndRefusesTheUndefined()
    {
        Assert.Equal(
            Enum.GetValues<TrustEvaluationPoint>().Where(point => point != TrustEvaluationPoint.None).OrderBy(point => (int)point),
            Table.Select(entry => entry.Point).OrderBy(point => (int)point));
        _ = Assert.Throws<ArgumentOutOfRangeException>(() => TrustPoints.KindsAt(TrustEvaluationPoint.None));
        _ = Assert.Throws<ArgumentOutOfRangeException>(() => TrustPoints.KindsAt((TrustEvaluationPoint)99));
        Assert.All(Enum.GetValues<TrustKind>().Where(kind => kind != TrustKind.None), kind => Assert.Contains(Table, entry => entry.Kinds.Contains(kind)));
    }

    [Theory]
    [InlineData(PublisherTrustState.Verified, TrustEligibility.Eligible)]
    [InlineData(PublisherTrustState.Unverified, TrustEligibility.EligibleUnverified)]
    [InlineData(PublisherTrustState.Revoked, TrustEligibility.NotEligible)]
    [InlineData(PublisherTrustState.Unknown, TrustEligibility.Unknown)]
    [InlineData((PublisherTrustState)77, TrustEligibility.Unknown)]
    public async Task EachPublisherStateHasItsOwnEligibility(PublisherTrustState state, TrustEligibility expected)
    {
        var assessment = await AssessAsync(TrustEvaluationPoint.PackageInstallOrUpdate, new FakeTrustFacts { Publisher = state });

        Assert.Equal(state, assessment.Publisher);
        Assert.Equal(expected, assessment.Eligibility);
    }

    [Theory]
    [InlineData(PackageTrustState.SignatureVerified, TrustEligibility.Eligible)]
    [InlineData(PackageTrustState.Unverified, TrustEligibility.EligibleUnverified)]
    [InlineData(PackageTrustState.Revoked, TrustEligibility.NotEligible)]
    [InlineData(PackageTrustState.Unknown, TrustEligibility.Unknown)]
    [InlineData((PackageTrustState)77, TrustEligibility.Unknown)]
    public async Task EachPackageStateHasItsOwnEligibility(PackageTrustState state, TrustEligibility expected)
    {
        var assessment = await AssessAsync(TrustEvaluationPoint.ExtensionHostStart, new FakeTrustFacts { Package = state });

        Assert.Equal(state, assessment.Package);
        Assert.Equal(expected, assessment.Eligibility);
    }

    [Theory]
    [InlineData(SoftwareIdentityState.Matched, TrustEligibility.Eligible)]
    [InlineData(SoftwareIdentityState.Mismatched, TrustEligibility.NotEligible)]
    [InlineData(SoftwareIdentityState.Unknown, TrustEligibility.Unknown)]
    [InlineData((SoftwareIdentityState)77, TrustEligibility.Unknown)]
    public async Task EachSoftwareIdentityStateHasItsOwnEligibility(SoftwareIdentityState state, TrustEligibility expected)
    {
        var assessment = await AssessAsync(TrustEvaluationPoint.LocalRpcHandshake, new FakeTrustFacts { Software = state });

        Assert.Equal(state, assessment.Software);
        Assert.Equal(expected, assessment.Eligibility);
    }

    [Theory]
    [InlineData(DeviceTrustState.Trusted, TrustEligibility.Eligible)]
    [InlineData(DeviceTrustState.Untrusted, TrustEligibility.NotEligible)]
    [InlineData(DeviceTrustState.Revoked, TrustEligibility.NotEligible)]
    [InlineData(DeviceTrustState.Unknown, TrustEligibility.Unknown)]
    [InlineData((DeviceTrustState)77, TrustEligibility.Unknown)]
    public async Task EachDeviceStateHasItsOwnEligibility(DeviceTrustState state, TrustEligibility expected)
    {
        var assessment = await AssessAsync(TrustEvaluationPoint.RemoteInvocation, new FakeTrustFacts { Device = state });

        Assert.Equal(state, assessment.Device);
        Assert.Equal(expected, assessment.Eligibility);
    }

    [Theory]
    [InlineData(ExtensionTrustState.Enabled, TrustEligibility.Eligible)]
    [InlineData(ExtensionTrustState.Developer, TrustEligibility.EligibleUnverified)]
    [InlineData(ExtensionTrustState.Unverified, TrustEligibility.EligibleUnverified)]
    [InlineData(ExtensionTrustState.Installed, TrustEligibility.NotEligible)]
    [InlineData(ExtensionTrustState.Revoked, TrustEligibility.NotEligible)]
    [InlineData(ExtensionTrustState.Unknown, TrustEligibility.Unknown)]
    [InlineData((ExtensionTrustState)77, TrustEligibility.Unknown)]
    public async Task EachExtensionStateHasItsOwnEligibility(ExtensionTrustState state, TrustEligibility expected)
    {
        var assessment = await AssessAsync(TrustEvaluationPoint.ExtensionInvocation, new FakeTrustFacts { Extension = state });

        Assert.Equal(state, assessment.Extension);
        Assert.Equal(expected, assessment.Eligibility);
    }

    [Theory]
    [InlineData(PublisherTrustState.Verified, PackageTrustState.SignatureVerified, TrustEligibility.Eligible)]
    [InlineData(PublisherTrustState.Verified, PackageTrustState.Unverified, TrustEligibility.EligibleUnverified)]
    [InlineData(PublisherTrustState.Unverified, PackageTrustState.SignatureVerified, TrustEligibility.EligibleUnverified)]
    [InlineData(PublisherTrustState.Unverified, PackageTrustState.Unverified, TrustEligibility.EligibleUnverified)]
    [InlineData(PublisherTrustState.Revoked, PackageTrustState.SignatureVerified, TrustEligibility.NotEligible)]
    [InlineData(PublisherTrustState.Verified, PackageTrustState.Revoked, TrustEligibility.NotEligible)]
    [InlineData(PublisherTrustState.Unknown, PackageTrustState.SignatureVerified, TrustEligibility.Unknown)]
    [InlineData(PublisherTrustState.Verified, PackageTrustState.Unknown, TrustEligibility.Unknown)]
    [InlineData(PublisherTrustState.Unknown, PackageTrustState.Revoked, TrustEligibility.NotEligible)]
    [InlineData(PublisherTrustState.Revoked, PackageTrustState.Unknown, TrustEligibility.NotEligible)]
    [InlineData(PublisherTrustState.Unverified, PackageTrustState.Unknown, TrustEligibility.Unknown)]
    [InlineData((PublisherTrustState)90, PackageTrustState.SignatureVerified, TrustEligibility.Unknown)]
    public async Task CombinedEligibilityIsTheStrictestOfTheEvaluatedKinds(PublisherTrustState publisher, PackageTrustState package, TrustEligibility expected)
    {
        var assessment = await AssessAsync(TrustEvaluationPoint.PackageInstallOrUpdate, new FakeTrustFacts { Publisher = publisher, Package = package });

        Assert.Equal(expected, assessment.Eligibility);
    }

    [Fact]
    public async Task AVerifiedPublisherAndAVerifiedSignatureAreNotAClaimOfSafety()
    {
        // TR-02 and TR-03: the best publisher and package states are only "eligible"; the type has no member that says "safe" or "granted".
        var assessment = await AssessAsync(TrustEvaluationPoint.PackageInstallOrUpdate, new FakeTrustFacts());

        Assert.Equal(TrustEligibility.Eligible, assessment.Eligibility);
        var members = typeof(TrustAssessment).GetProperties(BindingFlags.Public | BindingFlags.Instance).Select(property => property.Name).Order().ToArray();
        Assert.Equal(["Device", "Eligibility", "Extension", "Package", "Point", "Publisher", "Software"], members);
    }

    [Fact]
    [UnconditionalSuppressMessage("Trimming", "IL2026", Justification = "This offline test inspects the assembly's own public surface by reflection and is never trimmed.")]
    [UnconditionalSuppressMessage("Trimming", "IL2075", Justification = "This offline test inspects the assembly's own public surface by reflection and is never trimmed.")]
    public void TrustIsTypedNotAScalarAndNamesNoPermissionLeaseOrGrant()
    {
        var types = typeof(TrustAssessment).Assembly.GetExportedTypes().Where(type => type.Namespace == "ArcForges.Security.Trust").ToArray();
        Assert.NotEmpty(types);
        var forbidden = new[] { typeof(PermissionGrantRecord), typeof(CapabilityLease), typeof(CapabilityLeaseId), typeof(LeaseUse), typeof(PermissionAvailabilityEvidence), typeof(SecurityDecision) };
        foreach (var type in types.Where(type => !type.IsEnum))
        {
            foreach (var member in type.GetMembers(BindingFlags.Public | BindingFlags.Instance | BindingFlags.Static | BindingFlags.DeclaredOnly))
            {
                var exposed = member switch
                {
                    PropertyInfo property => [property.PropertyType],
                    MethodInfo method => method.GetParameters().Select(parameter => parameter.ParameterType).Append(method.ReturnType).ToArray(),
                    ConstructorInfo constructor => constructor.GetParameters().Select(parameter => parameter.ParameterType).ToArray(),
                    FieldInfo field => [field.FieldType],
                    _ => [],
                };
                foreach (var candidate in exposed.SelectMany(Flatten))
                {
                    Assert.DoesNotContain(candidate, forbidden);
                    // No scalar trust level: no public numeric property or field in the namespace.
                    Assert.False(candidate == typeof(int) && member is PropertyInfo or FieldInfo, $"{type.Name}.{member.Name} is a numeric trust level");
                    Assert.False(candidate == typeof(double) && member is PropertyInfo or FieldInfo, $"{type.Name}.{member.Name} is a numeric trust level");
                }
            }
        }

        Assert.DoesNotContain(types, type => type.Name.Contains("TrustLevel", StringComparison.Ordinal));
    }

    [Fact]
    public async Task ARequestOfALocalPersonReadsOnlyTheCallersSoftwareIdentity()
    {
        var facts = new FakeTrustFacts();
        var request = Request(new DecisionHarness(), ActorKind.None);

        var verdict = await new TrustEvaluator(facts).EvaluateAsync(request, null, Token);

        Assert.Equal(TrustVerdict.Verified, verdict);
        Assert.Equal([TrustKind.SoftwareIdentity], facts.Reads);
        Assert.Null(facts.LastSubject!.Actor);
        Assert.Equal(request.Actors.Device, facts.LastSubject.Device);
        Assert.Equal(request.Actors.Installation, facts.LastSubject.Installation);
        Assert.Equal(request.Actors.CallerInstance, facts.LastSubject.CallerInstance);
        Assert.Equal(DecisionOrigin.Local, facts.LastSubject.Origin);
    }

    [Theory]
    [InlineData(SoftwareIdentityState.Matched, TrustVerdict.Verified)]
    [InlineData(SoftwareIdentityState.Mismatched, TrustVerdict.Revoked)]
    [InlineData(SoftwareIdentityState.Unknown, TrustVerdict.Unknown)]
    public async Task TheCallersSoftwareIdentityDecidesAnOrdinaryRequest(SoftwareIdentityState state, TrustVerdict expected)
    {
        var verdict = await new TrustEvaluator(new FakeTrustFacts { Software = state }).EvaluateAsync(Request(new DecisionHarness(), ActorKind.None), null, Token);

        Assert.Equal(expected, verdict);
    }

    [Fact]
    public async Task AnAgentIsEvaluatedByItsCallerAndNeverByPackageOrExtensionState()
    {
        var facts = new FakeTrustFacts { Package = PackageTrustState.Revoked, Extension = ExtensionTrustState.Revoked };
        var request = Request(new DecisionHarness(), ActorKind.Agent);

        var verdict = await new TrustEvaluator(facts).EvaluateAsync(request, null, Token);

        Assert.Equal(TrustVerdict.Verified, verdict);
        Assert.Equal([TrustKind.SoftwareIdentity], facts.Reads);
        Assert.Equal(request.Actors.Actors[0], facts.LastSubject!.Actor);
    }

    [Fact]
    public async Task AnExtensionIsEvaluatedAtHostStartAndAtEveryInvocationAsWellAsByItsCaller()
    {
        var facts = new FakeTrustFacts();
        var request = Request(new DecisionHarness(), ActorKind.Extension);

        var verdict = await new TrustEvaluator(facts).EvaluateAsync(request, null, Token);

        Assert.Equal(TrustVerdict.Verified, verdict);
        Assert.Equal([TrustKind.SoftwareIdentity, TrustKind.Package, TrustKind.ExtensionState], facts.Reads);
        Assert.Equal(request.Actors.Actors[^1], facts.LastSubject!.Actor);
    }

    [Theory]
    [InlineData(ExtensionTrustState.Enabled, PackageTrustState.SignatureVerified, TrustVerdict.Verified)]
    [InlineData(ExtensionTrustState.Developer, PackageTrustState.SignatureVerified, TrustVerdict.Unverified)]
    [InlineData(ExtensionTrustState.Unverified, PackageTrustState.SignatureVerified, TrustVerdict.Unverified)]
    [InlineData(ExtensionTrustState.Enabled, PackageTrustState.Unverified, TrustVerdict.Unverified)]
    [InlineData(ExtensionTrustState.Installed, PackageTrustState.SignatureVerified, TrustVerdict.Revoked)]
    [InlineData(ExtensionTrustState.Revoked, PackageTrustState.SignatureVerified, TrustVerdict.Revoked)]
    [InlineData(ExtensionTrustState.Enabled, PackageTrustState.Revoked, TrustVerdict.Revoked)]
    [InlineData(ExtensionTrustState.Developer, PackageTrustState.Revoked, TrustVerdict.Revoked)]
    [InlineData(ExtensionTrustState.Unknown, PackageTrustState.SignatureVerified, TrustVerdict.Unknown)]
    [InlineData(ExtensionTrustState.Enabled, PackageTrustState.Unknown, TrustVerdict.Unknown)]
    [InlineData(ExtensionTrustState.Unverified, PackageTrustState.Unknown, TrustVerdict.Unknown)]
    [InlineData(ExtensionTrustState.Unknown, PackageTrustState.Revoked, TrustVerdict.Revoked)]
    public async Task AnExtensionRequestIsAsEligibleAsItsStrictestState(ExtensionTrustState extension, PackageTrustState package, TrustVerdict expected)
    {
        var facts = new FakeTrustFacts { Extension = extension, Package = package };

        var verdict = await new TrustEvaluator(facts).EvaluateAsync(Request(new DecisionHarness(), ActorKind.Extension), null, Token);

        Assert.Equal(expected, verdict);
    }

    [Fact]
    public async Task AMismatchedCallerOutweighsAnEligibleExtension()
    {
        var verdict = await new TrustEvaluator(new FakeTrustFacts { Software = SoftwareIdentityState.Mismatched }).EvaluateAsync(
            Request(new DecisionHarness(), ActorKind.Extension), null, Token);

        Assert.Equal(TrustVerdict.Revoked, verdict);
    }

    [Fact]
    public async Task ARemoteRequestAlsoReadsTheDeviceAndALocalOneNever()
    {
        var local = new FakeTrustFacts { Device = DeviceTrustState.Revoked };
        var remote = new FakeTrustFacts { Device = DeviceTrustState.Revoked };
        var harness = new DecisionHarness();
        var localRequest = Request(harness, ActorKind.None);
        var builder = harness.Request();
        builder.Origin = DecisionOrigin.Remote;

        var localVerdict = await new TrustEvaluator(local).EvaluateAsync(localRequest, null, Token);
        var remoteVerdict = await new TrustEvaluator(remote).EvaluateAsync(builder.Build(), null, Token);

        Assert.Equal(TrustVerdict.Verified, localVerdict);
        Assert.Equal([TrustKind.SoftwareIdentity], local.Reads);
        Assert.Equal(TrustVerdict.Revoked, remoteVerdict);
        Assert.Equal([TrustKind.SoftwareIdentity, TrustKind.Device], remote.Reads);
        Assert.Equal(DecisionOrigin.Remote, remote.LastSubject!.Origin);
    }

    [Theory]
    [InlineData(DeviceTrustState.Trusted, TrustVerdict.Verified)]
    [InlineData(DeviceTrustState.Untrusted, TrustVerdict.Revoked)]
    [InlineData(DeviceTrustState.Unknown, TrustVerdict.Unknown)]
    public async Task ARemoteRequestIsAsEligibleAsItsDevice(DeviceTrustState device, TrustVerdict expected)
    {
        var harness = new DecisionHarness();
        var builder = harness.Request();
        builder.Origin = DecisionOrigin.Remote;

        var verdict = await new TrustEvaluator(new FakeTrustFacts { Device = device }).EvaluateAsync(builder.Build(), null, Token);

        Assert.Equal(expected, verdict);
    }

    [Fact]
    public async Task TheTransportBindingReachesTheFactSourcesAsPartOfTheSubject()
    {
        var facts = new FakeTrustFacts();
        var binding = new TransportBinding(TransportKind.InProcess, TransportAssurance.InProcessHost);

        _ = await new TrustEvaluator(facts).EvaluateAsync(Request(new DecisionHarness(), ActorKind.None), binding, Token);

        Assert.Same(binding, facts.LastSubject!.Transport);
    }

    [Fact]
    public async Task ASourceThatFailsFailsTheEvaluationAndNeverDefaultsToTrust()
    {
        var facts = new FakeTrustFacts { Throw = true };

        _ = await Assert.ThrowsAsync<InvalidOperationException>(async () =>
            await new TrustEvaluator(facts).EvaluateAsync(Request(new DecisionHarness(), ActorKind.None), null, Token));
        _ = await Assert.ThrowsAsync<InvalidOperationException>(async () =>
            await new TrustEvaluator(facts).AssessAsync(TrustEvaluationPoint.CloudAuthentication, Subject(DecisionOrigin.Remote, null), Token));
    }

    [Fact]
    public async Task TheEvaluatorAndTheSubjectValidateTheirArguments()
    {
        var facts = new FakeTrustFacts();
        var evaluator = new TrustEvaluator(facts);
        var harness = new DecisionHarness();
        var chain = DecisionHarness.Chain();

        _ = Assert.Throws<ArgumentNullException>(() => new TrustEvaluator(null!));
        _ = await Assert.ThrowsAsync<ArgumentNullException>(async () => await evaluator.AssessAsync(TrustEvaluationPoint.LocalRpcHandshake, null!, Token));
        _ = await Assert.ThrowsAsync<ArgumentNullException>(async () => await evaluator.EvaluateAsync(null!, null, Token));
        _ = Assert.Throws<ArgumentOutOfRangeException>(() => new TrustSubject(null, chain.Device, chain.Installation, chain.CallerInstance, DecisionOrigin.None));
        _ = Assert.Throws<ArgumentOutOfRangeException>(() => new TrustSubject(null, chain.Device, chain.Installation, chain.CallerInstance, (DecisionOrigin)9));
        _ = Assert.Throws<ArgumentException>(() => new TrustSubject(null, default, chain.Installation, chain.CallerInstance, DecisionOrigin.Local));
        _ = Assert.Throws<ArgumentException>(() => new TrustSubject(null, chain.Device, default, chain.CallerInstance, DecisionOrigin.Local));
        _ = Assert.Throws<ArgumentException>(() => new TrustSubject(null, chain.Device, chain.Installation, default, DecisionOrigin.Local));
        Assert.NotNull(harness);
    }

    // -------------------------------------------------------------------------------------------------- inside the pipeline

    [Theory]
    [InlineData(ActorKind.None)]
    [InlineData(ActorKind.Agent)]
    [InlineData(ActorKind.Extension)]
    public async Task TheBestTrustOfEveryKindNeverGrantsAPermission(ActorKind actor)
    {
        var harness = new DecisionHarness();
        harness.RealTrust = new TrustEvaluator(new FakeTrustFacts());
        harness.Permissions.Behavior = (_, _) => ValueTask.FromResult<PermissionGrantRecord?>(null);
        var request = Request(harness, actor);

        var decision = await harness.Pipeline().EvaluateAsync(EnforcementPoint.ServiceDecision, request, Token);

        Assert.Equal(StepDisposition.Passed, decision.Steps[4].Disposition);
        Assert.Equal(DecisionStep.CapabilityPermission, decision.FailedStep);
        Assert.Equal(DecisionReason.S06NotGranted, decision.Reason);
        Assert.Equal(PermissionDisposition.Required, decision.Permission!.Disposition);
        Assert.Equal(0, harness.OwnerOperation.Calls);
    }

    [Theory]
    [InlineData(PermissionGrantState.NotGranted, DecisionReason.S06NotGranted)]
    [InlineData(PermissionGrantState.ExplicitlyDenied, DecisionReason.S06ExplicitlyDenied)]
    public async Task VerifiedTrustCannotOverrideAnAbsentOrDeniedPermission(PermissionGrantState state, DecisionReason expected)
    {
        var harness = new DecisionHarness();
        harness.RealTrust = new TrustEvaluator(new FakeTrustFacts());
        harness.Permissions.Behavior = (request, _) => ValueTask.FromResult<PermissionGrantRecord?>(harness.Grant(request, state));

        var decision = await harness.Pipeline().EvaluateAsync(EnforcementPoint.ServiceDecision, Request(harness, ActorKind.None), Token);

        Assert.Equal(expected, decision.Reason);
    }

    [Fact]
    public async Task APermissionNeverReplacesTrust()
    {
        var harness = new DecisionHarness();
        harness.Permissions.Behavior = (request, _) => ValueTask.FromResult<PermissionGrantRecord?>(harness.Grant(request));
        var cases = new (Action<FakeTrustFacts> Arrange, ActorKind Actor, DecisionReason Reason)[]
        {
            (f => f.Software = SoftwareIdentityState.Mismatched, ActorKind.None, DecisionReason.S05TrustRevoked),
            (f => f.Software = SoftwareIdentityState.Unknown, ActorKind.None, DecisionReason.S05TrustUnknown),
            (f => f.Extension = ExtensionTrustState.Revoked, ActorKind.Extension, DecisionReason.S05TrustRevoked),
            (f => f.Package = PackageTrustState.Revoked, ActorKind.Extension, DecisionReason.S05TrustRevoked),
            (f => f.Extension = ExtensionTrustState.Installed, ActorKind.Extension, DecisionReason.S05TrustRevoked),
        };
        foreach (var (arrange, actor, reason) in cases)
        {
            var facts = new FakeTrustFacts();
            arrange(facts);
            harness.RealTrust = new TrustEvaluator(facts);
            var before = harness.Log.Count("permission");

            var decision = await harness.Pipeline().EvaluateAsync(EnforcementPoint.ServiceDecision, Request(harness, actor), Token);

            Assert.Equal(reason, decision.Reason);
            Assert.Equal(DecisionStep.TrustEligible, decision.FailedStep);
            Assert.Equal(before, harness.Log.Count("permission"));
        }
    }

    [Fact]
    public async Task ATrustUpgradeNeverChangesWhatPermissionDecides()
    {
        var harness = new DecisionHarness();
        harness.Permissions.Behavior = (_, _) => ValueTask.FromResult<PermissionGrantRecord?>(null);
        var unverified = new FakeTrustFacts { Extension = ExtensionTrustState.Developer, Package = PackageTrustState.Unverified };
        harness.RealTrust = new TrustEvaluator(unverified);
        var request = Request(harness, ActorKind.Extension);

        var before = await harness.Pipeline().EvaluateAsync(EnforcementPoint.ServiceDecision, request, Token);
        unverified.Extension = ExtensionTrustState.Enabled;
        unverified.Package = PackageTrustState.SignatureVerified;
        var after = await harness.Pipeline().EvaluateAsync(EnforcementPoint.ServiceDecision, request, Token);

        Assert.Equal(DecisionReason.S06NotGranted, before.Reason);
        Assert.Equal(DecisionReason.S06NotGranted, after.Reason);
        Assert.Equal(before.Permission!.Disposition, after.Permission!.Disposition);
        Assert.Equal(before.Permission.Constraints, after.Permission.Constraints);
        Assert.Null(before.Permission.ValidUntilUtc);
        Assert.Null(after.Permission.ValidUntilUtc);
    }

    [Fact]
    public async Task UnverifiedTrustRaisesTheRiskFloorAndGrantsNothing()
    {
        var harness = new DecisionHarness();
        harness.Permissions.Behavior = (request, _) => ValueTask.FromResult<PermissionGrantRecord?>(harness.Grant(request));
        var facts = new FakeTrustFacts();
        harness.RealTrust = new TrustEvaluator(facts);
        var request = Request(harness, ActorKind.Extension);

        var verified = await harness.Pipeline().EvaluateAsync(EnforcementPoint.CallerPreCheck, request, Token);
        facts.Extension = ExtensionTrustState.Developer;
        var unverified = await harness.Pipeline().EvaluateAsync(EnforcementPoint.CallerPreCheck, request, Token);

        Assert.Equal(RiskLevel.R3, verified.Risk!.EffectiveRisk);
        Assert.Equal(RiskLevel.R4, unverified.Risk!.EffectiveRisk);
        Assert.Contains(unverified.Risk.Adjustments, adjustment => adjustment.Modifier == RiskModifier.ExtensionWithUnverifiedPackage);
        Assert.Equal(PermissionDisposition.Granted, unverified.Permission!.Disposition);
        Assert.Equal(unverified.Permission.Constraints, verified.Permission!.Constraints);
        Assert.Equal(unverified.Permission.ValidUntilUtc, verified.Permission.ValidUntilUtc);
    }

    [Fact]
    public async Task TrustIsNotALeaseAnExtensionStillNeedsOneWhateverItsTrust()
    {
        var harness = new DecisionHarness();
        harness.RealTrust = new TrustEvaluator(new FakeTrustFacts());
        harness.Permissions.Behavior = (request, _) => ValueTask.FromResult<PermissionGrantRecord?>(harness.Grant(request));
        var builder = harness.Request().WithActors(ActorKind.Extension);
        builder.OmitLease = true;

        var decision = await harness.Pipeline().EvaluateAsync(EnforcementPoint.ServiceDecision, builder.Build(), Token);

        Assert.Equal(DecisionReason.S06LeaseRequired, decision.Reason);
        Assert.Equal(PermissionDisposition.Granted, decision.Permission!.Disposition);
    }

    [Fact]
    public async Task ALeaseNeverReplacesTrustAndAFailingTrustSourceRefusesTheStepAsUnavailable()
    {
        var harness = new DecisionHarness();
        var facts = new FakeTrustFacts { Extension = ExtensionTrustState.Revoked };
        harness.RealTrust = new TrustEvaluator(facts);
        harness.Permissions.Behavior = (request, _) => ValueTask.FromResult<PermissionGrantRecord?>(harness.Grant(request));
        var request = Request(harness, ActorKind.Extension);

        var revoked = await harness.Pipeline().EvaluateAsync(EnforcementPoint.ServiceDecision, request, Token);
        facts.Throw = true;
        var unavailable = await harness.Pipeline().EvaluateAsync(EnforcementPoint.ServiceDecision, request, Token);

        Assert.Equal(DecisionReason.S05TrustRevoked, revoked.Reason);
        Assert.Equal(DecisionReason.S05Unavailable, unavailable.Reason);
        Assert.Equal(0, harness.Leases.Calls);
    }

    [Fact]
    public async Task AFullyTrustedPermittedLeasedExtensionStillNeedsItsApprovalAtThisRisk()
    {
        var harness = new DecisionHarness();
        harness.RealTrust = new TrustEvaluator(new FakeTrustFacts());
        harness.Permissions.Behavior = (request, _) => ValueTask.FromResult<PermissionGrantRecord?>(harness.Grant(request));
        var request = Request(harness, ActorKind.Extension);

        var decision = await harness.Pipeline().EvaluateAsync(EnforcementPoint.ServiceDecision, request, Token);

        Assert.Equal(DecisionStep.ApprovalAndPresence, decision.FailedStep);
        Assert.Equal(DecisionReason.S10ApprovalRequired, decision.Reason);
    }

    private static Task<TrustAssessment> AssessAsync(TrustEvaluationPoint point, FakeTrustFacts facts) =>
        new TrustEvaluator(facts).AssessAsync(point, Subject(DecisionOrigin.Local, null), Token).AsTask();

    private static TrustSubject Subject(DecisionOrigin origin, DelegatedActor? actor)
    {
        var chain = DecisionHarness.Chain();
        return new TrustSubject(actor, chain.Device, chain.Installation, chain.CallerInstance, origin);
    }

    private static DecisionRequest Request(DecisionHarness harness, ActorKind actor)
    {
        var builder = harness.Request();
        if (actor != ActorKind.None)
        {
            _ = builder.WithActors(actor);
        }

        return builder.Build();
    }

    private static IEnumerable<Type> Flatten(Type type)
    {
        yield return type;
        if (type.IsGenericType)
        {
            foreach (var argument in type.GetGenericArguments().SelectMany(Flatten))
            {
                yield return argument;
            }
        }

        if (type.HasElementType && type.GetElementType() is { } element)
        {
            foreach (var inner in Flatten(element))
            {
                yield return inner;
            }
        }
    }
}
