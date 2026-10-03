// SPDX-License-Identifier: AGPL-3.0-only
using System.Reflection;
using ArcForges.Security.Decisions;
using ArcForges.Security.Egress;
using Xunit;

namespace ArcForges.Security.Tests;

/// <summary>EG-04: every egress decision is audited, durably, before it is released, with classes and identities and no content.</summary>
public sealed class EgressAuditTests
{
    public static TheoryData<string> ScenarioNames => EgressScenarios.Data;

    [Theory]
    [MemberData(nameof(ScenarioNames))]
    public async Task EveryDecisionWritesExactlyOneAuditRecordThatTheDecisionCarries(string name)
    {
        var scenario = EgressScenarios.Build(name);
        var h = scenario.Harness;

        var decision = await h.Authority().DecideAsync(scenario.Request, scenario.Destination, TestContext.Current.CancellationToken);

        var record = Assert.Single(h.Audit.Records);
        Assert.Same(record, decision.Audit);
        Assert.Equal(1, h.Log.Count("egress-audit"));
        Assert.Equal(decision.Allowed ? EgressAuditKind.Authorized : EgressAuditKind.Refused, record.Kind);
        Assert.Equal(scenario.Expected, record.Reason);
        Assert.Equal(decision.ReasonCode, record.ReasonCode);
        Assert.Equal(decision.RegisteredCode, record.RegisteredCode);
        Assert.Equal(DecisionHarness.InstantOf(h.Now), record.OccurredAt);
        Assert.Same(scenario.Request.Actors, record.Actors);
        Assert.Equal(scenario.Request.Actors.CallerInstance, record.Executor);
        Assert.Equal(scenario.Request.CapabilityKey, record.CapabilityKey);
        Assert.Same(scenario.Request.Resource, record.Resource);
        Assert.Same(scenario.Request.Scope, record.Scope);
        Assert.Equal(scenario.Request.Origin, record.Origin);
        Assert.Equal(scenario.Request.Actors.Device, record.Device);
        Assert.Equal(scenario.Request.CommandId, record.Correlation);
        Assert.Equal(decision.DataClass, record.DataClass);
        Assert.Equal(decision.DestinationClass, record.DestinationClass);
        Assert.Equal(decision.Authority, record.Authority);
        Assert.Equal(decision.AuthorityReference, record.AuthorityReference);
        Assert.Equal(decision.Destination?.Origin, record.Destination);
    }

    [Fact]
    public async Task AnAuthorizedRecordNamesTheDataClassTheExactDestinationAndTheAuthority()
    {
        var h = new EgressHarness();
        var request = h.Request();
        h.Classify(EgressDataClass.Diagnostic, aiEligible: true);
        h.Permit(request, destinationClass: EgressDestinationClass.CloudAiProvider);
        h.Grants.Behavior = (_, _, _) => EgressScenarios.Grants(h.Grant(request, authority: EgressAuthorityKind.ProductRoute, reference: "route-3", issuer: "owner.route"));

        var decision = await h.Authority().DecideAsync(request, EgressHarness.Destination, TestContext.Current.CancellationToken);

        Assert.True(decision.Allowed);
        var record = decision.Audit;
        Assert.Equal(EgressAuditKind.Authorized, record.Kind);
        Assert.Equal(EgressReason.None, record.Reason);
        Assert.Null(record.ReasonCode);
        Assert.Null(record.RegisteredCode);
        Assert.Equal("https://api.example.com", record.Destination);
        Assert.Equal(EgressDestinationClass.CloudAiProvider, record.DestinationClass);
        Assert.Equal(EgressDataClass.Diagnostic, record.DataClass);
        Assert.True(record.AiEligible);
        Assert.Equal(EgressAuthorityKind.ProductRoute, record.Authority);
        Assert.Equal("route-3", record.AuthorityReference);
        Assert.Equal("owner.route", record.GrantIssuer);
        Assert.Equal("grant-generation-1", record.GrantGeneration);
        Assert.Equal("allowlist-generation-1", record.AllowlistGeneration);
    }

    [Fact]
    public async Task ARefusalRecordKeepsWhatWasKnownWhenItRefused()
    {
        var h = new EgressHarness();
        var request = h.Request();
        h.Classify(EgressDataClass.SensitiveContent, aiEligible: false);
        h.Permit(request, allowlistMax: EgressDataClass.Diagnostic);

        var decision = await h.Authority().DecideAsync(request, EgressHarness.Destination, TestContext.Current.CancellationToken);

        Assert.Equal(EgressReason.DataClassAboveAllowlist, decision.Reason);
        var record = decision.Audit;
        Assert.Equal(EgressAuditKind.Refused, record.Kind);
        Assert.Equal("egress.data_class_above_allowlist", record.ReasonCode);
        Assert.Equal("perm.egress_denied", record.RegisteredCode);
        Assert.Equal("https://api.example.com", record.Destination);
        Assert.Equal(EgressDestinationClass.ThirdParty, record.DestinationClass);
        Assert.Equal(EgressDataClass.SensitiveContent, record.DataClass);
        Assert.False(record.AiEligible);
        Assert.Equal(EgressAuthorityKind.None, record.Authority);
        Assert.Null(record.AuthorityReference);
        Assert.Null(record.GrantIssuer);
        Assert.Equal("allowlist-generation-1", record.AllowlistGeneration);
    }

    [Fact]
    public async Task TheDecisionIsNotReleasedUntilTheAuditWriteHasCompleted()
    {
        var h = new EgressHarness();
        var request = h.Request();
        h.Permit(request);
        var written = false;
        h.Audit.Behavior = async (_, _) =>
        {
            await Task.Delay(150, CancellationToken.None);
            written = true;
        };

        var decision = await h.Authority().DecideAsync(request, EgressHarness.Destination, TestContext.Current.CancellationToken);

        Assert.True(decision.Allowed);
        Assert.True(written);
    }

    [Theory]
    [InlineData("throws")]
    [InlineData("faults")]
    [InlineData("times-out-honouring-the-token")]
    [InlineData("times-out-ignoring-the-token")]
    public async Task AnAllowedDecisionWhoseAuditCannotBeWrittenIsRefusedNotReleased(string failure)
    {
        var h = new EgressHarness();
        var request = h.Request();
        h.Permit(request);
        h.Audit.Behavior = (_, token) => Fail(failure, token);

        var decision = await h.Authority(new EgressAuthorityOptions { StepTimeout = TimeSpan.FromMilliseconds(150) })
            .DecideAsync(request, EgressHarness.Destination, TestContext.Current.CancellationToken);

        Assert.False(decision.Allowed);
        Assert.Equal(EgressReason.AuditUnavailable, decision.Reason);
        Assert.Equal(BoundaryVerdict.Unknown, decision.ToBoundaryVerdict());
        Assert.Equal("resource.unavailable", DecisionHarness.FailureCode(decision.ToAuthorizationOutcome()));
        Assert.Equal(EgressAuditKind.Refused, decision.Audit.Kind);
        Assert.Equal(EgressAuthorityKind.None, decision.Authority);
        Assert.Null(decision.AuthorityReference);
        Assert.Equal(1, h.Log.Count("egress-audit"));
    }

    [Fact]
    public async Task ARefusalStaysTheSameRefusalWhenItsAuditCannotBeWritten()
    {
        var h = new EgressHarness();
        var request = h.Request();
        h.Audit.Behavior = (_, _) => throw new InvalidOperationException("sink down");

        var decision = await h.Authority().DecideAsync(request, EgressHarness.Destination, TestContext.Current.CancellationToken);

        Assert.Equal(EgressReason.NotAllowlisted, decision.Reason);
        Assert.Equal(BoundaryVerdict.Denied, decision.ToBoundaryVerdict());
    }

    [Fact]
    public async Task TheAuditWriteIsNotCancelledByTheCallersCancellation()
    {
        var h = new EgressHarness();
        var request = h.Request();
        h.Permit(request);
        using var cancel = new CancellationTokenSource();
        var completed = false;
        h.Audit.Behavior = async (_, token) =>
        {
            await cancel.CancelAsync();
            await Task.Delay(50, token);
            completed = true;
        };

        var decision = await h.Authority().DecideAsync(request, EgressHarness.Destination, cancel.Token);

        Assert.True(decision.Allowed);
        Assert.True(completed);
        Assert.NotEqual(cancel.Token, h.Audit.LastToken);
    }

    [Fact]
    public void TheAuditRecordHasRoomForClassesIdentitiesAndReferencesOnlyNeverContent()
    {
        var allowedText = new[]
        {
            nameof(EgressAuditRecord.ReasonCode),
            nameof(EgressAuditRecord.RegisteredCode),
            nameof(EgressAuditRecord.SoftwareIdentity),
            nameof(EgressAuditRecord.CapabilityKey),
            nameof(EgressAuditRecord.Destination),
            nameof(EgressAuditRecord.AuthorityReference),
            nameof(EgressAuditRecord.GrantIssuer),
            nameof(EgressAuditRecord.GrantGeneration),
            nameof(EgressAuditRecord.AllowlistGeneration),
        };
        var properties = typeof(EgressAuditRecord).GetProperties(BindingFlags.Public | BindingFlags.Instance)
            .Where(property => property.Name != "EqualityContract")
            .ToArray();

        foreach (var property in properties)
        {
            var type = Nullable.GetUnderlyingType(property.PropertyType) ?? property.PropertyType;
            if (type == typeof(string))
            {
                Assert.Contains(property.Name, allowedText);
            }
            else
            {
                Assert.False(type == typeof(byte[]) || type == typeof(object) || type == typeof(ReadOnlyMemory<byte>) || type == typeof(Stream),
                    $"{property.Name} could carry content.");
            }
        }

        Assert.Equal(allowedText.Length, properties.Count(property => property.PropertyType == typeof(string)));
    }

    [Fact]
    public async Task EachRepeatedDecisionIsItsOwnAuditEvent()
    {
        var h = new EgressHarness();
        var request = h.Request();
        h.Permit(request);
        var authority = h.Authority();

        for (var index = 0; index < 3; index++)
        {
            await authority.DecideAsync(request, EgressHarness.Destination, TestContext.Current.CancellationToken);
        }

        Assert.Equal(3, h.Audit.Records.Count);
        Assert.All(h.Audit.Records, record => Assert.Equal(EgressAuditKind.Authorized, record.Kind));
    }

    private static ValueTask Fail(string failure, CancellationToken token) => failure switch
    {
        "throws" => throw new InvalidOperationException("sink failed"),
        "faults" => FaultAsync(),
        "times-out-honouring-the-token" => HonourAsync(token),
        "times-out-ignoring-the-token" => IgnoreAsync(),
        _ => throw new ArgumentOutOfRangeException(nameof(failure)),
    };

    private static async ValueTask FaultAsync()
    {
        await Task.Yield();
        throw new InvalidOperationException("sink faulted");
    }

    private static async ValueTask HonourAsync(CancellationToken token) => await Task.Delay(Timeout.Infinite, token);

    private static async ValueTask IgnoreAsync() => await Task.Delay(TimeSpan.FromSeconds(30), CancellationToken.None);
}
