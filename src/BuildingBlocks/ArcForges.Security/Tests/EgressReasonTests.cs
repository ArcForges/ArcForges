// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Foundation.Errors;
using ArcForges.Security.Egress;
using Xunit;

namespace ArcForges.Security.Tests;

/// <summary>The closed reason table and the validation of the egress policy records.</summary>
public sealed class EgressReasonTests
{
    private static readonly DateTimeOffset From = new(2026, 9, 30, 12, 0, 0, TimeSpan.Zero);

    [Fact]
    public void EveryReasonThatCanRefuseHasExactlyOneEntryWithAStableCodeAndARegisteredSemanticCode()
    {
        var reasons = Enum.GetValues<EgressReason>().Where(reason => reason != EgressReason.None).ToArray();

        Assert.Equal(reasons.Order(), EgressReasons.All.Select(entry => entry.Reason).Order());
        Assert.Equal(reasons.Length, EgressReasons.All.Select(entry => entry.Code).Distinct(StringComparer.Ordinal).Count());
        foreach (var reason in reasons)
        {
            var entry = EgressReasons.Describe(reason);
            Assert.Equal(reason, entry.Reason);
            Assert.StartsWith("egress.", entry.Code, StringComparison.Ordinal);
            Assert.True(ReasonCodes.TryGet(entry.RegisteredCode, out _), entry.RegisteredCode);
            Assert.Equal(entry.IsUnavailable, entry.RegisteredCode == "resource.unavailable");
            Assert.Equal(entry.IsUnavailable ? "resource.unavailable" : "perm.egress_denied", entry.RegisteredCode);
            Assert.NotNull(TypedFailure.Create(entry.RegisteredCode));
        }

        Assert.Equal(
            [EgressReason.ClassifierUnavailable, EgressReason.AllowlistUnavailable, EgressReason.GrantSourceUnavailable, EgressReason.AuditUnavailable],
            EgressReasons.All.Where(entry => entry.IsUnavailable).Select(entry => entry.Reason));
    }

    [Fact]
    public void NoReasonIsDescribedForNoneOrAnUndefinedValue()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => EgressReasons.Describe(EgressReason.None));
        Assert.Throws<ArgumentOutOfRangeException>(() => EgressReasons.Describe((EgressReason)999));
    }

    [Fact]
    public void SecretMaterialIsAboveEveryLimitAPolicyRecordCanState()
    {
        Assert.True(EgressDataClass.SecretMaterial > EgressDataClass.SensitiveContent);
        var destination = EgressDestinationIdentity.Parse("https://api.example.com");
        foreach (var invalid in new[] { EgressDataClass.None, EgressDataClass.SecretMaterial, (EgressDataClass)42 })
        {
            Assert.Throws<ArgumentOutOfRangeException>(() => new EgressAllowlistEntry("scope", destination, EgressDestinationClass.ThirdParty, invalid, "g"));
            Assert.Throws<ArgumentOutOfRangeException>(() => Grant(max: invalid));
        }
    }

    [Fact]
    public void AnAllowlistEntryIsValidatedAndKeepsWhatItWasGiven()
    {
        var destination = EgressDestinationIdentity.Parse("https://api.example.com");
        var entry = new EgressAllowlistEntry("scope-1", destination, EgressDestinationClass.CloudAiProvider, EgressDataClass.Diagnostic, "generation-4");

        Assert.Equal("scope-1", entry.ScopeKey);
        Assert.Same(destination, entry.Destination);
        Assert.Equal(EgressDestinationClass.CloudAiProvider, entry.DestinationClass);
        Assert.Equal(EgressDataClass.Diagnostic, entry.MaxDataClass);
        Assert.Equal("generation-4", entry.SourceGeneration);
        Assert.Throws<ArgumentException>(() => new EgressAllowlistEntry(" ", destination, EgressDestinationClass.ThirdParty, EgressDataClass.Public, "g"));
        Assert.Throws<ArgumentException>(() => new EgressAllowlistEntry("scope\n", destination, EgressDestinationClass.ThirdParty, EgressDataClass.Public, "g"));
        Assert.Throws<ArgumentException>(() => new EgressAllowlistEntry("scope", destination, EgressDestinationClass.ThirdParty, EgressDataClass.Public, ""));
        Assert.Throws<ArgumentException>(() => new EgressAllowlistEntry(new string('s', 257), destination, EgressDestinationClass.ThirdParty, EgressDataClass.Public, "g"));
        Assert.Throws<ArgumentNullException>(() => new EgressAllowlistEntry("scope", null!, EgressDestinationClass.ThirdParty, EgressDataClass.Public, "g"));
        Assert.Throws<ArgumentOutOfRangeException>(() => new EgressAllowlistEntry("scope", destination, EgressDestinationClass.None, EgressDataClass.Public, "g"));
        Assert.Throws<ArgumentOutOfRangeException>(() => new EgressAllowlistEntry("scope", destination, (EgressDestinationClass)9, EgressDataClass.Public, "g"));
        _ = new EgressAllowlistEntry(new string('s', 256), destination, EgressDestinationClass.Public, EgressDataClass.SensitiveContent, "g");
    }

    [Fact]
    public void AGrantRecordIsValidatedAndKeepsWhatItWasGiven()
    {
        var grant = Grant();

        Assert.Equal("issuer", grant.IssuerKey);
        Assert.Equal("principal", grant.PrincipalKey);
        Assert.Equal("capability", grant.CapabilityKey);
        Assert.Equal("scope", grant.ScopeKey);
        Assert.Equal("https://api.example.com", grant.Destination.Origin);
        Assert.Equal(EgressGrantState.Granted, grant.State);
        Assert.Equal(EgressDataClass.WorkspaceContent, grant.MaxDataClass);
        Assert.Equal(EgressAuthorityKind.UserConsent, grant.Authority);
        Assert.Equal("consent-1", grant.AuthorityReference);
        Assert.Equal(From, grant.ValidFromUtc);
        Assert.Equal(From.AddHours(1), grant.ValidUntilUtc);
        Assert.Equal("generation", grant.SourceGeneration);
        Assert.Equal(EgressGrantState.Denied, Grant(state: EgressGrantState.Denied).State);

        Assert.Throws<ArgumentException>(() => Grant(issuer: ""));
        Assert.Throws<ArgumentException>(() => Grant(principal: " "));
        Assert.Throws<ArgumentException>(() => Grant(capability: "a\tb"));
        Assert.Throws<ArgumentException>(() => Grant(scope: ""));
        Assert.Throws<ArgumentException>(() => Grant(reference: ""));
        Assert.Throws<ArgumentException>(() => Grant(generation: ""));
        Assert.Throws<ArgumentNullException>(() => Grant(destination: null));
        Assert.Throws<ArgumentOutOfRangeException>(() => Grant(state: EgressGrantState.None));
        Assert.Throws<ArgumentOutOfRangeException>(() => Grant(state: (EgressGrantState)7));
        Assert.Throws<ArgumentOutOfRangeException>(() => Grant(authority: EgressAuthorityKind.None));
        Assert.Throws<ArgumentOutOfRangeException>(() => Grant(authority: (EgressAuthorityKind)7));
    }

    [Fact]
    public void AGrantLifetimeIsUtcAndNotEmpty()
    {
        Assert.Throws<ArgumentException>(() => Grant(from: new DateTimeOffset(2026, 9, 30, 13, 0, 0, TimeSpan.FromHours(1))));
        Assert.Throws<ArgumentException>(() => Grant(until: new DateTimeOffset(2026, 9, 30, 13, 0, 0, TimeSpan.FromHours(1))));
        Assert.Throws<ArgumentException>(() => Grant(until: From));
        Assert.Throws<ArgumentException>(() => Grant(until: From.AddTicks(-1)));
        Assert.Equal(From.AddTicks(1), Grant(until: From.AddTicks(1)).ValidUntilUtc);
    }

    private static EgressGrantRecord Grant(
        string issuer = "issuer",
        string principal = "principal",
        string capability = "capability",
        string scope = "scope",
        string? destination = "https://api.example.com",
        EgressGrantState state = EgressGrantState.Granted,
        EgressDataClass max = EgressDataClass.WorkspaceContent,
        EgressAuthorityKind authority = EgressAuthorityKind.UserConsent,
        string reference = "consent-1",
        DateTimeOffset? from = null,
        DateTimeOffset? until = null,
        string generation = "generation") =>
        new(
            issuer,
            principal,
            capability,
            scope,
            destination is null ? null! : EgressDestinationIdentity.Parse(destination),
            state,
            max,
            authority,
            reference,
            from ?? From,
            until ?? From.AddHours(1),
            generation);
}
