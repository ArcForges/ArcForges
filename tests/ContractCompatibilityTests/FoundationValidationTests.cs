// SPDX-License-Identifier: AGPL-3.0-only

using ArcForges.Contracts.Foundation;

namespace ArcForges.Tests.ContractCompatibilityTests;

/// <summary>
/// The invariants a reference must satisfy, and the illegal combinations it must refuse.
/// </summary>
/// <remarks>
/// Validation is inline. Contract assemblies do not reference the Guard helper in
/// <c>ArcForges.Foundation</c>, so these throw <see cref="ArgumentException"/> and
/// <see cref="ArgumentOutOfRangeException"/> directly and the assembly keeps zero non-essential transitive
/// dependencies.
/// </remarks>
public sealed class FoundationValidationTests
{
    [Xunit.Fact]
    [Xunit.Trait("Category", "Contract")]
    public void AValidLocalResourcePassesValidation() => FoundationFixtures.LocalResource().Validate();

    [Xunit.Fact]
    [Xunit.Trait("Category", "Contract")]
    public void AValidCloudResourcePassesValidation() => FoundationFixtures.CloudResource().Validate();

    [Xunit.Theory]
    [Xunit.InlineData(ResourceAvailability.LocalOnline)]
    [Xunit.InlineData(ResourceAvailability.LocalOffline)]
    [Xunit.Trait("Category", "Contract")]
    public void LocalAvailabilityWithoutALocalLocatorIsRefused(ResourceAvailability availability)
    {
        var reference = FoundationFixtures.LocalResource() with
        {
            Availability = availability,
            LocalLocator = null,
        };

        Xunit.Assert.Throws<ArgumentException>(reference.Validate);
    }

    [Xunit.Theory]
    [Xunit.InlineData(ResourceAvailability.LocalOnline)]
    [Xunit.InlineData(ResourceAvailability.LocalOffline)]
    [Xunit.Trait("Category", "Contract")]
    public void LocalAvailabilityCarryingACloudObjectIsRefused(ResourceAvailability availability)
    {
        var reference = FoundationFixtures.LocalResource() with
        {
            Availability = availability,
            CloudObjectId = Guid.Parse(FoundationFixtures.CloudObjectGuid),
        };

        Xunit.Assert.Throws<ArgumentException>(reference.Validate);
    }

    [Xunit.Fact]
    [Xunit.Trait("Category", "Contract")]
    public void CloudAvailabilityWithoutACloudObjectIsRefused()
    {
        var reference = FoundationFixtures.CloudResource() with { CloudObjectId = null };

        Xunit.Assert.Throws<ArgumentException>(reference.Validate);
    }

    [Xunit.Fact]
    [Xunit.Trait("Category", "Contract")]
    public void CloudAvailabilityCarryingALocalLocatorIsRefused()
    {
        var reference = FoundationFixtures.CloudResource() with { LocalLocator = FoundationFixtures.Locator() };

        Xunit.Assert.Throws<ArgumentException>(reference.Validate);
    }

    [Xunit.Fact]
    [Xunit.Trait("Category", "Contract")]
    public void PreparingRequiresExactlyOneLocator()
    {
        var neither = FoundationFixtures.LocalResource() with
        {
            Availability = ResourceAvailability.Preparing,
            LocalLocator = null,
        };
        var both = FoundationFixtures.LocalResource() with
        {
            Availability = ResourceAvailability.Preparing,
            CloudObjectId = Guid.Parse(FoundationFixtures.CloudObjectGuid),
        };
        var exactlyOne = FoundationFixtures.LocalResource() with
        {
            Availability = ResourceAvailability.Preparing,
        };

        Xunit.Assert.Throws<ArgumentException>(neither.Validate);
        Xunit.Assert.Throws<ArgumentException>(both.Validate);
        exactlyOne.Validate();
    }

    [Xunit.Fact]
    [Xunit.Trait("Category", "Contract")]
    public void UnavailablePermitsNoLocator()
    {
        var withLocator = FoundationFixtures.LocalResource() with
        {
            Availability = ResourceAvailability.Unavailable,
        };
        var withNeither = FoundationFixtures.LocalResource() with
        {
            Availability = ResourceAvailability.Unavailable,
            LocalLocator = null,
        };

        Xunit.Assert.Throws<ArgumentException>(withLocator.Validate);
        withNeither.Validate();
    }

    [Xunit.Theory]
    [Xunit.InlineData("")]
    [Xunit.InlineData("not-a-hash")]
    [Xunit.InlineData("9F86D081884C7D659A2FEAA0C55AD015A3BF4F1B2B0B822CD15D6C15B0F00A08")]
    [Xunit.InlineData("9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a0")]
    [Xunit.Trait("Category", "Contract")]
    public void AContentHashThatIsNotLowerCaseHexSha256IsRefused(string hash)
    {
        // Empty, wrong shape, upper-case and one character short all fail. A reference without a real digest
        // must not exist at all, so there is nowhere for a placeholder hash to hide.
        Xunit.Assert.Throws<ArgumentException>(() => FoundationFixtures.LocalResource() with { ContentHash = hash });
    }

    [Xunit.Theory]
    [Xunit.InlineData(WellKnownProducts.ArcForgesCloud)]
    [Xunit.InlineData(WellKnownProducts.ArcForgesWeb)]
    [Xunit.InlineData(WellKnownProducts.ArcChatMobile)]
    [Xunit.Trait("Category", "Contract")]
    public void OnlyTheFourDesktopProductsCanOwnAResource(string product)
    {
        // Cloud and Web hold resources but never own them, and the mobile head is a client. Ownership decides
        // who re-authorises access, so a non-owner claiming it would break the authorisation chain.
        Xunit.Assert.Throws<ArgumentOutOfRangeException>(() =>
            FoundationFixtures.LocalResource() with { OwnerProduct = new ProductId(product) });
    }

    [Xunit.Fact]
    [Xunit.Trait("Category", "Contract")]
    public void ANegativeSizeIsRefused() =>
        Xunit.Assert.Throws<ArgumentOutOfRangeException>(() =>
            FoundationFixtures.LocalResource() with { SizeBytes = -1 });

    [Xunit.Theory]
    [Xunit.InlineData("")]
    [Xunit.InlineData("   ")]
    [Xunit.Trait("Category", "Contract")]
    public void BlankTextFieldsAreRefused(string blank)
    {
        Xunit.Assert.Throws<ArgumentException>(() => FoundationFixtures.LocalResource() with { Kind = blank });
        Xunit.Assert.Throws<ArgumentException>(() => FoundationFixtures.LocalResource() with { DisplayName = blank });
        Xunit.Assert.Throws<ArgumentException>(() => FoundationFixtures.Locator() with { LocatorId = blank });
    }

    [Xunit.Fact]
    [Xunit.Trait("Category", "Contract")]
    public void AnArtifactMustShareItsResourceOwner()
    {
        var mismatched = FoundationFixtures.Artifact() with { OwnerProduct = ProductId.ArcScope };

        Xunit.Assert.Throws<ArgumentException>(mismatched.Validate);
    }

    [Xunit.Fact]
    [Xunit.Trait("Category", "Contract")]
    public void AnArtifactTimelineCannotRunBackwards()
    {
        var reversed = FoundationFixtures.Artifact() with
        {
            UpdatedAtUtc = FoundationFixtures.CreatedAt.AddSeconds(-1),
        };

        Xunit.Assert.Throws<ArgumentException>(reversed.Validate);
    }

    [Xunit.Fact]
    [Xunit.Trait("Category", "Contract")]
    public void AValidArtifactPassesValidation() => FoundationFixtures.Artifact().Validate();
}
