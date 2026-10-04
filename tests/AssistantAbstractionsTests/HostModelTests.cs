// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Assistant.Abstractions;
using ArcForges.Contracts.Foundation.V1;

namespace AssistantAbstractionsTests;

public sealed class HostModelTests
{
    [Xunit.Fact]
    public void ResourceReferenceValidatesOwnerKindRevisionAndHashAndCopiesOnEntryAndExit()
    {
        var wire = TestData.Version();
        var reference = new AssistantResourceReference(wire);
        Xunit.Assert.Same(AssistantProductIdentity.ArcScope, reference.Owner);
        Xunit.Assert.True(reference.IsOwnedBy(AssistantProductIdentity.ArcScope));
        Xunit.Assert.False(reference.IsOwnedBy(AssistantProductIdentity.Companion));
        Xunit.Assert.Throws<ArgumentNullException>(() => reference.IsOwnedBy(null!));

        wire.ContentHash = new string('b', 64);
        Xunit.Assert.Equal(new string('a', 64), reference.ToWire().ContentHash);
        var exported = reference.ToWire();
        exported.ContentHash = new string('c', 64);
        Xunit.Assert.Equal(new string('a', 64), reference.ToWire().ContentHash);

        Xunit.Assert.Throws<ArgumentNullException>(() => new AssistantResourceReference(null!));
        var noRevision = TestData.Version();
        noRevision.ClearRevision();
        Xunit.Assert.Throws<ArgumentException>(() => new AssistantResourceReference(noRevision));
        Xunit.Assert.Throws<ArgumentException>(() => new AssistantResourceReference(new ResourceVersionRef
        {
            Cloud = new Revision { Value = 1 },
            ContentHash = new string('a', 64),
        }));
    }

    [Xunit.Theory]
    [Xunit.InlineData("unknown-product", "unknown-product.capture", 'a')]
    [Xunit.InlineData("arcscope", "companion.capture", 'a')]
    [Xunit.InlineData("arcscope", "arcscope.", 'a')]
    [Xunit.InlineData("arcscope", "capture", 'a')]
    [Xunit.InlineData("arcscope", "arcscope.capture", 'A')]
    public void ResourceReferenceRefusesForeignOwnersUnnamespacedKindsAndMalformedHashes(string owner, string kind, char hash)
    {
        var version = TestData.Version(owner, kind, hash);
        Xunit.Assert.Throws<ArgumentException>(() => new AssistantResourceReference(version));
    }

    [Xunit.Fact]
    public void ResourceReferenceRefusesShortAndOversizedHashesAndKinds()
    {
        var shortHash = TestData.Version();
        shortHash.ContentHash = new string('a', 63);
        Xunit.Assert.Throws<ArgumentException>(() => new AssistantResourceReference(shortHash));
        var missingHash = TestData.Version();
        missingHash.ClearContentHash();
        Xunit.Assert.Throws<ArgumentException>(() => new AssistantResourceReference(missingHash));
        Xunit.Assert.Throws<ArgumentException>(() => new AssistantResourceReference(
            TestData.Version(kind: "arcscope." + new string('x', 200))));
    }

    [Xunit.Fact]
    public void ContextBudgetIsBoundedByTheSharedCeilings()
    {
        var budget = new AssistantContextBudget(AssistantContextBudget.AbsoluteMaximumItems,
            AssistantContextBudget.AbsoluteMaximumBytes);
        Xunit.Assert.Equal(128, budget.MaximumItems);
        Xunit.Assert.Equal(64UL * 1024 * 1024, budget.MaximumBytes);
        Xunit.Assert.Throws<ArgumentOutOfRangeException>(() => new AssistantContextBudget(0, 1));
        Xunit.Assert.Throws<ArgumentOutOfRangeException>(() => new AssistantContextBudget(129, 1));
        Xunit.Assert.Throws<ArgumentOutOfRangeException>(() => new AssistantContextBudget(1, 0));
        Xunit.Assert.Throws<ArgumentOutOfRangeException>(() => new AssistantContextBudget(1,
            AssistantContextBudget.AbsoluteMaximumBytes + 1));
    }

    [Xunit.Fact]
    public void ContextSelectionIsBoundedRevisionBoundAndFreeOfPathsAndBytes()
    {
        var reference = TestData.Reference();
        var selection = new HostContextSelection(ContextSelectionId.New(), reference, "selection.capture", 3, 512);
        Xunit.Assert.Equal(512UL, selection.EstimatedBytes);
        Xunit.Assert.Equal(3U, selection.ApproximateItemCount);
        Xunit.Assert.NotSame(reference, selection.Resource);
        Xunit.Assert.Equal(reference.ToWire(), selection.Resource.ToWire());

        Xunit.Assert.Throws<ArgumentException>(() => new HostContextSelection(default, reference, "selection.capture", 1, 1));
        Xunit.Assert.Throws<ArgumentNullException>(() => new HostContextSelection(ContextSelectionId.New(), null!, "selection.capture", 1, 1));
        Xunit.Assert.Throws<ArgumentException>(() => new HostContextSelection(ContextSelectionId.New(), reference, "", 1, 1));
        Xunit.Assert.Throws<ArgumentException>(() => new HostContextSelection(ContextSelectionId.New(), reference, "line\nbreak", 1, 1));
        Xunit.Assert.Throws<ArgumentException>(() => new HostContextSelection(ContextSelectionId.New(), reference,
            new string('k', 161), 1, 1));
    }

    [Xunit.Fact]
    public void FrozenContextOwnsItsSnapshotAndTracksPartialResults()
    {
        var owner = TestData.Host();
        var budget = new AssistantContextBudget(4, 4096);
        var first = TestData.Selection(bytes: 100);
        var second = TestData.Selection(bytes: 200);
        var included = new List<HostContextSelection> { first, second };
        var excludedId = ContextSelectionId.New();
        var frozen = new FrozenHostContext(owner, budget, included, [excludedId, excludedId]);

        included.Clear();
        Xunit.Assert.Equal(2, frozen.Included.Count);
        Xunit.Assert.Equal(300UL, frozen.TotalEstimatedBytes);
        Xunit.Assert.Same(budget, frozen.Budget);
        Xunit.Assert.True(frozen.IsPartial);
        Xunit.Assert.Equal([excludedId], frozen.Excluded);
        Xunit.Assert.Equal(owner, frozen.Owner);
        Xunit.Assert.False(new FrozenHostContext(owner, budget, [first]).IsPartial);
        Xunit.Assert.Empty(new FrozenHostContext(owner, budget, []).Included);
    }

    [Xunit.Fact]
    public void FrozenContextRefusesBudgetOverrunsOverflowDuplicatesOverlapAndForeignProducts()
    {
        var owner = TestData.Host();
        var budget = new AssistantContextBudget(2, 1000);
        var a = TestData.Selection(bytes: 600);
        var b = TestData.Selection(bytes: 600);
        var c = TestData.Selection(bytes: 1);

        Xunit.Assert.Throws<ArgumentException>(() => new FrozenHostContext(owner, budget, [a, b]));
        Xunit.Assert.Throws<ArgumentException>(() => new FrozenHostContext(owner, budget, [c, TestData.Selection(bytes: 1), TestData.Selection(bytes: 1)]));
        // Two maximal estimates must not wrap around a 64-bit sum into an apparently small total.
        Xunit.Assert.Throws<ArgumentException>(() => new FrozenHostContext(owner, budget,
            [TestData.Selection(bytes: ulong.MaxValue), TestData.Selection(bytes: 2)]));
        Xunit.Assert.Throws<ArgumentException>(() => new FrozenHostContext(owner, budget, [c, c]));
        Xunit.Assert.Throws<ArgumentException>(() => new FrozenHostContext(owner, budget, [c], [c.Id]));
        var foreignResource = TestData.Selection(TestData.Reference("companion"), bytes: 1);
        Xunit.Assert.Throws<ArgumentException>(() => new FrozenHostContext(owner, budget, [foreignResource]));
        Xunit.Assert.Throws<ArgumentNullException>(() => new FrozenHostContext(null!, budget, []));
        Xunit.Assert.Throws<ArgumentNullException>(() => new FrozenHostContext(owner, null!, []));
        Xunit.Assert.Throws<ArgumentNullException>(() => new FrozenHostContext(owner, budget, null!));
        Xunit.Assert.NotNull(new FrozenHostContext(owner, budget, [a]));
    }

    [Xunit.Fact]
    public void ActionDescriptorKeysAreBoundedLowercaseAndUnique()
    {
        var descriptor = TestData.Descriptor();
        Xunit.Assert.Equal("measurements.read", descriptor.OperationId);
        Xunit.Assert.Equal(["resource.selection"], descriptor.AcceptedContextKeys);

        foreach (string invalid in new[] { "", "Upper", "has space", "line\nbreak", "semi;colon", new string('a', 161) })
        {
            Xunit.Assert.Throws<ArgumentException>(() => new AssistantActionDescriptor(invalid, "t", "d", [], [], "a"));
            Xunit.Assert.Throws<ArgumentException>(() => new AssistantActionDescriptor("op", "t", "d", [invalid], [], "a"));
            Xunit.Assert.Throws<ArgumentException>(() => new AssistantActionDescriptor("op", "t", "d", [], [invalid], "a"));
        }

        Xunit.Assert.Throws<ArgumentException>(() => new AssistantActionDescriptor("op", "t", "d", ["x", "x"], [], "a"));
        Xunit.Assert.Throws<ArgumentException>(() => new AssistantActionDescriptor("op", "t", "d", [], ["x", "x"], "a"));
        Xunit.Assert.Throws<ArgumentNullException>(() => new AssistantActionDescriptor("op", "t", "d", null!, [], "a"));
    }

    [Xunit.Fact]
    public void AvailabilityIsEitherAvailableOrUnavailableWithAReason()
    {
        Xunit.Assert.True(new ActionAvailability(true).IsAvailable);
        Xunit.Assert.Null(new ActionAvailability(true).ReasonKey);
        var unavailable = new ActionAvailability(false, "availability.no_selection");
        Xunit.Assert.False(unavailable.IsAvailable);
        Xunit.Assert.Equal("availability.no_selection", unavailable.ReasonKey);
        Xunit.Assert.Throws<ArgumentException>(() => new ActionAvailability(true, "availability.contradiction"));
        Xunit.Assert.Throws<ArgumentNullException>(() => new ActionAvailability(false));
        Xunit.Assert.Throws<ArgumentException>(() => new ActionAvailability(false, "bad\tkey"));
        Xunit.Assert.Throws<ArgumentException>(() => new ActionAvailability(false, new string('r', 161)));
    }

    [Xunit.Fact]
    public void BusyStateAndShutdownSummaryCannotContradictThemselves()
    {
        Xunit.Assert.Equal(HostBusyKind.Idle, new HostBusyState(HostBusyKind.Idle, 0).Kind);
        Xunit.Assert.Equal(2, new HostBusyState(HostBusyKind.LocalWork, 2, "busy.local").ActiveLocalOperations);
        Xunit.Assert.Throws<ArgumentOutOfRangeException>(() => new HostBusyState(HostBusyKind.None, 0));
        Xunit.Assert.Throws<ArgumentOutOfRangeException>(() => new HostBusyState((HostBusyKind)99, 0));
        Xunit.Assert.Throws<ArgumentOutOfRangeException>(() => new HostBusyState(HostBusyKind.LocalWork, -1));
        Xunit.Assert.Throws<ArgumentException>(() => new HostBusyState(HostBusyKind.LocalWork, 0));
        Xunit.Assert.Throws<ArgumentException>(() => new HostBusyState(HostBusyKind.Idle, 1));
        Xunit.Assert.Throws<ArgumentException>(() => new HostBusyState(HostBusyKind.AwaitingRemote, 3));
        Xunit.Assert.Throws<ArgumentException>(() => new HostBusyState(HostBusyKind.Idle, 0, "bad\nkey"));

        var closable = new AssistantShutdownSummary(true, 0, []);
        Xunit.Assert.True(closable.CanClose);
        var refused = new AssistantShutdownSummary(false, 2, ["shutdown.local_work"]);
        Xunit.Assert.Equal(["shutdown.local_work"], refused.RefusalMessageKeys);
        Xunit.Assert.Throws<ArgumentException>(() => new AssistantShutdownSummary(true, 0, ["shutdown.local_work"]));
        Xunit.Assert.Throws<ArgumentException>(() => new AssistantShutdownSummary(false, 1, []));
        Xunit.Assert.Throws<ArgumentOutOfRangeException>(() => new AssistantShutdownSummary(true, -1, []));
        Xunit.Assert.Throws<ArgumentException>(() => new AssistantShutdownSummary(false, 1, [""]));
        Xunit.Assert.Throws<ArgumentNullException>(() => new AssistantShutdownSummary(true, 0, null!));
    }

    [Xunit.Fact]
    public void GrantsAndHandlesCarryTheirOwnerAndRefuseEmptyOrUnpermissionedValues()
    {
        var owner = TestData.Host();
        var reference = TestData.Reference();
        Xunit.Assert.Throws<ArgumentException>(() => new HostFileGrant(owner, Guid.Empty, true, false));
        Xunit.Assert.Throws<ArgumentException>(() => new HostFileGrant(owner, Guid.NewGuid(), false, false));
        Xunit.Assert.Throws<ArgumentNullException>(() => new HostFileGrant(null!, Guid.NewGuid(), true, false));
        var file = new HostFileGrant(owner, Guid.NewGuid(), true, false);
        Xunit.Assert.True(file.CanRead);
        Xunit.Assert.False(file.CanWrite);
        Xunit.Assert.Equal(owner, file.Owner);

        Xunit.Assert.Throws<ArgumentException>(() => new HostResourceReadGrant(owner, Guid.Empty, reference));
        Xunit.Assert.Throws<ArgumentNullException>(() => new HostResourceReadGrant(owner, Guid.NewGuid(), null!));
        Xunit.Assert.Throws<ArgumentNullException>(() => new HostResourceReadGrant(null!, Guid.NewGuid(), reference));
        var read = new HostResourceReadGrant(owner, Guid.NewGuid(), reference);
        Xunit.Assert.NotSame(reference, read.Resource);

        Xunit.Assert.Throws<ArgumentException>(() => new AssistantSecretHandle(owner, Guid.Empty));
        Xunit.Assert.Throws<ArgumentNullException>(() => new AssistantSecretHandle(null!, Guid.NewGuid()));
        Xunit.Assert.Equal(owner, new AssistantSecretHandle(owner, Guid.NewGuid()).Owner);
    }

    [Xunit.Fact]
    public void ResolvedResourcePreviewAndSaveReceiptAreBoundToTheirResource()
    {
        var owner = TestData.Host();
        var reference = TestData.Reference();
        var grant = new HostResourceReadGrant(owner, Guid.NewGuid(), reference);
        var resolved = new ResolvedHostResource(reference, grant, "resource.available");
        Xunit.Assert.Same(grant, resolved.ReadGrant);
        Xunit.Assert.Null(new ResolvedHostResource(reference, null, "resource.unavailable").ReadGrant);
        Xunit.Assert.Throws<ArgumentException>(() => new ResolvedHostResource(TestData.Reference(), grant, "resource.available"));
        Xunit.Assert.Throws<ArgumentException>(() => new ResolvedHostResource(reference, grant, ""));
        Xunit.Assert.Throws<ArgumentNullException>(() => new ResolvedHostResource(null!, null, "resource.available"));

        Xunit.Assert.Equal(HostPreviewMode.Inline, new HostPreview(reference, HostPreviewMode.Inline, "preview.capture").Mode);
        Xunit.Assert.Throws<ArgumentOutOfRangeException>(() => new HostPreview(reference, HostPreviewMode.None, "preview.capture"));
        Xunit.Assert.Throws<ArgumentOutOfRangeException>(() => new HostPreview(reference, (HostPreviewMode)42, "preview.capture"));
        Xunit.Assert.Throws<ArgumentException>(() => new HostPreview(reference, HostPreviewMode.Inline, "a\nb"));
        Xunit.Assert.Throws<ArgumentNullException>(() => new HostPreview(null!, HostPreviewMode.Inline, "preview.capture"));

        var receipt = new HostSaveReceipt(Guid.NewGuid(), reference);
        Xunit.Assert.Same(reference, receipt.SavedResource);
        Xunit.Assert.Throws<ArgumentException>(() => new HostSaveReceipt(Guid.Empty, reference));
        Xunit.Assert.Throws<ArgumentNullException>(() => new HostSaveReceipt(Guid.NewGuid(), null!));
    }

    [Xunit.Fact]
    public void ByteRangesAttentionAndAccessibilityValuesAreBounded()
    {
        Xunit.Assert.Equal(0, new HostByteRange(0, null).Offset);
        Xunit.Assert.Equal(16L, new HostByteRange(4, 16).Length);
        Xunit.Assert.Throws<ArgumentOutOfRangeException>(() => new HostByteRange(-1, null));
        Xunit.Assert.Throws<ArgumentOutOfRangeException>(() => new HostByteRange(0, -1));

        Xunit.Assert.Equal("attention.sample", new AssistantAttentionRequest("attention.sample", "attention.message").AttentionId);
        Xunit.Assert.Throws<ArgumentException>(() => new AssistantAttentionRequest("", "attention.message"));
        Xunit.Assert.Throws<ArgumentException>(() => new AssistantAttentionRequest("attention.sample", new string('m', 161)));
        Xunit.Assert.Throws<ArgumentException>(() => new AssistantAttention("a\0", "m", DateTimeOffset.UnixEpoch));
        Xunit.Assert.Equal("m", new AssistantAttention("a", "m", DateTimeOffset.UnixEpoch).MessageKey);

        Xunit.Assert.Equal(2.0, new HostAccessibilityPreferences(true, true, 2.0).TextScale);
        foreach (double invalid in new[] { 0.0, 0.49, 4.01, double.NaN, double.PositiveInfinity, double.NegativeInfinity })
        {
            Xunit.Assert.Throws<ArgumentOutOfRangeException>(() => new HostAccessibilityPreferences(false, false, invalid));
        }
    }

    [Xunit.Fact]
    public void HostOptionsValidateNamesIconsModesAndDeriveTheProductDataRoot()
    {
        var owner = TestData.Host();
        var options = TestData.Options(owner);
        Xunit.Assert.Same(AssistantProductIdentity.ArcScope, options.Product);
        Xunit.Assert.Equal(AssistantDataRoot.ForApplication(TestData.PlatformRoot, owner.Installation).InstallationDirectory,
            options.DataRoot.InstallationDirectory);
        Xunit.Assert.Equal(new AssistantStorePartition(owner.Installation, TestData.Profile), options.InitialStorePartition);
        Xunit.Assert.True(options.Supports(AssistantPresentationMode.Docked));
        Xunit.Assert.False(options.Supports(AssistantPresentationMode.Expanded));
        Xunit.Assert.Equal(2, options.AvailablePresentationModes.Count);

        Xunit.Assert.Throws<ArgumentException>(() => TestData.Options(owner, default(AssistantProfileId)));
        Xunit.Assert.Throws<ArgumentException>(() => TestData.Options(owner, modes: []));
        Xunit.Assert.Throws<ArgumentException>(() => TestData.Options(owner, modes: [AssistantPresentationMode.None]));
        Xunit.Assert.Throws<ArgumentException>(() => TestData.Options(owner, modes: [(AssistantPresentationMode)77]));
        Xunit.Assert.Throws<ArgumentException>(() => TestData.Options(owner,
            modes: [AssistantPresentationMode.Docked, AssistantPresentationMode.Docked]));
        Xunit.Assert.Throws<ArgumentException>(() => new AssistantHostOptions(owner, TestData.Profile, "relative", "Name", "icon.key",
            [AssistantPresentationMode.Docked]));
        Xunit.Assert.Throws<ArgumentException>(() => new AssistantHostOptions(owner, TestData.Profile, TestData.PlatformRoot,
            new string('n', 121), "icon.key", [AssistantPresentationMode.Docked]));
        Xunit.Assert.Throws<ArgumentException>(() => new AssistantHostOptions(owner, TestData.Profile, TestData.PlatformRoot,
            "Name", "file:///etc/passwd", [AssistantPresentationMode.Docked]));
        Xunit.Assert.Throws<ArgumentException>(() => new AssistantHostOptions(owner, TestData.Profile, TestData.PlatformRoot,
            "Name", "icon\nkey", [AssistantPresentationMode.Docked]));
        Xunit.Assert.Throws<ArgumentException>(() => new AssistantHostOptions(owner, TestData.Profile, TestData.PlatformRoot,
            "bad\nname", "icon.key", [AssistantPresentationMode.Docked]));
    }
}
