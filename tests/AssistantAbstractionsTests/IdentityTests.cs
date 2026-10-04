// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Assistant.Abstractions;
using ArcForges.Contracts.Foundation.Values;

namespace AssistantAbstractionsTests;

public sealed class IdentityTests
{
    [Xunit.Fact]
    public void ProductIdentityIsAClosedSetOfExactIdentifiers()
    {
        Xunit.Assert.Same(AssistantProductIdentity.ArcScope, AssistantProductIdentity.Parse("arcscope"));
        Xunit.Assert.Same(AssistantProductIdentity.Companion, AssistantProductIdentity.Parse("companion"));
        Xunit.Assert.NotEqual(AssistantProductIdentity.ArcScope, AssistantProductIdentity.Companion);
        foreach (string invalid in new[] { "", " ", "ArcScope", "arcscope ", "companion-android", "companion-web", "arcscope-v2", "hub" })
        {
            Xunit.Assert.Throws<ArgumentException>(() => AssistantProductIdentity.Parse(invalid));
        }

        Xunit.Assert.Throws<ArgumentException>(() => AssistantProductIdentity.Parse(null!));
    }

    [Xunit.Fact]
    public void InstallationAndHostIdentityRejectUninitializedValuesAndComposeByValue()
    {
        Xunit.Assert.Throws<ArgumentException>(() => new AssistantInstallationIdentity(AssistantProductIdentity.ArcScope, default));
        Xunit.Assert.Throws<ArgumentNullException>(() => new AssistantInstallationIdentity(null!,
            new InstallationId(Guid.NewGuid())));
        var installation = TestData.Installed();
        Xunit.Assert.Throws<ArgumentException>(() => new AssistantHostIdentity(installation, default, 1));
        Xunit.Assert.Throws<ArgumentOutOfRangeException>(() => new AssistantHostIdentity(installation,
            new InstanceId(Guid.NewGuid()), 0));

        var identity = TestData.Host(installation);
        Xunit.Assert.Equal(TestData.Host(TestData.Installed()), identity);
        Xunit.Assert.Same(installation.Product, identity.Product);
        Xunit.Assert.NotEqual(identity, TestData.Host(installation, instance: 2));
        Xunit.Assert.NotEqual(identity, TestData.Host(installation, epoch: 8));
        Xunit.Assert.NotEqual(identity, TestData.Host(TestData.Installed(installation: 2)));
        Xunit.Assert.NotEqual(identity, TestData.Host(TestData.Installed(AssistantProductIdentity.Companion)));
    }

    [Xunit.Fact]
    public void ProfileIdentityIsNeverEmptyAndGeneratedProfilesAreDistinct()
    {
        Xunit.Assert.Throws<ArgumentException>(() => new AssistantProfileId(Guid.Empty));
        Xunit.Assert.Throws<ArgumentException>(() => new AssistantWindowId(Guid.Empty));
        Xunit.Assert.Throws<ArgumentException>(() => new AssistantConversationId(Guid.Empty));
        Xunit.Assert.Throws<ArgumentException>(() => new ContextSelectionId(Guid.Empty));

        Guid[] generated =
        [
            AssistantProfileId.New().Value, AssistantProfileId.New().Value,
            AssistantWindowId.New().Value, AssistantWindowId.New().Value,
            AssistantConversationId.New().Value, AssistantConversationId.New().Value,
            ContextSelectionId.New().Value, ContextSelectionId.New().Value,
        ];
        Xunit.Assert.All(generated, value => Xunit.Assert.NotEqual(Guid.Empty, value));
        Xunit.Assert.Equal(generated.Length, generated.Distinct().Count());
    }

    [Xunit.Fact]
    public void StorePartitionsDifferByProductInstallationAndProfile()
    {
        var arc1 = TestData.Installed(AssistantProductIdentity.ArcScope, 1);
        var arc2 = TestData.Installed(AssistantProductIdentity.ArcScope, 2);
        var companion1 = TestData.Installed(AssistantProductIdentity.Companion, 1);

        var baseline = new AssistantStorePartition(arc1, TestData.Profile);
        Xunit.Assert.Equal(baseline, new AssistantStorePartition(TestData.Installed(), TestData.Profile));
        Xunit.Assert.NotEqual(baseline, new AssistantStorePartition(arc2, TestData.Profile));
        Xunit.Assert.NotEqual(baseline, new AssistantStorePartition(companion1, TestData.Profile));
        Xunit.Assert.NotEqual(baseline, new AssistantStorePartition(arc1, TestData.OtherProfile));
        Xunit.Assert.Same(AssistantProductIdentity.Companion, new AssistantStorePartition(companion1, TestData.Profile).Product);
        Xunit.Assert.Throws<ArgumentNullException>(() => new AssistantStorePartition(null!, TestData.Profile));
        Xunit.Assert.Throws<ArgumentException>(() => new AssistantStorePartition(arc1, default));
    }

    [Xunit.Fact]
    public void DataRootsAreAbsoluteDisjointAndDerivedOnlyFromTypedIdentities()
    {
        var arc1 = TestData.Installed(AssistantProductIdentity.ArcScope, 1);
        var arc2 = TestData.Installed(AssistantProductIdentity.ArcScope, 2);
        // Same installation GUID under the other product must still be a different directory.
        var companion1 = TestData.Installed(AssistantProductIdentity.Companion, 1);
        var roots = new[] { arc1, arc2, companion1 }
            .Select(installation => AssistantDataRoot.ForApplication(TestData.PlatformRoot, installation)).ToArray();

        Xunit.Assert.All(roots, root => Xunit.Assert.True(Path.IsPathFullyQualified(root.InstallationDirectory)));
        Xunit.Assert.Equal(3, roots.Select(root => root.InstallationDirectory).Distinct(StringComparer.Ordinal).Count());
        foreach (var left in roots)
        {
            foreach (var right in roots.Where(other => !ReferenceEquals(other, left)))
            {
                string prefix = left.InstallationDirectory.TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
                Xunit.Assert.False(right.InstallationDirectory.StartsWith(prefix, StringComparison.Ordinal),
                    "One installation directory must never contain another.");
            }
        }

        string platform = Path.GetFullPath(TestData.PlatformRoot);
        Xunit.Assert.All(roots, root => Xunit.Assert.StartsWith(platform, root.InstallationDirectory, StringComparison.Ordinal));
        Xunit.Assert.Equal(arc1, roots[0].Installation);
        Xunit.Assert.Same(AssistantProductIdentity.Companion, roots[2].Product);

        Xunit.Assert.Throws<ArgumentException>(() => AssistantDataRoot.ForApplication("relative/path", arc1));
        Xunit.Assert.Throws<ArgumentException>(() => AssistantDataRoot.ForApplication("", arc1));
        Xunit.Assert.Throws<ArgumentNullException>(() => AssistantDataRoot.ForApplication(TestData.PlatformRoot, null!));
    }

    [Xunit.Fact]
    public void ProfileDirectoriesStayUnderTheirInstallationAndRefuseAForeignPartition()
    {
        var arc1 = TestData.Installed(AssistantProductIdentity.ArcScope, 1);
        var arc2 = TestData.Installed(AssistantProductIdentity.ArcScope, 2);
        var root1 = AssistantDataRoot.ForApplication(TestData.PlatformRoot, arc1);
        var root2 = AssistantDataRoot.ForApplication(TestData.PlatformRoot, arc2);

        string first = root1.GetProfileDirectory(root1.ForProfile(TestData.Profile));
        string second = root1.GetProfileDirectory(root1.ForProfile(TestData.OtherProfile));
        string foreign = root2.GetProfileDirectory(root2.ForProfile(TestData.Profile));
        Xunit.Assert.NotEqual(first, second);
        Xunit.Assert.NotEqual(first, foreign);
        string installationPrefix = root1.InstallationDirectory + Path.DirectorySeparatorChar;
        Xunit.Assert.StartsWith(installationPrefix, first, StringComparison.Ordinal);
        Xunit.Assert.StartsWith(installationPrefix, second, StringComparison.Ordinal);
        Xunit.Assert.DoesNotContain("..", first, StringComparison.Ordinal);

        Xunit.Assert.Throws<ArgumentException>(() => root1.GetProfileDirectory(root2.ForProfile(TestData.Profile)));
        Xunit.Assert.Throws<ArgumentException>(() => root1.GetProfileDirectory(new AssistantStorePartition(
            TestData.Installed(AssistantProductIdentity.Companion, 1), TestData.Profile)));
        Xunit.Assert.Throws<ArgumentNullException>(() => root1.GetProfileDirectory(null!));
    }
}
