// SPDX-License-Identifier: AGPL-3.0-only

using ArcForges.Foundation.Versions;
using Xunit;

namespace ArcForges.Foundation.Tests;

public sealed class VersionAxisTests
{
    [Fact]
    public void EveryAxisParsesAndKeepsItsOwnType()
    {
        CheckAxis<AppVersion>(); CheckAxis<ContractSet>(); CheckAxis<CapabilityVersion>();
        CheckAxis<NativeFormatVersion>(); CheckAxis<NativeAbiVersion>(); CheckAxis<PolicySchemaVersion>();
        CheckAxis<ExtensionProtocolVersion>(); CheckAxis<PackageVersion>();
        Assert.Equal(10U, StorageSchemaVersion.Parse("10").Number);
        Assert.True(StorageSchemaVersion.Parse("10") > StorageSchemaVersion.Parse("2"));
        Assert.True(VersionRange<StorageSchemaVersion>.Parse("[2,10)").Contains(new(5)));
        Assert.False(VersionRange<StorageSchemaVersion>.Parse("[2,10)").Contains(new(10)));
        Assert.True(VersionRange<StorageSchemaVersion>.Parse("(,10]").Contains(new(0)));
    }

    private static void CheckAxis<T>() where T : struct, IVersionAxis<T>
    {
        var first = T.Parse("1.2.3");
        Assert.True(first.IsValid);
        Assert.True(first.CompareTo(T.Parse("1.10.0")) < 0);
        Assert.Equal("1.2.3", first.ToString());
        Assert.True(VersionRange<T>.Parse("1.*").Contains(first));
        Assert.True(VersionRange<T>.Parse("1.2.*").Contains(first));
        Assert.False(VersionRange<T>.Parse("1.2.*").Contains(T.Parse("1.3.0")));
        Assert.True(VersionRange<T>.Parse("(,1.2.3]").Contains(first));
        Assert.False(VersionRange<T>.Parse("(1.2.3,)").Contains(first));
        Assert.False(VersionRange<T>.Parse("*").Contains(default));
        Assert.Throws<InvalidOperationException>(() => default(T).CompareTo(first));
    }

    [Theory]
    [InlineData("")]
    [InlineData(" 1.2.3")]
    [InlineData("01.2.3")]
    [InlineData("1.2.3.4")]
    [InlineData("1.2.3-")]
    [InlineData("1.2.3+")]
    [InlineData("1.2.3-01")]
    [InlineData("1.2.3-a..b")]
    [InlineData("1.2.3+bad+more")]
    [InlineData("4294967296")]
    public void InvalidSemanticVersionsRefuse(string text)
    {
        Assert.False(AppVersion.TryParse(text, out var value));
        Assert.False(value.IsValid);
        Assert.Throws<FormatException>(() => AppVersion.Parse(text));
    }

    [Theory]
    [InlineData("1.0")]
    [InlineData("1-beta")]
    [InlineData("1+build")]
    [InlineData("01")]
    [InlineData("-1")]
    [InlineData(" 1")]
    public void MigrationVersionIsAnIntegerNotASemanticRelease(string text) => Assert.False(StorageSchemaVersion.TryParse(text, out _));

    [Fact]
    public void SemanticOrderingUsesNumericPrereleaseAndIgnoresBuildMetadata()
    {
        string[] ordered = ["1.0.0-alpha", "1.0.0-alpha.1", "1.0.0-alpha.beta", "1.0.0-beta", "1.0.0-beta.2", "1.0.0-beta.11", "1.0.0-rc.1", "1.0.0"];
        for (var index = 1; index < ordered.Length; index++)
            Assert.True(AppVersion.Parse(ordered[index - 1]) < AppVersion.Parse(ordered[index]));
        Assert.Equal(0, PackageVersion.Parse("1.2.3+one").CompareTo(PackageVersion.Parse("1.2.3+two")));
        Assert.Equal("1.2.3+one", PackageVersion.Parse("1.2.3+one").ToString());
        Assert.True(AppVersion.Parse("1.0.0-999999999999999999999999999999") > AppVersion.Parse("1.0.0-99999999999999999999999999999"));
    }

    [Fact]
    public void OpenPartialAndExactBoundsRemainExplicit()
    {
        Assert.Equal(AppVersion.Parse("1"), AppVersion.Parse("1.0.0"));
        Assert.True(VersionRange<AppVersion>.Parse("1.2.3").Contains(AppVersion.Parse("1.2.3+build")));
        Assert.False(VersionRange<AppVersion>.Parse("1.*").Contains(AppVersion.Parse("1.0.0-beta")));
        Assert.False(VersionRange<AppVersion>.Parse("1.*").Contains(AppVersion.Parse("2.0.0")));
        Assert.True(VersionRange<AppVersion>.Parse("4294967295.*").Contains(AppVersion.Parse("4294967295.1.2")));
        Assert.Throws<ArgumentException>(() => VersionRange<AppVersion>.Parse("[2,1]"));
        Assert.Throws<ArgumentException>(() => VersionRange<AppVersion>.Parse("(1,1)"));
        Assert.Throws<FormatException>(() => VersionRange<AppVersion>.Parse("[,1]"));
        Assert.Throws<FormatException>(() => VersionRange<AppVersion>.Parse("1.2.3.*"));
        Assert.Throws<FormatException>(() => VersionRange<StorageSchemaVersion>.Parse("1.*"));
        Assert.Throws<ArgumentException>(() => new VersionRange<AppVersion>(default(AppVersion), true, null, false));
    }
}
