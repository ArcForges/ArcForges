// SPDX-License-Identifier: AGPL-3.0-only

using ArcForges.Contracts.Foundation.V1;
using ArcForges.Foundation.Errors;
using ArcForges.Foundation.Execution;
using ArcForges.Foundation.Versions;
using Xunit;

namespace ArcForges.Foundation.Tests;

public sealed class ContractCoverageTests
{
    [Fact]
    public void FactoriesProduceNondefaultIndependentIdentifiers()
    {
        Guid[] ids =
        [
            IdentityGeneration.NewRealm().Value, IdentityGeneration.NewUser().Value,
            IdentityGeneration.NewWorkspace().Value, IdentityGeneration.NewDevice().Value,
            IdentityGeneration.NewInstallation().Value, IdentityGeneration.NewInstance().Value,
            IdentityGeneration.NewCommand().Value, IdentityGeneration.NewCorrelation().Value,
            IdentityGeneration.NewResource().Value, IdentityGeneration.NewBlob().Value,
            IdentityGeneration.NewArtifact().Value, IdentityGeneration.NewContentOrigin().Value,
            IdentityGeneration.NewContentUnit().Value, IdentityGeneration.NewConflict().Value,
            IdentityGeneration.NewDelegation().Value,
        ];
        Assert.DoesNotContain(Guid.Empty, ids);
        Assert.Equal(ids.Length, ids.Distinct().Count());
    }

    [Fact]
    public void KnownEffectAndReasonLookupRefuseUnknownValues()
    {
        Assert.True(WireValues.IsKnownEffect(EffectCertainty.Happened));
        Assert.False(WireValues.IsKnownEffect(EffectCertainty.Unspecified));
        Assert.False(WireValues.IsKnownEffect((EffectCertainty)999));
        Assert.True(ReasonCodes.TryGet("validation.invalid_request", out var reason));
        Assert.Equal(ReasonCodes.Get("validation.invalid_request"), reason);
        Assert.False(ReasonCodes.TryGet("future.unknown", out _));
        Assert.True(new Instant(0, 1).CompareTo(new Instant(0, 2)) < 0);
        Assert.True(new Instant(1, 0).CompareTo(new Instant(0, 999)) > 0);
    }
    [Fact]
    public void AttemptIdCodecKeepsIdentityAndRefusesInvalidWire()
    {
        var value = ArcForges.Foundation.Execution.AttemptId.New();
        Assert.NotEqual(Guid.Empty, value.Value);
        Assert.Equal(value, ArcForges.Foundation.Execution.AttemptId.FromWire(value.ToWire()));
        Assert.Throws<ArgumentException>(() => ArcForges.Foundation.Execution.AttemptId.FromWire(new Id()));
        Assert.Throws<ArgumentException>(() => default(ArcForges.Foundation.Execution.AttemptId).ToWire());
    }

    [Fact]
    public void ChatTurnIdCodecKeepsIdentityAndRefusesInvalidWire()
    {
        var value = ArcForges.Foundation.Execution.ChatTurnId.New();
        Assert.NotEqual(Guid.Empty, value.Value);
        Assert.Equal(value, ArcForges.Foundation.Execution.ChatTurnId.FromWire(value.ToWire()));
        Assert.Throws<ArgumentException>(() => ArcForges.Foundation.Execution.ChatTurnId.FromWire(new Id()));
        Assert.Throws<ArgumentException>(() => default(ArcForges.Foundation.Execution.ChatTurnId).ToWire());
    }

    [Fact]
    public void InvocationIdCodecKeepsIdentityAndRefusesInvalidWire()
    {
        var value = ArcForges.Foundation.Execution.InvocationId.New();
        Assert.NotEqual(Guid.Empty, value.Value);
        Assert.Equal(value, ArcForges.Foundation.Execution.InvocationId.FromWire(value.ToWire()));
        Assert.Throws<ArgumentException>(() => ArcForges.Foundation.Execution.InvocationId.FromWire(new Id()));
        Assert.Throws<ArgumentException>(() => default(ArcForges.Foundation.Execution.InvocationId).ToWire());
    }

    [Fact]
    public void RunIdCodecKeepsIdentityAndRefusesInvalidWire()
    {
        var value = ArcForges.Foundation.Execution.RunId.New();
        Assert.NotEqual(Guid.Empty, value.Value);
        Assert.Equal(value, ArcForges.Foundation.Execution.RunId.FromWire(value.ToWire()));
        Assert.Throws<ArgumentException>(() => ArcForges.Foundation.Execution.RunId.FromWire(new Id()));
        Assert.Throws<ArgumentException>(() => default(ArcForges.Foundation.Execution.RunId).ToWire());
    }

    [Fact]
    public void SessionIdCodecKeepsIdentityAndRefusesInvalidWire()
    {
        var value = ArcForges.Foundation.Execution.SessionId.New();
        Assert.NotEqual(Guid.Empty, value.Value);
        Assert.Equal(value, ArcForges.Foundation.Execution.SessionId.FromWire(value.ToWire()));
        Assert.Throws<ArgumentException>(() => ArcForges.Foundation.Execution.SessionId.FromWire(new Id()));
        Assert.Throws<ArgumentException>(() => default(ArcForges.Foundation.Execution.SessionId).ToWire());
    }

    [Fact]
    public void StepIdCodecKeepsIdentityAndRefusesInvalidWire()
    {
        var value = ArcForges.Foundation.Execution.StepId.New();
        Assert.NotEqual(Guid.Empty, value.Value);
        Assert.Equal(value, ArcForges.Foundation.Execution.StepId.FromWire(value.ToWire()));
        Assert.Throws<ArgumentException>(() => ArcForges.Foundation.Execution.StepId.FromWire(new Id()));
        Assert.Throws<ArgumentException>(() => default(ArcForges.Foundation.Execution.StepId).ToWire());
    }

    [Fact]
    public void TaskIdCodecKeepsIdentityAndRefusesInvalidWire()
    {
        var value = ArcForges.Foundation.Execution.TaskId.New();
        Assert.NotEqual(Guid.Empty, value.Value);
        Assert.Equal(value, ArcForges.Foundation.Execution.TaskId.FromWire(value.ToWire()));
        Assert.Throws<ArgumentException>(() => ArcForges.Foundation.Execution.TaskId.FromWire(new Id()));
        Assert.Throws<ArgumentException>(() => default(ArcForges.Foundation.Execution.TaskId).ToWire());
    }

    [Fact]
    public void AppVersionTryParseRefusesMalformedAndRoundTripsValidInput()
    {
        Assert.True(AppVersion.TryParse("1.2.3", out var value));
        Assert.Equal(AppVersion.Parse("1.2.3"), value);
        Assert.False(AppVersion.TryParse("invalid", out _));
        Assert.False(AppVersion.TryParse(null, out _));
        Assert.Equal("1.2.3", value.ToString());
    }

    [Fact]
    public void ContractSetTryParseRefusesMalformedAndRoundTripsValidInput()
    {
        Assert.True(ContractSet.TryParse("1.2.3", out var value));
        Assert.Equal(ContractSet.Parse("1.2.3"), value);
        Assert.False(ContractSet.TryParse("invalid", out _));
        Assert.False(ContractSet.TryParse(null, out _));
        Assert.Equal("1.2.3", value.ToString());
    }

    [Fact]
    public void CapabilityVersionTryParseRefusesMalformedAndRoundTripsValidInput()
    {
        Assert.True(CapabilityVersion.TryParse("1.2.3", out var value));
        Assert.Equal(CapabilityVersion.Parse("1.2.3"), value);
        Assert.False(CapabilityVersion.TryParse("invalid", out _));
        Assert.False(CapabilityVersion.TryParse(null, out _));
        Assert.Equal("1.2.3", value.ToString());
    }

    [Fact]
    public void NativeFormatVersionTryParseRefusesMalformedAndRoundTripsValidInput()
    {
        Assert.True(NativeFormatVersion.TryParse("1.2.3", out var value));
        Assert.Equal(NativeFormatVersion.Parse("1.2.3"), value);
        Assert.False(NativeFormatVersion.TryParse("invalid", out _));
        Assert.False(NativeFormatVersion.TryParse(null, out _));
        Assert.Equal("1.2.3", value.ToString());
    }

    [Fact]
    public void NativeAbiVersionTryParseRefusesMalformedAndRoundTripsValidInput()
    {
        Assert.True(NativeAbiVersion.TryParse("1.2.3", out var value));
        Assert.Equal(NativeAbiVersion.Parse("1.2.3"), value);
        Assert.False(NativeAbiVersion.TryParse("invalid", out _));
        Assert.False(NativeAbiVersion.TryParse(null, out _));
        Assert.Equal("1.2.3", value.ToString());
    }

    [Fact]
    public void PolicySchemaVersionTryParseRefusesMalformedAndRoundTripsValidInput()
    {
        Assert.True(PolicySchemaVersion.TryParse("1.2.3", out var value));
        Assert.Equal(PolicySchemaVersion.Parse("1.2.3"), value);
        Assert.False(PolicySchemaVersion.TryParse("invalid", out _));
        Assert.False(PolicySchemaVersion.TryParse(null, out _));
        Assert.Equal("1.2.3", value.ToString());
    }

    [Fact]
    public void ExtensionProtocolVersionTryParseRefusesMalformedAndRoundTripsValidInput()
    {
        Assert.True(ExtensionProtocolVersion.TryParse("1.2.3", out var value));
        Assert.Equal(ExtensionProtocolVersion.Parse("1.2.3"), value);
        Assert.False(ExtensionProtocolVersion.TryParse("invalid", out _));
        Assert.False(ExtensionProtocolVersion.TryParse(null, out _));
        Assert.Equal("1.2.3", value.ToString());
    }

    [Fact]
    public void PackageVersionTryParseRefusesMalformedAndRoundTripsValidInput()
    {
        Assert.True(PackageVersion.TryParse("1.2.3", out var value));
        Assert.Equal(PackageVersion.Parse("1.2.3"), value);
        Assert.False(PackageVersion.TryParse("invalid", out _));
        Assert.False(PackageVersion.TryParse(null, out _));
        Assert.Equal("1.2.3", value.ToString());
    }

    [Fact]
    public void StorageSchemaVersionTryParseRefusesMalformedAndRoundTripsValidInput()
    {
        Assert.True(StorageSchemaVersion.TryParse("3", out var value));
        Assert.Equal(StorageSchemaVersion.Parse("3"), value);
        Assert.False(StorageSchemaVersion.TryParse("invalid", out _));
        Assert.False(StorageSchemaVersion.TryParse(null, out _));
        Assert.Equal("3", value.ToString());
    }

}

