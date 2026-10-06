// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Foundation.Errors;
using ArcForges.Sdk.Contracts.V1;
using Google.Protobuf;
using Xunit;

namespace ArcForges.Capabilities.Tests;

public sealed class InvocationRestoreTests
{
    [Fact]
    public void RestoreResultValidatesExactSchemaBudgetAndVersionWithoutCallingOwner()
    {
        var (binding, result) = Create(InvocationResultVersionKind.Revision);
        var version = InvocationResultVersion.FromRevision(new Revision { Value = 7 });
        Assert.True(binding.RestoreResult(result, version).TryGetValue(out _));
        Assert.False(binding.RestoreResult(null!, version).TryGetValue(out _));
        Assert.False(binding.RestoreResult(result, null!).TryGetValue(out _));
        var missing = result.Clone();
        missing.ClearSchemaId();
        Assert.False(binding.RestoreResult(missing, version).TryGetValue(out _));
        var wrong = result.Clone();
        wrong.SchemaId += ".other";
        Assert.False(binding.RestoreResult(wrong, version).TryGetValue(out _));
        wrong = result.Clone();
        wrong.Value = new StructuredValue();
        Assert.False(binding.RestoreResult(wrong, version).TryGetValue(out _));
        wrong.Value = null;
        Assert.False(binding.RestoreResult(wrong, version).TryGetValue(out _));
        wrong.Value = new StructuredValue { Text = new string('x', 262_145) };
        Assert.False(binding.RestoreResult(wrong, version).TryGetValue(out _));
        Assert.False(binding.RestoreResult(result, InvocationResultVersion.NonVersioned()).TryGetValue(out _));
        Assert.False(binding.RestoreResult(result, InvocationResultVersion.FromNativeContentRev(new NativeContentRev { Value = 7 })).TryGetValue(out _));
        Assert.Throws<ArgumentException>(() => InvocationResultVersion.FromRevision(new Revision()));
        Assert.Throws<ArgumentException>(() => InvocationResultVersion.FromNativeContentRev(new NativeContentRev { Value = 0 }));
    }

    [Fact]
    public void RestoredValuesAreClonedAndRoundTripEveryVersionKind()
    {
        foreach (var kind in new[] { InvocationResultVersionKind.Revision, InvocationResultVersionKind.NativeContentRev, InvocationResultVersionKind.NonVersioned })
        {
            var (binding, result) = Create(kind);
            var version = kind switch
            {
                InvocationResultVersionKind.Revision => InvocationResultVersion.FromRevision(new Revision { Value = 9 }),
                InvocationResultVersionKind.NativeContentRev => InvocationResultVersion.FromNativeContentRev(new NativeContentRev { Value = 11 }),
                _ => InvocationResultVersion.NonVersioned(),
            };
            var persisted = CapabilityResult.Parser.ParseFrom(result.ToByteArray());
            Assert.True(binding.RestoreResult(persisted, version).TryGetValue(out var restored));
            persisted.Value.Text = "changed";
            result.Value.Text = "changed-original";
            var returned = restored!.Result;
            returned.Value.Text = "changed-returned";
            if (version.Revision is { } revision) revision.Value = 99;
            if (version.NativeContentRev is { } native) native.Value = 99;
            var replay = InvocationOutcome.Success(restored);
            Assert.Equal("stored-result", replay.Value!.Result.Value.Text);
            Assert.Equal(kind, replay.Value.Version.Kind);
            Assert.Equal(kind == InvocationResultVersionKind.Revision ? 9L : null, replay.Value.Version.Revision?.Value);
            Assert.Equal(kind == InvocationResultVersionKind.NativeContentRev ? 11UL : null, replay.Value.Version.NativeContentRev?.Value);
        }
    }

    private static (CapabilityInvocationBinding Binding, CapabilityResult Result) Create(InvocationResultVersionKind kind)
    {
        var registry = CapabilityRegistry.CreateInitial();
        const string capability = "IScopeOperations.GetSession";
        var result = new CapabilityResult { SchemaId = registry.Find(capability)!.Descriptor.ResponseSchema, Value = new StructuredValue { Text = "stored-result" } };
        var binding = new CapabilityInvocationBinding<string, string>(registry, capability, kind,
            _ => throw new InvalidOperationException("Restoration must not decode invocation arguments."),
            (_, _, _, _, _) => throw new InvalidOperationException("Restoration must never execute the owner."),
            _ => throw new InvalidOperationException("Restoration must not encode a new owner result."),
            _ => throw new InvalidOperationException("Restoration must not derive a new version."));
        return (binding, result);
    }
}
