// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Contracts.Foundation.Values;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Foundation.Errors;
using ArcForges.Foundation.Execution;
using Xunit;

namespace ArcForges.Foundation.Tests;

public sealed class ExecutionTests
{
    private static readonly Guid ScopeId = Guid.Parse("00112233-4455-6677-8899-aabbccddeeff");

    [Fact]
    public void RetryPreservesCommandAndAllocatesOnlyAnAuthorizedAttempt()
    {
        var identity = new ExecutionIdentity(ExecutionOwner.ForTask(TaskId.New()), IdentityGeneration.NewCommand(),
            InvocationId.New(), RunId.New(), StepId.New(), AttemptId.New());
        var retry = identity.Retry(EffectCertainty.DidNotHappen, RetryMode.SameCommand);
        Assert.Equal(identity.Command, retry.Command);
        Assert.Equal(identity.Invocation, retry.Invocation);
        Assert.Equal(identity.Owner, retry.Owner);
        Assert.Equal(identity.Run, retry.Run);
        Assert.Equal(identity.Step, retry.Step);
        Assert.NotEqual(identity.Attempt, retry.Attempt);
        Assert.Throws<InvalidOperationException>(() => identity.Retry(EffectCertainty.Unknown, RetryMode.SameCommand));
        Assert.Throws<InvalidOperationException>(() => identity.Retry(EffectCertainty.Happened, RetryMode.SameCommand));
        Assert.Throws<InvalidOperationException>(() => identity.Retry((EffectCertainty)999, RetryMode.SameCommand));
        Assert.Throws<InvalidOperationException>(() => identity.Retry(EffectCertainty.Unknown, RetryMode.Reconcile));
        Assert.Equal(identity.Command, identity.Retry(EffectCertainty.Unknown, RetryMode.Reconcile, reconciliationAuthorized: true).Command);
    }

    [Fact]
    public void OwnerAlternativesAndCancellationRemainDistinct()
    {
        var owner = ExecutionOwner.ForChatTurn(ChatTurnId.New());
        Assert.Null(owner.Task);
        Assert.NotNull(owner.ChatTurn);
        Assert.Throws<ArgumentException>(() => ExecutionOwner.ForTask(default));
        var cancelled = Outcome.Cancelled<int>(EffectCertainty.Unknown);
        Assert.Equal(OutcomeKind.Cancelled, cancelled.Kind);
        Assert.False(cancelled.TryGetFailure(out _));
        Assert.Equal(EffectCertainty.Unknown, cancelled.CancellationEffect);
    }

    [Fact]
    public void CanonicalHashMatchesIndependentUtf8ProfileVector()
    {
        // Fixed preimage written directly from registry-04's profile, independently
        // hashed with PowerShell/System.Security.Cryptography, not this canonicalizer.
        const string canonical = """
            {"actor":"00112233-4455-6677-8899-aabbccddeeff","operation":"Scope.Update","profile":"arcforges.command.v1","realm":"00112233-4455-6677-8899-aabbccddeeff","revisionKind":"cloud","revisionValue":"1","semantic":{"a":null,"wide":"9007199254740993"},"workspace":"00112233-4455-6677-8899-aabbccddeeff"}
            """;
        const string expected = "d7b9a9244885a45919a34fda3b75047c0d2bf4ed5fa3a1e8a9ec58eeacc03e4b";
        Assert.Equal(expected, Convert.ToHexStringLower(System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(canonical))));
        Assert.Equal(expected, Hash("{\"wide\":\"9007199254740993\",\"a\":null}"));
        Assert.Equal("b77b5dca4e94810e8a6e32c373c1962ba4023be6ef43578ee1d03e4ba0a3c990", Hash("{\"wide\":\"9007199254740993\"}"));
        Assert.Equal("544b0734d5df0aa63001508ac16dfad9718618a729dab733ee17ef10f1c09c1d", Hash("{\"wide\":\"9007199254740993\"}", "2"));
    }

    [Fact]
    public void SemanticHashIgnoresObjectOrderingButDistinguishesPresenceAndRevision()
    {
        Assert.Equal(Hash("{\"b\":\"9007199254740993\",\"a\":true}"), Hash("{ \"a\":true, \"b\":\"9007199254740993\" }"));
        Assert.NotEqual(Hash("{}"), Hash("{\"a\":null}"));
        Assert.NotEqual(Hash("{\"a\":null}"), Hash("{\"a\":[]}"));
        Assert.NotEqual(Hash("{}"), Hash("{}", "2"));
        Assert.Throws<ArgumentException>(() => Hash("{\"a\":1,\"a\":2}"));
        Assert.Throws<ArgumentException>(() => Hash("{\"a\":9007199254740993}"));
        Assert.Throws<ArgumentException>(() => Hash("{\"é\":1}"));
    }

    private static string Hash(string semantic, string revision = "1") => CanonicalCommandHash.Compute("Scope.Update",
        new RealmId(ScopeId), new WorkspaceId(ScopeId), new UserId(ScopeId), "cloud", revision, semantic);
}
