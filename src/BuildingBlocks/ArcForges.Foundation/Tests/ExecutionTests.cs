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
