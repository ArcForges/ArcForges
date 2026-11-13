// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Client;
using ArcForges.Contracts.Node.V1;
using ArcForges.Node.Core.Security;

namespace ArcForges.Node.Core.Tests;

/// <summary>New file receipt/status caller binding; legacy task/workspace replay rules remain separate.</summary>
public sealed class FileCallerBindingTests
{
    [Fact]
    public void AccountSessionsMayChangeWithinTheSameVerifiedAccount()
    {
        var first = new CenterCaller
        {
            Kind = CenterCallerKind.AccountSession,
            AccountId = CommandIds.New(),
            UserId = CommandIds.New(),
            SessionId = CommandIds.New(),
        };
        var second = first.Clone();
        second.UserId = CommandIds.New();
        second.SessionId = CommandIds.New();
        Assert.True(CenterRouting.SameFileCaller(first, second));
        Assert.False(CenterRouting.SameClass(first, second));
        second.AccountId = CommandIds.New();
        Assert.False(CenterRouting.SameFileCaller(first, second));
        second = first.Clone();
        second.SessionId = null;
        Assert.False(CenterRouting.SameFileCaller(first, second));
    }

    [Fact]
    public void RelaysBindNodeOriginAndTheExactVerifiedLocalSession()
    {
        var first = new CenterCaller
        {
            Kind = CenterCallerKind.NodeRelay,
            AccountId = CommandIds.New(),
            RelayingNodeId = CommandIds.New(),
            LocalOrigin = Origin.Agent,
            LocalSessionId = CommandIds.New(),
        };
        var second = first.Clone();
        Assert.True(CenterRouting.SameFileCaller(first, second));
        second.LocalSessionId = CommandIds.New();
        Assert.False(CenterRouting.SameFileCaller(first, second));
        Assert.True(CenterRouting.SameClass(first, second));
        second = first.Clone();
        second.RelayingNodeId = CommandIds.New();
        Assert.False(CenterRouting.SameFileCaller(first, second));
        second = first.Clone();
        second.LocalOrigin = Origin.Script;
        Assert.False(CenterRouting.SameFileCaller(first, second));
        second = first.Clone();
        second.AccountId = CommandIds.New();
        Assert.False(CenterRouting.SameFileCaller(first, second));
        second = first.Clone();
        second.LocalSessionId = null;
        Assert.False(CenterRouting.SameFileCaller(first, second));
    }
}
