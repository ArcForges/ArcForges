// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;

namespace ArcForges.Node.Store.Tests;

[Trait("env", "windows-real")]
[Trait("env", "linux-real")]
public sealed class CenterControlReceiptsTests
{
    [Fact]
    public void ReopeningOwnerSettlesOnlyItsAcceptedCenterControlReceiptsAsUnknown()
    {
        using var root = new TemporaryDataRoot();
        var clock = new ManualClock();
        const string owner = "center-control-owner";
        const string otherOwner = "other-center-control-owner";
        const string priorUnknown = """{"reason":"prior_observation"}""";
        var interrupted = new List<DurableIntent>();
        DurableIntent settled;
        DurableIntent unrelated;
        DurableIntent foreign;
        DurableIntent uncertain;

        using (var store = root.Open(clock))
        using (var commands = Commands(store, owner))
        using (var other = Commands(store, otherOwner))
        {
            foreach (string method in new[] { "BeginConnect", "CancelConnect", "Disconnect", "SignOut" })
            {
                interrupted.Add(Admit(commands, "CenterControlService." + method));
            }

            settled = Admit(commands, "CenterControlService.SignOut");
            _ = commands.SetResult(settled.CommandId, "SUCCEEDED", 2, "{}");
            uncertain = Admit(commands, "CenterControlService.Disconnect");
            _ = commands.SetResult(uncertain.CommandId, "UNKNOWN", 3, priorUnknown);
            unrelated = Admit(commands, "CenterControlService.CancelConnectLater");
            foreign = Admit(other, "CenterControlService.BeginConnect");
        }

        using (var store = root.Open(clock))
        using (var commands = Commands(store, owner))
        using (var other = Commands(store, otherOwner))
        {
            commands.RecoverInterruptedCenterControls();
            commands.RecoverInterruptedCenterControls();
            foreach (var intent in interrupted)
            {
                var replay = commands.Admit(intent);
                Assert.Equal(DurableDecision.InProgress, replay.Decision);
                Assert.Equal("UNKNOWN", replay.Receipt!.State);
                Assert.Equal(3, replay.Receipt.Effect);
                Assert.Equal("""{"code":"outcome_unknown","reason":"center_control_interrupted"}""", replay.Receipt.ResponseJson);
            }

            Assert.Equal("ACCEPTED", commands.Inspect(unrelated.CommandId)!.State);
            Assert.Equal("ACCEPTED", other.Inspect(foreign.CommandId)!.State);
            Assert.Equal("SUCCEEDED", commands.Inspect(settled.CommandId)!.State);
            Assert.Equal(priorUnknown, commands.Inspect(uncertain.CommandId)!.ResponseJson);
        }

        DurableCommandStore Commands(NodeStore store, string id) =>
            new(store, id, NodeSecretStores.ForTestDataRoot(root.Path), new(16, 8, 1024, 65536));
    }

    private static DurableIntent Admit(DurableCommandStore commands, string method)
    {
        var intent = new DurableIntent(RandomNumberGenerator.GetBytes(StoreIds.Length), commands.OwnerEpoch.ToArray(),
            method, null, null, []);
        Assert.Equal(DurableDecision.Execute, commands.Admit(intent).Decision);
        return intent;
    }
}
