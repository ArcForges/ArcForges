// SPDX-License-Identifier: AGPL-3.0-only
using System.Text;
using System.Text.Json;
using ArcForges.Contracts.Node.V1;
using ArcForges.Node.Core.Events;

namespace ArcForges.Node.Core.Tests;

/// <summary>Pure logic: SM-NODE, cursors, configuration and the log's redaction (R-SEC-003, seeded secrets).</summary>
public sealed class UnitTests
{
    public static TheoryData<NodeLifecycleState, NodeLifecycleState, bool> Transitions()
    {
        // machines.json SM-NODE: every (from, to) pair, allowed exactly when the design lists it.
        (NodeLifecycleState, NodeLifecycleState)[] allowed =
        [
            (NodeLifecycleState.Starting, NodeLifecycleState.Recovering),
            (NodeLifecycleState.Recovering, NodeLifecycleState.Ready),
            (NodeLifecycleState.Recovering, NodeLifecycleState.Degraded),
            (NodeLifecycleState.Ready, NodeLifecycleState.Degraded),
            (NodeLifecycleState.Degraded, NodeLifecycleState.Ready),
            (NodeLifecycleState.Ready, NodeLifecycleState.Stopping),
            (NodeLifecycleState.Degraded, NodeLifecycleState.Stopping),
            (NodeLifecycleState.Ready, NodeLifecycleState.Updating),
            (NodeLifecycleState.Degraded, NodeLifecycleState.Updating),
        ];
        var data = new TheoryData<NodeLifecycleState, NodeLifecycleState, bool>();
        var states = Enum.GetValues<NodeLifecycleState>().Where(state => state != NodeLifecycleState.Unspecified).ToArray();
        foreach (var from in states)
        {
            foreach (var to in states)
            {
                data.Add(from, to, allowed.Contains((from, to)));
            }
        }

        return data;
    }

    [Theory]
    [MemberData(nameof(Transitions))]
    public void TheLifecycleFollowsSmNode(NodeLifecycleState from, NodeLifecycleState to, bool allowed) =>
        Assert.Equal(allowed, NodeLifecycle.IsAllowed(from, to));

    [Fact]
    public void ALifecycleRefusesTransitionsOutsideSmNode()
    {
        var lifecycle = new NodeLifecycle();
        Assert.Equal(NodeLifecycleState.Starting, lifecycle.State);
        Assert.Throws<InvalidLifecycleTransitionException>(() => lifecycle.MoveTo(NodeLifecycleState.Ready, "too early"));
        lifecycle.MoveTo(NodeLifecycleState.Recovering, "store_opened");
        lifecycle.MoveTo(NodeLifecycleState.Degraded, "capabilities_observe_only");
        Assert.False(lifecycle.IsStopping);
        lifecycle.MoveTo(NodeLifecycleState.Stopping, "stop_node");
        Assert.True(lifecycle.IsStopping);
        Assert.Equal("stop_node", lifecycle.Reason);
        Assert.Throws<InvalidLifecycleTransitionException>(() => lifecycle.MoveTo(NodeLifecycleState.Ready, "back"));
    }

    [Fact]
    public void CursorsRoundTripAndRejectForeignText()
    {
        var cursor = new EventCursor(3, 1234);
        Assert.Equal("v1.3.1234", cursor.ToString());
        Assert.True(EventCursor.TryParse(cursor.ToString(), out var parsed));
        Assert.Equal(cursor, parsed);
        foreach (var bad in (string?[])[null, "", "v1.3", "v1.0.5", "v2.3.4", "v1.-3.4", "v1.3.4.5", "v1.3.x", "v1." + new string('9', 70)])
        {
            Assert.False(EventCursor.TryParse(bad, out _), bad);
        }
    }

    [Fact]
    public void ConfigurationRoundTripsAndRefusesInvalidFiles()
    {
        var directory = Directory.CreateTempSubdirectory("arcforges-config-tests-");
        try
        {
            var path = Path.Combine(directory.FullName, "node.json");
            Assert.Equal(0, NodeConfiguration.Read(path).Revision);
            NodeConfiguration.Write(path, new NodeConfigurationFile { DataRoot = directory.FullName, LogLevel = "debug", TelemetryOptIn = true, Revision = 4 });
            var read = NodeConfiguration.Read(path);
            Assert.Equal((directory.FullName, "debug", true, 4L), (read.DataRoot, read.LogLevel, read.TelemetryOptIn, read.Revision));
            Assert.Equal(LogLevel.Debug, NodeConfiguration.ParseLogLevel(read.LogLevel));

            foreach (var bad in (string[])["{ \"logLevel\": \"loud\" }", "{ \"dataRoot\": \"relative\" }", "{ \"revision\": -1 }", "[", "null"])
            {
                File.WriteAllText(path, bad);
                Assert.Throws<NodeConfigurationException>(() => NodeConfiguration.Read(path));
            }
        }
        finally
        {
            directory.Delete(recursive: true);
        }
    }

    [Fact]
    public void SeededSecretsNeverReachTheLog()
    {
        // R-SEC-003: field names the Observability redaction processor knows as sensitive are written as [redacted], and an
        // exception is written as its reason code and type, never its message.
        const string Secret = "ghp_s3cr3tV4lu3NeverLogged";
        var line = Encoding.UTF8.GetString(NodeLog.Format(DateTimeOffset.UnixEpoch, LogLevel.Debug, "node.test",
        [
            new("token", Secret),
            new("apiKey", Secret),
            new("password", Secret),
            new("authorization", "Bearer " + Secret),
            new("commandLine", Secret),
            new("prompt", Secret),
            new("environmentPath", Secret),
            new("pid", 42),
            new("state", "ready"),
        ]));

        Assert.DoesNotContain(Secret, line, StringComparison.Ordinal);
        using var document = JsonDocument.Parse(line);
        var fields = document.RootElement.GetProperty("fields");
        Assert.Equal(NodeLog.Redacted, fields.GetProperty("token").GetString());
        Assert.Equal(NodeLog.Redacted, fields.GetProperty("apiKey").GetString());
        Assert.Equal(NodeLog.Redacted, fields.GetProperty("password").GetString());
        Assert.Equal(NodeLog.Redacted, fields.GetProperty("authorization").GetString());
        Assert.Equal(NodeLog.Redacted, fields.GetProperty("prompt").GetString());
        Assert.Equal(NodeLog.Redacted, fields.GetProperty("commandLine").GetString());
        Assert.Equal(NodeLog.Redacted, fields.GetProperty("environmentPath").GetString());
        Assert.Equal(42, fields.GetProperty("pid").GetInt32());
        Assert.Equal("ready", fields.GetProperty("state").GetString());
        Assert.Equal("node.test", document.RootElement.GetProperty("event").GetString());
        Assert.Equal("debug", document.RootElement.GetProperty("level").GetString());
    }

    [Fact]
    public void ExceptionsAreLoggedAsReasonCodesWithoutTheirText()
    {
        var directory = Directory.CreateTempSubdirectory("arcforges-log-tests-");
        try
        {
            using (var log = new NodeLog(directory.FullName, LogLevel.Info))
            {
                log.Error("node.failed", new InvalidOperationException("token=ghp_leaked in a message"));
                log.Debug("node.hidden", new LogField("x", 1));
            }

            var text = File.ReadAllText(Path.Combine(directory.FullName, "node.log"));
            Assert.DoesNotContain("ghp_leaked", text, StringComparison.Ordinal);
            Assert.Contains("\"reason\":\"state.invalid_transition\"", text, StringComparison.Ordinal);
            Assert.Contains("\"errorType\":\"InvalidOperationException\"", text, StringComparison.Ordinal);
            Assert.DoesNotContain("node.hidden", text, StringComparison.Ordinal);
            Assert.Equal("redacted", JsonDocument.Parse(NodeLog.Format(DateTimeOffset.UnixEpoch, LogLevel.Info, "has space", [])).RootElement.GetProperty("event").GetString());
        }
        finally
        {
            directory.Delete(recursive: true);
        }
    }

    [Fact]
    public void TheLogRotatesAndKeepsFiveFiles()
    {
        var directory = Directory.CreateTempSubdirectory("arcforges-log-tests-");
        try
        {
            using (var log = new NodeLog(directory.FullName, LogLevel.Info, maxBytes: 2048, files: 5))
            {
                for (var i = 0; i < 400; i++)
                {
                    log.Info("node.filler", new LogField("i", i), new LogField("text", new string('x', 64)));
                }
            }

            var files = Directory.GetFiles(directory.FullName).Select(Path.GetFileName).Order(StringComparer.Ordinal).ToArray();
            Assert.Equal(["node.1.log", "node.2.log", "node.3.log", "node.4.log", "node.log"], files);
            Assert.All(Directory.GetFiles(directory.FullName), file => Assert.True(new FileInfo(file).Length <= 2048));
            Assert.Contains("\"i\":399", File.ReadAllText(Path.Combine(directory.FullName, "node.log")), StringComparison.Ordinal);
        }
        finally
        {
            directory.Delete(recursive: true);
        }
    }

    [Theory]
    [InlineData("build box", true)]
    [InlineData("x", true)]
    [InlineData("", false)]
    [InlineData("   ", false)]
    [InlineData("tab\tname", false)]
    public void NodeNamesAreOneToSixtyFourPrintableCharacters(string name, bool valid)
    {
        Assert.Equal(valid, NodeName.IsValid(name));
        Assert.True(NodeName.IsValid(new string('n', 64)));
        Assert.False(NodeName.IsValid(new string('n', 65)));
    }
}
