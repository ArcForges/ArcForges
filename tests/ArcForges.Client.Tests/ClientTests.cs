// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using Google.Protobuf;

namespace ArcForges.Client.Tests;

/// <summary>IDs, command IDs, the reconnect schedule, locations and the endpoint descriptor.</summary>
public sealed class ClientTests
{
    [Fact]
    public void IdTextRoundTripsAndSortsLikeTheBytes()
    {
        var first = CommandIds.New(new FixedClock(new DateTimeOffset(2026, 10, 15, 12, 0, 0, TimeSpan.Zero))).Value.ToByteArray();
        var later = CommandIds.New(new FixedClock(new DateTimeOffset(2026, 10, 15, 12, 0, 1, TimeSpan.Zero))).Value.ToByteArray();
        var text = IdText.Format(first);

        Assert.Equal(26, text.Length);
        Assert.Matches("^[0-7][0-9a-hjkmnp-tv-z]{25}$", text);
        Assert.True(IdText.TryParse(text, out var parsed));
        Assert.Equal(first, parsed);
        Assert.True(IdText.TryParse(text.ToUpperInvariant(), out var upper));
        Assert.Equal(first, upper);
        Assert.True(string.CompareOrdinal(text, IdText.Format(later)) < 0);
        Assert.False(IdText.TryParse(text[..25], out _));
        Assert.False(IdText.TryParse("8" + text[1..], out _));
    }

    [Fact]
    public void IdPrefixesNormalizeConfusableCharacters()
    {
        Assert.True(IdText.TryNormalizePrefix("01M4ZRIO", out var normalized));
        Assert.Equal("01m4zr10", normalized);
        Assert.False(IdText.TryNormalizePrefix("01m4u!", out _));
    }

    [Fact]
    public void CommandIdsAreVersion7AndUniquePerAction()
    {
        var ids = Enumerable.Range(0, 1000).Select(_ => CommandIds.New().Value.ToByteArray()).ToList();

        Assert.All(ids, id => Assert.Equal(0x70, id[6] & 0xF0));
        Assert.All(ids, id => Assert.Equal(0x80, id[8] & 0xC0));
        Assert.Equal(ids.Count, ids.Select(Convert.ToHexString).Distinct().Count());
    }

    [Fact]
    public void ARetriedActionResendsTheIdenticalBytesWithTheSameCommandId()
    {
        var request = new NodeServiceRenameNodeRequest { Meta = new RequestMeta { CorrelationId = CommandIds.New() }, Name = "build box" };
        var action = CommandIds.Begin(request, r => r.Meta, (r, m) => r.Meta = m);
        var first = action.RequestForAttempt().ToByteArray();
        var second = action.RequestForAttempt().ToByteArray();

        Assert.Equal(first, second);
        Assert.Equal(action.Bytes.ToArray(), first);
        Assert.Equal(16, request.Meta.CommandId.Value.Length);
        Assert.Equal(2, action.Attempts);

        // A request changed after it was prepared is never sent under the same command ID.
        request.Name = "other";
        Assert.Throws<InvalidOperationException>(action.RequestForAttempt);
    }

    [Fact]
    public void MapOrderIsPartOfTheBytesThatAreResent()
    {
        // The node's payload digest covers wire bytes, so a retry must send the same instance, not a rebuilt one.
        var metric = new HealthMetric { Name = "m" };
        metric.Labels["b"] = "2";
        metric.Labels["a"] = "1";
        var reordered = new HealthMetric { Name = "m" };
        reordered.Labels["a"] = "1";
        reordered.Labels["b"] = "2";

        Assert.NotEqual(metric.ToByteArray(), reordered.ToByteArray());
        Assert.Equal(metric.ToByteArray(), HealthMetric.Parser.ParseFrom(metric.ToByteArray()).ToByteArray());
    }

    [Theory]
    [InlineData(1, 500)]
    [InlineData(2, 1000)]
    [InlineData(3, 2000)]
    [InlineData(5, 8000)]
    [InlineData(6, 10_000)]
    [InlineData(30, 10_000)]
    public void ReconnectBackoffDoublesFromHalfASecondToTenSecondsWithJitter(int attempt, int ceilingMs)
    {
        Assert.Equal(TimeSpan.FromMilliseconds(ceilingMs), ReconnectBackoff.Ceiling(attempt));
        Assert.Equal(TimeSpan.FromMilliseconds(ceilingMs / 2.0), new ReconnectBackoff(() => 0).Next(attempt));
        Assert.Equal(TimeSpan.FromMilliseconds(ceilingMs), new ReconnectBackoff(() => 1).Next(attempt));
    }

    [Fact]
    public void ConnectionStateReportsEachTransitionOnce()
    {
        var tracker = new ConnectionStateTracker();
        var changes = new List<ConnectionStateChange>();
        tracker.Changed += (_, change) => changes.Add(change);

        Assert.True(tracker.MoveTo(ConnectionState.Connected));
        Assert.False(tracker.MoveTo(ConnectionState.Connected));
        Assert.True(tracker.MoveTo(ConnectionState.Reconnecting));

        Assert.Equal(
            [new ConnectionStateChange(ConnectionState.Connecting, ConnectionState.Connected), new ConnectionStateChange(ConnectionState.Connected, ConnectionState.Reconnecting)],
            changes);
    }

    [Fact]
    public void TestHooksApplyOnlyInTestModeAndNameTheInstanceAfterTheEndpoint()
    {
        var endpoint = OperatingSystem.IsWindows() ? "arcforges-unit-" + Guid.NewGuid().ToString("N")[..8] : "/tmp/arcforges-unit-" + Guid.NewGuid().ToString("N")[..8] + ".sock";
        var previous = Environment.GetEnvironmentVariable(NodeLocations.EndpointVariable);
        Environment.SetEnvironmentVariable(NodeLocations.EndpointVariable, endpoint);
        try
        {
            Assert.Null(NodeLocations.EndpointOverride(testMode: false));
            Assert.Equal(endpoint, NodeLocations.EndpointOverride(testMode: true));
            Assert.Equal(endpoint, NodeLocations.Endpoint(testMode: true, Path.GetTempPath()).Address);
            Assert.NotEqual(endpoint, NodeLocations.Endpoint(testMode: false, Path.GetTempPath()).Address);
            var user = NodeLocations.InstanceKey(testMode: false);
            var test = NodeLocations.InstanceKey(testMode: true);
            Assert.Matches("^[0-9a-f]{32}$", user);
            Assert.StartsWith(user + "-", test, StringComparison.Ordinal);
            Assert.Equal(@"Local\ArcForges.Node." + user, NodeLocations.NodeMutexName(user));
        }
        finally
        {
            Environment.SetEnvironmentVariable(NodeLocations.EndpointVariable, previous);
        }
    }

    [Fact]
    public void TheDefaultEndpointIsThePerUserWellKnownOne()
    {
        var dataRoot = Path.Combine(Path.GetTempPath(), "arcforges-unit-root");
        var endpoint = NodeLocations.Endpoint(testMode: false, dataRoot);
        if (OperatingSystem.IsWindows())
        {
            Assert.Equal("arcforges-" + NodeLocations.InstanceKey(false) + "-node", endpoint.Address);
        }
        else
        {
            var runtime = Environment.GetEnvironmentVariable("XDG_RUNTIME_DIR");
            Assert.Equal(string.IsNullOrEmpty(runtime) ? Path.Combine(dataRoot, "run", "node.sock") : Path.Combine(runtime, "arcforges", "node.sock"), endpoint.Address);
        }
    }

    [Fact]
    public void TheConfiguredDataRootIsReadFromNodeJson()
    {
        var directory = Directory.CreateTempSubdirectory("arcforges-unit-config-");
        try
        {
            var root = Path.Combine(directory.FullName, "data");
            File.WriteAllText(Path.Combine(directory.FullName, "node.json"), "{ \"logLevel\": \"info\", \"dataRoot\": " + System.Text.Json.JsonSerializer.Serialize(root) + " }");
            Assert.Equal(root, NodeLocations.ReadConfiguredDataRoot(Path.Combine(directory.FullName, "node.json")));
            File.WriteAllText(Path.Combine(directory.FullName, "node.json"), "{ \"dataRoot\": \"relative\" }");
            Assert.Null(NodeLocations.ReadConfiguredDataRoot(Path.Combine(directory.FullName, "node.json")));
            File.WriteAllText(Path.Combine(directory.FullName, "node.json"), "not json");
            Assert.Null(NodeLocations.ReadConfiguredDataRoot(Path.Combine(directory.FullName, "node.json")));
        }
        finally
        {
            directory.Delete(recursive: true);
        }
    }

    [Fact]
    public void TheEndpointDescriptorIsWrittenAtomicallyAndNamesALiveProcess()
    {
        var directory = Directory.CreateTempSubdirectory("arcforges-unit-descriptor-");
        try
        {
            var path = Path.Combine(directory.FullName, "run", "endpoint.json");
            var descriptor = new EndpointDescriptor
            {
                Endpoint = "arcforges-x-node",
                Transport = "named-pipe",
                NodeId = IdText.Format(CommandIds.New()),
                ProcessId = Environment.ProcessId,
                ProcessStartUnixMs = EndpointDescriptor.CurrentProcessStartUnixMs(),
                StartedAt = "2026-10-15T12:00:00.000Z",
                ContractMajor = 1,
                ContractMinor = 0,
                Version = "0.1.0-dev",
            };
            descriptor.Write(path);
            var read = EndpointDescriptor.TryRead(path);

            Assert.NotNull(read);
            Assert.Equal(descriptor.Endpoint, read.Endpoint);
            Assert.True(read.ProcessIsAlive());
            Assert.Single(Directory.GetFiles(Path.GetDirectoryName(path)!));

            // A recorded start time that differs means the PID was reused: the descriptor is stale.
            Assert.False(new EndpointDescriptor
            {
                Endpoint = read.Endpoint,
                Transport = read.Transport,
                NodeId = read.NodeId,
                ProcessId = read.ProcessId,
                ProcessStartUnixMs = read.ProcessStartUnixMs - 60_000,
                StartedAt = read.StartedAt,
                ContractMajor = 1,
                ContractMinor = 0,
                Version = "x",
            }.ProcessIsAlive());

            using var exited = Process.Start(new ProcessStartInfo(Environment.ProcessPath!, "--version") { RedirectStandardOutput = true, UseShellExecute = false })!;
            exited.WaitForExit(TimeSpan.FromSeconds(30));
            var dead = new EndpointDescriptor
            {
                Endpoint = read.Endpoint,
                Transport = read.Transport,
                NodeId = read.NodeId,
                ProcessId = exited.Id,
                ProcessStartUnixMs = read.ProcessStartUnixMs,
                StartedAt = read.StartedAt,
                ContractMajor = 1,
                ContractMinor = 0,
                Version = "x",
            };
            Assert.False(dead.ProcessIsAlive());
            File.WriteAllText(path, "{ broken");
            Assert.Null(EndpointDescriptor.TryRead(path));
        }
        finally
        {
            directory.Delete(recursive: true);
        }
    }

    [Fact]
    public void CiMarkersAreReportedAndFalseValuesIgnored()
    {
        var saved = ClientProcess.CiVariables.ToDictionary(name => name, Environment.GetEnvironmentVariable);
        try
        {
            foreach (var name in ClientProcess.CiVariables)
            {
                Environment.SetEnvironmentVariable(name, null);
            }

            Assert.Empty(ClientProcess.CiMarkers());
            Environment.SetEnvironmentVariable("CI", "false");
            Assert.Empty(ClientProcess.CiMarkers());
            Environment.SetEnvironmentVariable("CI", "true");
            Environment.SetEnvironmentVariable("GITHUB_ACTIONS", "true");
            Assert.Equal(["CI", "GITHUB_ACTIONS"], ClientProcess.CiMarkers());
            var hello = ClientProcess.Hello(ClientKind.Cli);
            Assert.Equal(["CI", "GITHUB_ACTIONS"], hello.CiMarkers);
            Assert.Equal(NodeContract.Major, hello.ContractMajor);
            Assert.Equal((uint)Environment.ProcessId, hello.Process.Pid);
            Assert.Equal(AutoStartOutcome.RefusedInCi, NodeAutoStart.Start(testMode: true).Outcome);
        }
        finally
        {
            foreach (var (name, value) in saved)
            {
                Environment.SetEnvironmentVariable(name, value);
            }
        }
    }

    [Fact]
    public void InstantsConvertBothWays()
    {
        var time = new DateTimeOffset(2026, 10, 15, 12, 34, 56, TimeSpan.Zero).AddTicks(1234567);
        var instant = ProtoTime.ToInstant(time);

        Assert.Equal(time, ProtoTime.ToDateTimeOffset(instant));
        Assert.Equal(DateTimeOffset.UnixEpoch.AddTicks(-1), ProtoTime.ToDateTimeOffset(ProtoTime.ToInstant(DateTimeOffset.UnixEpoch.AddTicks(-1))));
        Assert.Null(ProtoTime.ToDateTimeOffset(null));
        Assert.Null(ProtoTime.ToDateTimeOffset(new Instant()));
    }

    private sealed class FixedClock(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }
}
