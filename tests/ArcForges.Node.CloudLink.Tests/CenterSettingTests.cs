// SPDX-License-Identifier: AGPL-3.0-only
using System.Text.Json;
using ArcForges.Contracts.Node.V1;
using ArcForges.Node.Core;

namespace ArcForges.Node.CloudLink.Tests;

/// <summary>
/// N1-2 (CTR4-NODE-01/02; N1 decision G-6): the center setting in <c>node.json</c> through the node's settings manager, the code the
/// <c>UpdateNodeSettings</c> handler runs (REAL files). The <c>signing_in</c> refusal of <c>center_url</c> is reached with part N2's sign-in
/// flows (<c>SignInAccountServiceTests.TheCenterUrlIsRefusedWhileSigningInAndAcceptedAfterTheFlowEnds</c>).
/// </summary>
public sealed class CenterSettingTests : IDisposable
{
    private readonly string _root = Directory.CreateTempSubdirectory("arcforges-centersetting-").FullName;
    private readonly NodeLog _log;

    public CenterSettingTests() => _log = new NodeLog(Path.Combine(_root, "logs"), LogLevel.Debug, TimeProvider.System);

    public void Dispose()
    {
        _log.Dispose();
        Directory.Delete(_root, recursive: true);
    }

    [Fact]
    public void UnderTestModeThereIsNoDefaultCenterAndEmptyIsRefused()
    {
        var settings = Manager(centerUrl: null, testMode: true);
        Assert.Null(settings.Center());
        Assert.Equal(string.Empty, settings.Current().CenterUrl);
        var before = File.ReadAllBytes(settings.ConfigPath);
        var (updated, _, error) = settings.Update(null, LogLevel.Unspecified, null, centerUrl: string.Empty);
        Assert.Null(updated);
        Assert.Equal("invalid_argument", error!.Code);
        Assert.Equal(before, File.ReadAllBytes(settings.ConfigPath));

        // Outside --test-mode the official default applies, and empty goes back to it.
        var production = Manager(centerUrl: "https://center.example.test/api", testMode: false);
        Assert.Null(production.Update(null, LogLevel.Unspecified, null, centerUrl: string.Empty).Error);
        Assert.Equal(CenterEndpoint.OfficialDefault, production.Center()!.Url);
    }

    [Fact]
    public void TheTestCenterOverrideRefusesEveryCenterUpdateAndWritesNothing()
    {
        // G-6: while ARCFORGES_TEST_CENTER_URL names the center, it is the effective center and a center_url update is STATE/invalid_state.
        var configured = CenterEndpoint.Parse("https://configured.example.test");
        var hook = CenterEndpoint.Parse("http://127.0.0.1:4100/api");
        var settings = new NodeSettingsManager(Write(configured.Url), _root, _log) { TestMode = true, CenterOverride = hook };
        Assert.Equal(hook, settings.Center());
        Assert.Equal(hook.Url, settings.Current().CenterUrl);
        var before = File.ReadAllBytes(settings.ConfigPath);
        foreach (var value in new[] { "https://other.example.test", configured.Url, hook.Url, string.Empty })
        {
            var (updated, _, error) = settings.Update(null, LogLevel.Unspecified, null, centerUrl: value);
            Assert.Null(updated);
            Assert.Equal("invalid_state", error!.Code);
            Assert.Equal("test_override", error.Details.State.State);
            Assert.Equal(before, File.ReadAllBytes(settings.ConfigPath));
        }
    }

    [Fact]
    public void ACenterUpdateAtAStaleRevisionIsAConflictAndWritesNothing()
    {
        var settings = Manager(centerUrl: "https://center.example.test/api", testMode: false);
        var revision = settings.Current().Revision.Value;
        Assert.Null(settings.Update(revision, LogLevel.Unspecified, null, centerUrl: "https://second.example.test").Error);
        Assert.Equal(revision + 1, settings.Current().Revision.Value);
        var before = File.ReadAllBytes(settings.ConfigPath);
        var (updated, _, error) = settings.Update(revision, LogLevel.Unspecified, null, centerUrl: "https://third.example.test");
        Assert.Null(updated);
        Assert.Equal("revision_conflict", error!.Code);
        Assert.Equal(before, File.ReadAllBytes(settings.ConfigPath));
        Assert.Equal("https://second.example.test", settings.Center()!.Url);
    }

    private NodeSettingsManager Manager(string? centerUrl, bool testMode) => new(Write(centerUrl), _root, _log) { TestMode = testMode };

    private string Write(string? centerUrl)
    {
        var path = Path.Combine(_root, "config-" + Guid.NewGuid().ToString("N"), "node.json");
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.WriteAllText(path, "{ \"dataRoot\": " + JsonSerializer.Serialize(_root)
            + (centerUrl is null ? string.Empty : ", \"centerUrl\": " + JsonSerializer.Serialize(centerUrl)) + " }");
        return path;
    }
}
