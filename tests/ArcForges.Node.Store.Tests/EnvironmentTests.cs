// SPDX-License-Identifier: AGPL-3.0-only
using System.Text;
using System.Text.Json;
using ArcForges.Contracts.Node.V1;
using ArcForges.Node.Store.Proto;
using Google.Protobuf;

namespace ArcForges.Node.Store.Tests;

/// <summary>R-EXE-017: secret-shaped names, the submitted-environment split and content-addressed env_snapshot rows.</summary>
public sealed class EnvironmentTests
{
    [Theory]
    [InlineData("GITHUB_TOKEN", true)]
    [InlineData("gitlab_token", true)]
    [InlineData("CLAUDE_CODE_MESSAGING_TOKEN", true)]
    [InlineData("DB_PASSWORD", true)]
    [InlineData("MY_SECRET_FILE", true)]
    [InlineData("SIGNING_KEY", true)]
    [InlineData("OPENAI_APIKEY", true)]
    [InlineData("AWS_REGION", true)]
    [InlineData("AZURE_TENANT", true)]
    [InlineData("GH_HOST", true)]
    [InlineData("NPM_TOKEN", true)]
    [InlineData("PATH", false)]
    [InlineData("KEYBOARD_LAYOUT", false)]
    [InlineData("HOME", false)]
    [InlineData("SSH_AUTH_SOCK", false)]
    public void TheDefaultPatternsMatchSecretShapedNamesIgnoringCase(string name, bool secret)
    {
        Assert.Equal(secret, SecretNameMatcher.Default.IsSecret(name));
    }

    [Fact]
    public void ASubmittedEnvironmentSplitsAndRestoresExactly()
    {
        var spec = new TaskSpec
        {
            Command = new CommandSpec { Argv = new ArgvCommand { Argv = { "dotnet", "test" } } },
            WorkingDirectory = "/work",
            Environment = new EnvironmentSpec { Inherit = EnvironmentInherit.Caller, Unset = { "DOTNET_ROOT" } },
            Title = "dotnet test",
        };
        spec.Environment.CallerEnvironment.Add(new Dictionary<string, string>
        {
            ["PATH"] = "/usr/bin:/bin",
            ["GITHUB_TOKEN"] = "synthetic-token-value",
            ["HOME"] = "/home/user",
            ["AWS_PROFILE"] = "synthetic",
        });
        spec.Environment.Set.Add(new Dictionary<string, string> { ["NPM_TOKEN"] = "synthetic-npm", ["CI"] = "1" });

        var split = SubmittedEnvironment.Split(spec, SecretNameMatcher.Default);

        Assert.Empty(split.RedactedSpec.Environment.CallerEnvironment);
        Assert.Equal(["CI"], split.RedactedSpec.Environment.Set.Keys);
        Assert.Equal(["DOTNET_ROOT"], split.RedactedSpec.Environment.Unset);
        Assert.DoesNotContain("synthetic", Encoding.UTF8.GetString(split.RedactedSpec.ToByteArray()), StringComparison.Ordinal);
        Assert.Equal(["HOME", "PATH"], split.Snapshot!.Entries.Select(entry => entry.Name));
        Assert.Equal(["AWS_PROFILE", "GITHUB_TOKEN"], split.Snapshot.SealedNames);
        Assert.DoesNotContain("synthetic", Encoding.UTF8.GetString(split.Snapshot.ToByteArray()), StringComparison.Ordinal);
        Assert.Equal(["AWS_PROFILE", "GITHUB_TOKEN"], split.Secrets!.Caller.Select(entry => entry.Name));
        Assert.Equal(["NPM_TOKEN"], split.Secrets.Set.Select(entry => entry.Name));
        Assert.Equal(["AWS_PROFILE", "GITHUB_TOKEN", "NPM_TOKEN"], split.SealedNames);

        Assert.Equal(spec, SubmittedEnvironment.Restore(split.RedactedSpec, split.Snapshot, split.Secrets));
    }

    [Fact]
    public void ASpecWithoutSecretsHasNothingToSeal()
    {
        var spec = new TaskSpec { Environment = new EnvironmentSpec { Inherit = EnvironmentInherit.Node } };
        spec.Environment.Set["CI"] = "1";

        var split = SubmittedEnvironment.Split(spec, SecretNameMatcher.Default);

        Assert.Null(split.Snapshot);
        Assert.Null(split.Secrets);
        Assert.Empty(split.SealedNames);
        Assert.Equal(spec, SubmittedEnvironment.Restore(split.RedactedSpec, split.Snapshot, split.Secrets));
    }

    [Fact]
    public void IdenticalEnvironmentsAreStoredOnce()
    {
        using var root = new TemporaryDataRoot();
        var clock = new ManualClock();
        using var store = root.Open(clock);
        var first = Captured("env-windows-pwsh.json");
        var reordered = new EnvSnapshot();
        reordered.Entries.AddRange(first.Entries.Reverse());
        var changed = first.Clone();
        changed.Entries[0].Value += "x";

        var (a, b, c) = store.Write(transaction =>
        {
            var digestA = EnvSnapshots.Reference(transaction, first);
            Rows.InsertTask(transaction, digestA);
            var digestB = EnvSnapshots.Reference(transaction, reordered);
            Rows.InsertTask(transaction, digestB);
            var digestC = EnvSnapshots.Reference(transaction, changed);
            Rows.InsertTask(transaction, digestC);
            return (digestA, digestB, digestC);
        });

        Assert.Equal(a, b);
        Assert.NotEqual(a, c);
        Assert.Equal(EnvSnapshots.Digest(first), a);
        Assert.Equal(2L, store.Read(reader => reader.Scalar("SELECT count(*) FROM env_snapshot;")));
        Assert.Equal(2L, store.Read(reader => reader.Scalar("SELECT ref_count FROM env_snapshot WHERE env_digest = $d;", ("$d", a))));
        Assert.Equal(EnvSnapshots.Canonicalize(first), store.Environments.Get(a));
        Assert.Equal((long)first.Entries.Count, store.Read(reader => reader.Scalar("SELECT entry_count FROM env_snapshot WHERE env_digest = $d;", ("$d", a))));
        Assert.Equal((long)EnvSnapshots.Canonicalize(first).CalculateSize(), store.Read(reader => reader.Scalar("SELECT byte_size FROM env_snapshot WHERE env_digest = $d;", ("$d", a))));
        Assert.True(store.Read(reader => (long)reader.Scalar("SELECT length(entries) FROM env_snapshot WHERE env_digest = $d;", ("$d", a))!) < first.CalculateSize() / 2);
    }

    [Fact]
    public void UnreferencedSnapshotsAreDeleted24HoursAfterTheirLastUse()
    {
        using var root = new TemporaryDataRoot();
        var clock = new ManualClock();
        using var store = root.Open(clock);
        var snapshot = Captured("env-wsl-debian-bash.json");
        var digest = store.Write(transaction => EnvSnapshots.Reference(transaction, snapshot));

        store.Write(transaction => EnvSnapshots.Release(transaction, digest));
        clock.Advance(EnvSnapshots.UnreferencedRetention - TimeSpan.FromMinutes(1));
        Assert.Equal(0, store.Environments.DeleteUnreferenced());
        clock.Advance(TimeSpan.FromMinutes(1));
        Assert.Equal(1, store.Environments.DeleteUnreferenced());
        Assert.Null(store.Environments.Get(digest));
        Assert.Throws<InvalidOperationException>(() => store.Write(transaction => EnvSnapshots.Release(transaction, digest)));
    }

    [Fact]
    public void ACallerEnvironmentIsBounded()
    {
        using var root = new TemporaryDataRoot();
        using var store = root.Open(new ManualClock());
        var tooMany = new EnvSnapshot();
        tooMany.Entries.AddRange(Enumerable.Range(0, EnvSnapshots.MaxEntries + 1).Select(index => new EnvEntry { Name = "V" + index, Value = "1" }));
        var duplicate = new EnvSnapshot { Entries = { new EnvEntry { Name = "A", Value = "1" }, new EnvEntry { Name = "A", Value = "2" } } };

        Assert.Throws<ArgumentException>(() => store.Write(transaction => EnvSnapshots.Reference(transaction, tooMany)));
        Assert.Throws<ArgumentException>(() => EnvSnapshots.Digest(duplicate));
    }

    [Theory]
    [InlineData("env-windows-pwsh.json")]
    [InlineData("env-windows-git-bash.json")]
    [InlineData("env-wsl-debian-bash.json")]
    public void CapturedEnvironmentFixturesAreSyntheticAndSplitCleanly(string fixture)
    {
        using var document = JsonDocument.Parse(File.ReadAllBytes(Path.Combine(AppContext.BaseDirectory, "Fixtures", "environments", fixture)));
        Assert.Contains("every value synthetic", document.RootElement.GetProperty("note").GetString(), StringComparison.Ordinal);
        var snapshot = Captured(fixture);
        Assert.Equal(document.RootElement.GetProperty("entryCount").GetInt32(), snapshot.Entries.Count);

        var spec = new TaskSpec { Environment = new EnvironmentSpec { Inherit = EnvironmentInherit.Caller } };
        foreach (var entry in snapshot.Entries)
        {
            spec.Environment.CallerEnvironment[entry.Name] = entry.Value;
        }

        var split = SubmittedEnvironment.Split(spec, SecretNameMatcher.Default);
        Assert.All(split.Snapshot!.Entries, entry => Assert.False(SecretNameMatcher.Default.IsSecret(entry.Name)));
        Assert.Equal(spec, SubmittedEnvironment.Restore(split.RedactedSpec, split.Snapshot, split.Secrets));
    }

    internal static EnvSnapshot Captured(string fixture)
    {
        using var document = JsonDocument.Parse(File.ReadAllBytes(Path.Combine(AppContext.BaseDirectory, "Fixtures", "environments", fixture)));
        var snapshot = new EnvSnapshot();
        foreach (var entry in document.RootElement.GetProperty("entries").EnumerateArray())
        {
            snapshot.Entries.Add(new EnvEntry { Name = entry.GetProperty("name").GetString()!, Value = entry.GetProperty("value").GetString()! });
        }

        return snapshot;
    }
}
