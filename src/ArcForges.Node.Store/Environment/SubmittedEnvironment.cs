// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Contracts.Node.V1;
using ArcForges.Node.Store.Proto;

namespace ArcForges.Node.Store;

/// <summary>
/// How a submitted <see cref="TaskSpec"/> is stored (R-EXE-017; 04-execution section 2): the spec without its caller
/// environment and without secret-shaped values (<c>task.spec</c>), the caller environment without secret-shaped values
/// (<c>env_snapshot</c>, content-addressed), and the secret-shaped values of the caller environment and of
/// <c>environment.set</c>, sealed in <c>task_secret</c>. <see cref="Restore"/> rebuilds the submitted environment exactly,
/// so queued tasks, restarts and retries run with it.
/// </summary>
public sealed class SubmittedEnvironment
{
    private SubmittedEnvironment(TaskSpec redactedSpec, EnvSnapshot? snapshot, SecretEnvironment? secrets)
    {
        RedactedSpec = redactedSpec;
        Snapshot = snapshot;
        Secrets = secrets;
    }

    /// <summary>The spec as stored: no caller environment, no secret-shaped <c>set</c> values.</summary>
    public TaskSpec RedactedSpec { get; }

    /// <summary>The caller environment without secret-shaped values (canonical order), or <see langword="null"/> when the spec has none.</summary>
    public EnvSnapshot? Snapshot { get; }

    /// <summary>The secret-shaped values to seal, or <see langword="null"/> when there are none.</summary>
    public SecretEnvironment? Secrets { get; }

    /// <summary>The names of every sealed variable (caller and <c>set</c>), in canonical order: presence only.</summary>
    public IReadOnlyList<string> SealedNames => Secrets is null
        ? []
        : [.. Secrets.Caller.Select(entry => entry.Name).Concat(Secrets.Set.Select(entry => entry.Name)).Distinct(StringComparer.Ordinal).Order(Utf8Order.Instance)];

    /// <summary>Splits <paramref name="spec"/> with the policy's secret name patterns.</summary>
    public static SubmittedEnvironment Split(TaskSpec spec, SecretNameMatcher matcher)
    {
        ArgumentNullException.ThrowIfNull(spec);
        ArgumentNullException.ThrowIfNull(matcher);
        var redacted = spec.Clone();
        var environment = redacted.Environment;
        if (environment is null)
        {
            return new SubmittedEnvironment(redacted, snapshot: null, secrets: null);
        }

        var secrets = new SecretEnvironment();
        EnvSnapshot? snapshot = null;
        if (environment.Inherit == EnvironmentInherit.Caller || environment.CallerEnvironment.Count > 0)
        {
            snapshot = new EnvSnapshot();
            foreach (var (name, value) in environment.CallerEnvironment)
            {
                if (matcher.IsSecret(name))
                {
                    secrets.Caller.Add(new EnvEntry { Name = name, Value = value });
                    snapshot.SealedNames.Add(name);
                }
                else
                {
                    snapshot.Entries.Add(new EnvEntry { Name = name, Value = value });
                }
            }

            snapshot = EnvSnapshots.Canonicalize(snapshot);
            environment.CallerEnvironment.Clear();
        }

        foreach (var name in environment.Set.Keys.Where(matcher.IsSecret).ToList())
        {
            secrets.Set.Add(new EnvEntry { Name = name, Value = environment.Set[name] });
            environment.Set.Remove(name);
        }

        if (secrets.Caller.Count == 0 && secrets.Set.Count == 0)
        {
            return new SubmittedEnvironment(redacted, snapshot, secrets: null);
        }

        var sorted = new SecretEnvironment();
        sorted.Caller.AddRange(secrets.Caller.OrderBy(entry => entry.Name, Utf8Order.Instance));
        sorted.Set.AddRange(secrets.Set.OrderBy(entry => entry.Name, Utf8Order.Instance));
        return new SubmittedEnvironment(redacted, snapshot, sorted);
    }

    /// <summary>Rebuilds the submitted spec from its stored parts.</summary>
    public static TaskSpec Restore(TaskSpec redactedSpec, EnvSnapshot? snapshot, SecretEnvironment? secrets)
    {
        ArgumentNullException.ThrowIfNull(redactedSpec);
        var spec = redactedSpec.Clone();
        if (snapshot is null && secrets is null)
        {
            return spec;
        }

        spec.Environment ??= new EnvironmentSpec();
        if (snapshot is not null)
        {
            foreach (var entry in snapshot.Entries)
            {
                spec.Environment.CallerEnvironment[entry.Name] = entry.Value;
            }
        }

        if (secrets is not null)
        {
            foreach (var entry in secrets.Caller)
            {
                spec.Environment.CallerEnvironment[entry.Name] = entry.Value;
            }

            foreach (var entry in secrets.Set)
            {
                spec.Environment.Set[entry.Name] = entry.Value;
            }
        }

        return spec;
    }
}
