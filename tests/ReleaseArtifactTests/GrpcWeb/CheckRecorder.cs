// SPDX-License-Identifier: AGPL-3.0-only
namespace ArcForges.ReleaseArtifactTests.GrpcWeb;

internal sealed record CheckResult(string Name, bool Passed, string Detail);

/// <summary>Collects named checks. A name is recorded once; a repeated name is a probe defect.</summary>
internal sealed class CheckRecorder
{
    private readonly List<CheckResult> _results = [];

    public IReadOnlyList<CheckResult> Results => _results;

    public bool AllPassed => _results.Count > 0 && _results.TrueForAll(result => result.Passed);

    public void Expect(string name, bool condition, string detail)
    {
        ArgumentException.ThrowIfNullOrEmpty(name);
        ArgumentNullException.ThrowIfNull(detail);
        if (_results.Exists(result => result.Name == name))
        {
            throw new InvalidOperationException("Check recorded twice: " + name);
        }

        _results.Add(new CheckResult(name, condition, condition ? detail : "FAILED: " + detail));
    }

    public bool Passed(string name) => _results.Exists(result => result.Name == name && result.Passed);

    public bool Failed(string name) => _results.Exists(result => result.Name == name && !result.Passed);
}
