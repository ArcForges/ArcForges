// SPDX-License-Identifier: AGPL-3.0-only
using System.Text;
using ArcForges.Contracts.Node.V1;
using ArcForges.Tests;
using CsCheck;
using Google.Protobuf;

namespace ArcForges.Node.Store.Tests;

/// <summary>
/// R-EXE-017 (04-execution section 2) as properties over generated environments: the secret-name glob agrees with its definition, no stored
/// part of a submitted spec ever holds a secret-shaped variable's value, the split is idempotent, and the stored parts rebuild the
/// submitted spec exactly.
/// </summary>
public sealed class EnvironmentProperties
{
    private const string SecretMarker = "secret-value-";

    private static readonly Gen<string> Name = Gen.Frequency(
        (3, Gen.String[Gen.Char["ABCZ_ab12"], 1, 8]),
        (2, Gen.Select(Gen.String[Gen.Char["AB_x"], 0, 4], Gen.OneOfConst("TOKEN", "secret", "Password", "PASSWD", "_KEY", "APIKEY", "_key"), Gen.String[Gen.Char["AB_"], 0, 3],
            (head, word, tail) => head + word + tail)),
        (1, Gen.Select(Gen.OneOfConst("AWS_", "aws_", "AZURE_", "GH_", "gh_"), Gen.String[Gen.Char["ABC_"], 0, 5], (prefix, rest) => prefix + rest)),
        (1, Gen.OneOfConst("GITHUB_TOKEN", "NPM_TOKEN", "PATH", "HOME", "KEYBOARD", "SSH_AUTH_SOCK")));

    private static readonly Gen<string> Value = Gen.String[Gen.Char["abc /:=;-_\\\"é中"], 0, 10];

    private static readonly Gen<Dictionary<string, string>> Variables = Gen.Select(Name, Value).Array[0, 12]
        .Select(pairs => pairs.GroupBy(pair => pair.Item1, StringComparer.Ordinal).ToDictionary(group => group.Key, group => group.First().Item2, StringComparer.Ordinal));

    private static readonly Gen<TaskSpec> Spec = Gen.Select(Variables, Variables, Gen.Bool, Gen.String[Gen.Char["abc"], 0, 3].Array[0, 2],
        (caller, set, inheritCaller, unset) =>
        {
            var spec = new TaskSpec
            {
                Command = new CommandSpec { Argv = new ArgvCommand { Argv = { "tool", "run" } } },
                WorkingDirectory = "/work",
                Environment = new EnvironmentSpec { Inherit = inheritCaller ? EnvironmentInherit.Caller : EnvironmentInherit.Node, Unset = { unset.Distinct() } },
            };

            // A secret-shaped variable's value carries a marker no other value has, so a leak is found wherever it would appear.
            spec.Environment.CallerEnvironment.Add(caller.ToDictionary(pair => pair.Key, pair => Marked(pair.Key, pair.Value)));
            spec.Environment.Set.Add(set.ToDictionary(pair => pair.Key, pair => Marked(pair.Key, pair.Value)));
            return spec;
        });

    [Fact]
    public void TheSecretNameGlobAgreesWithItsDefinition()
    {
        var pattern = Gen.String[Gen.Char["AB_a*"], 1, 6].Where(text => !string.IsNullOrWhiteSpace(text));
        Gen.Select(pattern.Array[1, 3], Gen.String[Gen.Char["ABab_1"], 0, 8]).Sample((patterns, name) =>
            Assert.Equal(patterns.Any(item => Matches(item, name)), new SecretNameMatcher(patterns).IsSecret(name)),
            iter: PropertyRuns.Iter(20_000));
    }

    [Fact]
    public void NoStoredPartHoldsASecretShapedValueAndTheSpecIsRebuiltExactly() =>
        Spec.Sample(spec =>
        {
            var split = SubmittedEnvironment.Split(spec, SecretNameMatcher.Default);

            // What is stored in the task row and the content-addressed snapshot never holds a secret-shaped value.
            Assert.DoesNotContain(SecretMarker, Text(split.RedactedSpec), StringComparison.Ordinal);
            Assert.DoesNotContain(SecretMarker, split.Snapshot is null ? string.Empty : Text(split.Snapshot), StringComparison.Ordinal);

            // Exactly the secret-shaped names are sealed (presence only in the snapshot), and the sealed parts rebuild the spec exactly.
            var secretNames = spec.Environment.CallerEnvironment.Keys.Concat(spec.Environment.Set.Keys).Where(SecretNameMatcher.Default.IsSecret)
                .Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal);
            Assert.Equal(secretNames, split.SealedNames.Order(StringComparer.Ordinal));
            Assert.Equal(spec, SubmittedEnvironment.Restore(split.RedactedSpec, split.Snapshot, split.Secrets));

            // Splitting what is stored again finds nothing more to seal.
            var again = SubmittedEnvironment.Split(split.RedactedSpec, SecretNameMatcher.Default);
            Assert.Null(again.Secrets);
            Assert.Equal(split.RedactedSpec, again.RedactedSpec);
        }, iter: PropertyRuns.Iter(2_000), print: spec => spec.ToString());

    private static string Marked(string name, string value) => SecretNameMatcher.Default.IsSecret(name) ? SecretMarker + value : value.Replace(SecretMarker, string.Empty, StringComparison.Ordinal);

    private static string Text(IMessage message) => Encoding.UTF8.GetString(message.ToByteArray());

    /// <summary>The glob's definition: <c>*</c> matches any run of characters, other characters match ignoring case (invariant upper case).</summary>
    private static bool Matches(string pattern, string text) => pattern.Length == 0
        ? text.Length == 0
        : pattern[0] == '*'
            ? Matches(pattern[1..], text) || (text.Length > 0 && Matches(pattern, text[1..]))
            : text.Length > 0 && char.ToUpperInvariant(pattern[0]) == char.ToUpperInvariant(text[0]) && Matches(pattern[1..], text[1..]);
}
