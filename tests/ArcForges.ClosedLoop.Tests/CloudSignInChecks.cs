// SPDX-License-Identifier: AGPL-3.0-only
using System.Text.Json;

namespace ArcForges.ClosedLoop.Tests;

/// <summary>
/// The pure checks of <see cref="CloudSignInTests"/> (routine tests in <c>CloudSignInChecksTests</c> show that each fails on the broken
/// behaviour): the refresh counter and the delivered-key comparison.
/// </summary>
internal static class CloudSignInChecks
{
    /// <summary>
    /// Counts refreshes from the status's <c>LastContactAt</c> (Unix seconds). Nothing counts until a first contact exists (it is the
    /// baseline); then a refresh is a contact at least <c>cadence - slack</c> seconds after the last counted one, so a reading with no
    /// contact, an unchanged one, or a contact that is not a refresh (a report right after the sign-in) never completes the step.
    /// </summary>
    internal sealed class RefreshCounter(int cadenceSeconds, int slackSeconds = 2)
    {
        private long? _baseline;

        /// <summary>The refreshes seen after the baseline contact.</summary>
        public int Refreshes { get; private set; }

        /// <summary>The contact instants (Unix seconds): the baseline, then each counted refresh.</summary>
        public List<long> Instants { get; } = [];

        /// <summary>True once the first contact exists.</summary>
        public bool HasBaseline => _baseline is not null;

        /// <summary>Feeds one reading of <c>LastContactAt</c> (null while there is none).</summary>
        public void Observe(long? contactSeconds)
        {
            if (contactSeconds is not { } contact)
            {
                return;
            }

            if (_baseline is not { } baseline)
            {
                _baseline = contact;
                Instants.Add(contact);
                return;
            }

            if (contact - baseline >= cadenceSeconds - slackSeconds)
            {
                _baseline = contact;
                Refreshes++;
                Instants.Add(contact);
            }
        }

        /// <summary>The honest step text: how many refreshes were seen and when.</summary>
        public string Describe() =>
            Refreshes + " refreshes after the first contact (contact instants, Unix seconds: " + string.Join(", ", Instants) + ")";
    }

    /// <summary>One expected key set: the purpose (<c>command</c> or <c>entitlement</c>) and its exact kids.</summary>
    internal sealed record KeyExpectation(string Purpose, IReadOnlyList<string> Kids)
    {
        /// <summary>Parses <c>command:kid1,kid2;entitlement:kid3</c>; null or blank means no check.</summary>
        public static IReadOnlyList<KeyExpectation>? Parse(string? text)
        {
            if (string.IsNullOrWhiteSpace(text))
            {
                return null;
            }

            var expectations = new List<KeyExpectation>();
            foreach (var part in text.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            {
                var colon = part.IndexOf(':', StringComparison.Ordinal);
                var purpose = colon < 0 ? part : part[..colon].Trim();
                if (colon < 0 || purpose is not ("command" or "entitlement") || expectations.Any(item => item.Purpose == purpose))
                {
                    throw new FormatException("ARCFORGES_E2E_EXPECT_KEYS: expected 'command:<kid>,<kid>[;entitlement:<kid>,...]', each purpose once");
                }

                var kids = part[(colon + 1)..].Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
                if (kids.Length == 0 || kids.Distinct(StringComparer.Ordinal).Count() != kids.Length)
                {
                    throw new FormatException("ARCFORGES_E2E_EXPECT_KEYS: " + purpose + " needs distinct kids");
                }

                expectations.Add(new KeyExpectation(purpose, kids));
            }

            return expectations;
        }
    }

    /// <summary>
    /// Compares the node's key-set cache (<c>run/cloud-keys.json</c>, camelCase <c>commandKeys</c> and <c>entitlementKeys</c>) with the
    /// expectation: exactly the expected kids for each named purpose. Returns null when it matches, else the difference (kids only).
    /// </summary>
    public static string? CompareKeys(string? json, IReadOnlyList<KeyExpectation> expected)
    {
        if (json is null)
        {
            return "the key-set cache file does not exist";
        }

        JsonElement root;
        try
        {
            root = JsonDocument.Parse(json).RootElement.Clone();
        }
        catch (JsonException)
        {
            return "the key-set cache is not valid JSON";
        }

        var problems = new List<string>();
        foreach (var (purpose, kids) in expected.Select(item => (item.Purpose, item.Kids)))
        {
            var property = purpose + "Keys";
            var actual = new List<string>();
            if (root.ValueKind == JsonValueKind.Object && root.TryGetProperty(property, out var list) && list.ValueKind == JsonValueKind.Array)
            {
                actual.AddRange(list.EnumerateArray().Select(entry => entry.ValueKind == JsonValueKind.Object && entry.TryGetProperty("kid", out var kid) && kid.ValueKind == JsonValueKind.String ? kid.GetString()! : "(no kid)"));
            }

            var missing = kids.Except(actual, StringComparer.Ordinal).ToArray();
            var extra = actual.Except(kids, StringComparer.Ordinal).ToArray();
            if (missing.Length > 0 || extra.Length > 0 || actual.Count != kids.Count)
            {
                problems.Add(purpose + " keys: missing [" + string.Join(", ", missing) + "], unexpected [" + string.Join(", ", extra) + "], held " + actual.Count + " of " + kids.Count);
            }
        }

        return problems.Count == 0 ? null : string.Join("; ", problems);
    }
}
