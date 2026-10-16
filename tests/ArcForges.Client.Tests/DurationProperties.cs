// SPDX-License-Identifier: AGPL-3.0-only
using System.Globalization;
using System.Text.RegularExpressions;
using ArcForges.CommandLine;
using ArcForges.Tests;
using CsCheck;

namespace ArcForges.Client.Tests;

/// <summary>
/// CLI durations (experience/cli.md section 1: a whole number with <c>s</c>, <c>m</c>, <c>h</c> or <c>d</c>) as a property: over generated
/// text, <see cref="Durations.TryParse"/> accepts exactly the grammar (a positive amount up to 1,000,000; the unit in either case), returns
/// the amount in that unit, and refuses everything else without throwing.
/// </summary>
public sealed partial class DurationProperties
{
    [Fact]
    public void DurationsAcceptExactlyTheGrammar()
    {
        var text = Gen.Frequency(
            (3, Gen.Select(Gen.String[Gen.Char["0123456789"], 0, 9], Gen.Char["smhdSMHDxw0 "], (digits, unit) => digits + unit)),
            (1, Gen.Select(Gen.Long[-5, 1_000_005], Gen.Char["smhd"], (amount, unit) => amount.ToString(CultureInfo.InvariantCulture) + unit)),
            (1, Gen.String[Gen.Char["0123456789smhd -+.,_٣"], 0, 12]),
            (1, Gen.String));
        text.Sample(candidate =>
        {
            var accepted = Durations.TryParse(candidate, out var duration);
            var match = Grammar().Match(candidate);
            var amount = match.Success && long.TryParse(match.Groups[1].Value, NumberStyles.None, CultureInfo.InvariantCulture, out var parsed) ? parsed : 0;
            Assert.Equal(amount is > 0 and <= 1_000_000, accepted);
            if (accepted)
            {
                var expected = char.ToLowerInvariant(match.Groups[2].Value[0]) switch
                {
                    's' => TimeSpan.FromSeconds(amount),
                    'm' => TimeSpan.FromMinutes(amount),
                    'h' => TimeSpan.FromHours(amount),
                    _ => TimeSpan.FromDays(amount),
                };
                Assert.Equal(expected, duration);
            }
        }, iter: PropertyRuns.Iter(20_000));
    }

    [GeneratedRegex(@"^([0-9]+)([smhdSMHD])\z")]
    private static partial Regex Grammar();
}
