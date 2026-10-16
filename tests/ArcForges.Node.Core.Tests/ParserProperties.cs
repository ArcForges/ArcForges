// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Contracts.Node.V1;
using ArcForges.Node.Core.Events;
using ArcForges.Node.Core.Execution;
using ArcForges.Node.Store;
using ArcForges.Tests;
using CsCheck;

namespace ArcForges.Node.Core.Tests;

/// <summary>
/// Properties of the node's own text formats over generated input: the event cursor (events.proto <c>StreamPosition.cursor</c>;
/// <c>VALIDATION/invalid_cursor</c>) and the listing cursor round-trip, and any text either parses to a cursor that writes back the same
/// way or is refused, never an exception; the task command summary (node-store.md <c>task</c>; R-EXE-017) never shows the value of a
/// secret-shaped <c>NAME=value</c> argument and stays one line of at most 200 characters.
/// </summary>
public sealed class ParserProperties
{
    /// <summary>Text near the cursor grammar: digits, dots, the prefix, signs, spaces and other characters.</summary>
    private static readonly Gen<string> NearCursor = Gen.Frequency(
        (3, Gen.Select(Gen.OneOfConst("v1.", "v1", "V1.", "v2.", string.Empty), Gen.String[Gen.Char["0123456789.-+ x"], 0, 30], (prefix, rest) => prefix + rest)),
        (1, Gen.String[Gen.Char["v1.0123456789abcdef"], 0, 70]),
        (1, Gen.String));

    [Fact]
    public void AnEventCursorRoundTripsAndAnyTextParsesOrIsRefused()
    {
        Gen.Select(Gen.ULong[1, ulong.MaxValue], Gen.ULong).Sample((generation, sequence) =>
        {
            var cursor = new EventCursor(generation, sequence);
            Assert.True(EventCursor.TryParse(cursor.ToString(), out var parsed));
            Assert.Equal(cursor, parsed);
        }, iter: PropertyRuns.Iter(5_000));

        NearCursor.Sample(text =>
        {
            if (EventCursor.TryParse(text, out var cursor))
            {
                Assert.True(cursor.Generation >= 1, $"'{text}' parsed to generation 0.");
                Assert.True(EventCursor.TryParse(cursor.ToString(), out var again) && again == cursor);
            }
        }, iter: PropertyRuns.Iter(20_000));
    }

    [Fact]
    public void AListingCursorRoundTripsAndAnyTextParsesOrIsRefused()
    {
        Gen.Select(Gen.Long, Gen.Byte.Array[16]).Sample((created, id) =>
        {
            Assert.True(PageCursor.TryParse(new PageCursor(created, id).ToString(), out var parsed));
            Assert.Equal(created, parsed.CreatedAt);
            Assert.Equal(id, parsed.Id);
        }, iter: PropertyRuns.Iter(5_000));

        Gen.Frequency((3, Gen.Select(Gen.String[Gen.Char["-0123456789"], 0, 21], Gen.String[Gen.Char["0123456789abcdefABCDEFg."], 0, 40], (head, tail) => head + "." + tail)),
            (1, Gen.String)).Sample(text =>
        {
            if (PageCursor.TryParse(text, out var cursor))
            {
                Assert.Equal(16, cursor.Id.Length);
                Assert.True(PageCursor.TryParse(cursor.ToString(), out var again));
                Assert.Equal(cursor.CreatedAt, again.CreatedAt);
                Assert.Equal(cursor.Id, again.Id);
            }
        }, iter: PropertyRuns.Iter(20_000));
    }

    [Fact]
    public void ACommandSummaryNeverShowsASecretShapedValueAndStaysOneShortLine()
    {
        const string Marker = "secret-value-";
        var secretName = Gen.Select(Gen.String[Gen.Char["AB_x"], 0, 4], Gen.OneOfConst("TOKEN", "Secret", "PASSWORD", "_KEY", "APIKEY"), (head, word) => head + word);
        var argument = Gen.Frequency(
            (3, Gen.String[Gen.Char["abc -=/\\\"\r\n中"], 0, 20]),
            (2, Gen.Select(Gen.OneOfConst(string.Empty, "-", "--"), secretName, Gen.String[Gen.Char["abc =/\"\n中"], 0, 20],
                (dashes, name, value) => dashes + name + "=" + Marker + value)));
        Gen.Select(argument.Array[1, 12], Gen.Bool).Sample((arguments, shell) =>
        {
            var command = shell
                ? new CommandSpec { Shell = new ShellCommand { Kind = ShellKind.Pwsh, Script = string.Join(' ', arguments.Select(item => item.Replace(Marker, string.Empty, StringComparison.Ordinal))) } }
                : new CommandSpec { Argv = new ArgvCommand { Argv = { arguments } } };
            var summary = CommandText.Summary(command, SecretNameMatcher.Default);
            Assert.DoesNotContain(Marker, summary, StringComparison.Ordinal);
            Assert.True(summary.Length <= CommandText.MaxSummary, $"{summary.Length} characters.");
            Assert.DoesNotContain('\n', summary);
            Assert.DoesNotContain('\r', summary);
        }, iter: PropertyRuns.Iter(5_000));
    }
}
