// SPDX-License-Identifier: AGPL-3.0-only
using System.Collections.Concurrent;
using System.Reflection;
using Xunit.v3;

namespace ArcForges.Tests;

/// <summary>
/// What a test left running (16-testing-strategy section 4). A fixture reports it here from its disposal instead of throwing there: a
/// disposal that throws while the test's own failure unwinds replaces that failure, and the cause is lost. <see cref="FailOnLeftoversAttribute"/>
/// fails the test after it ran, next to its own failure. Linked into the test projects whose fixtures check for leftovers.
/// </summary>
internal static class Leftovers
{
    private static readonly ConcurrentDictionary<string, ConcurrentQueue<string>> Reported = new(StringComparer.Ordinal);

    /// <summary>Records what the current test left running; outside a test it fails at once.</summary>
    public static void Report(IReadOnlyCollection<string> leftovers)
    {
        if (leftovers.Count == 0)
        {
            return;
        }

        if (TestContext.Current.Test?.UniqueID is not { } test)
        {
            Assert.Fail(Message(leftovers));
            return;
        }

        var queue = Reported.GetOrAdd(test, _ => new ConcurrentQueue<string>());
        foreach (var leftover in leftovers)
        {
            queue.Enqueue(leftover);
        }

        TestContext.Current.TestOutputHelper?.WriteLine(Message(leftovers));
    }

    /// <summary>Takes what <paramref name="test"/> left running, if anything.</summary>
    public static IReadOnlyCollection<string> Take(string test) => Reported.TryRemove(test, out var queue) ? queue.ToArray() : [];

    public static string Message(IEnumerable<string> leftovers) => "Processes were left running after the test: " + string.Join(", ", leftovers);
}

/// <summary>Fails a test after it ran when its fixtures reported leftovers (<see cref="Leftovers"/>).</summary>
[AttributeUsage(AttributeTargets.Assembly)]
internal sealed class FailOnLeftoversAttribute : BeforeAfterTestAttribute
{
    public override void After(MethodInfo methodUnderTest, IXunitTest test)
    {
        ArgumentNullException.ThrowIfNull(test);
        var leftovers = Leftovers.Take(test.UniqueID);
        Assert.True(leftovers.Count == 0, Leftovers.Message(leftovers));
    }
}
