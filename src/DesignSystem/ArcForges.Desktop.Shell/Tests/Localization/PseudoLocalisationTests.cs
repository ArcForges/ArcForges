// SPDX-License-Identifier: AGPL-3.0-only
using System.Collections;
using System.Globalization;
using System.Resources;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Desktop.Shell.Accessibility;
using ArcForges.Desktop.Shell.Errors;
using ArcForges.Desktop.Shell.Localization;
using ArcForges.Foundation.Errors;
using Xunit;

namespace ArcForges.Desktop.Shell.Tests.Localization;

/// <summary>
/// The pseudo-localisation pass (LO-04, WP-10.07). It renders every shell-owned user-visible string in the pseudo-locale
/// and requires each to arrive as exactly one whole marked message, which exposes a literal that bypassed resources, two
/// fragments joined by code, and any text clipped before its end marker.
/// </summary>
public sealed class PseudoLocalisationTests
{
    [Fact]
    public void TransformMarksWholeMessagesAccentsLettersAndPreservesPlaceholdersAndPlurals()
    {
        const string ascii = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
        string plain = PseudoLocaliser.Transform(ascii);

        Assert.True(PseudoLocaliser.IsWholePseudoMessage(plain));
        string body = plain[1..^1].TrimEnd('~');
        Assert.Equal(ascii.Length, body.Length);
        Assert.All(body, static character => Assert.True(character > 0x7F, $"{character} was not accented."));
        Assert.Equal(ascii.Length, body.Distinct().Count());

        string withDigits = PseudoLocaliser.Transform("Page 12 of 40");
        Assert.Contains("12", withDigits, StringComparison.Ordinal);
        Assert.Contains("40", withDigits, StringComparison.Ordinal);

        const string plural = "{count, plural, =0 {No items} one {# item} other {# items}} for {name}. {{kept}}";
        string pseudo = PseudoLocaliser.Transform(plural);
        Assert.Contains("{name}", pseudo, StringComparison.Ordinal);
        Assert.Contains("{count, plural,", pseudo, StringComparison.Ordinal);
        Assert.Contains("{{", pseudo, StringComparison.Ordinal);

        // The pseudo pattern is still a valid pattern and formats like the original.
        string formatted = ShellMessageFormatter.Format(
            pseudo,
            new Dictionary<string, object?> { ["count"] = 3, ["name"] = "Ada" },
            CultureInfo.InvariantCulture);
        Assert.True(PseudoLocaliser.IsWholePseudoMessage(formatted));
        Assert.Contains("3", formatted, StringComparison.Ordinal);
        Assert.Contains("Ada", formatted, StringComparison.Ordinal);
    }

    [Fact]
    public void TransformExpandsTextAndRejectsInvalidPatterns()
    {
        const string text = "Open the selected item";
        string pseudo = PseudoLocaliser.Transform(text);

        Assert.True(pseudo.Length >= (int)(text.Length * 1.3));
        Assert.False(PseudoLocaliser.IsWholePseudoMessage(text));
        Assert.False(PseudoLocaliser.IsWholePseudoMessage(pseudo + pseudo));
        Assert.False(PseudoLocaliser.IsWholePseudoMessage(pseudo[..^1]));
        Assert.False(PseudoLocaliser.IsWholePseudoMessage(pseudo[1..]));
        Assert.False(PseudoLocaliser.IsWholePseudoMessage(pseudo[..^1] + pseudo));
        Assert.False(PseudoLocaliser.IsWholePseudoMessage(pseudo + "x" + PseudoLocaliser.EndMarker));
        Assert.False(PseudoLocaliser.IsWholePseudoMessage(PseudoLocaliser.StartMarker + "x" + pseudo));
        Assert.False(PseudoLocaliser.IsWholePseudoMessage(PseudoLocaliser.StartMarker.ToString()));
        Assert.Throws<FormatException>(() => PseudoLocaliser.Transform("{unterminated"));
        Assert.Throws<ArgumentNullException>(() => PseudoLocaliser.Transform(null!));
        Assert.Throws<ArgumentNullException>(() => PseudoLocaliser.IsWholePseudoMessage(null!));
    }

    [Fact]
    public void EveryShellResourceStringIsAValidPatternThatSurvivesTheTransform()
    {
        int checkedStrings = 0;
        foreach ((string set, string key, string value) in AllResourceStrings())
        {
            string pseudo = PseudoLocaliser.Transform(value);

            Assert.True(PseudoLocaliser.IsWholePseudoMessage(pseudo), $"{set}:{key}");
            Assert.True(pseudo.Length > value.Length, $"{set}:{key} did not expand.");
            checkedStrings++;
        }

        Assert.True(checkedStrings > 100, "The shell resource sets are unexpectedly small.");
    }

    [Fact]
    public void PseudoLocalisedShellRevealsNoHardCodedOrConcatenatedUserText()
    {
        using IDisposable scope = ShellText.BeginPseudoLocalisation();
        Assert.True(ShellText.IsPseudoLocalising);
        var visible = new List<(string Source, string Text)>();

        foreach (ReasonCode reason in ReasonCodes.All)
        {
            var presentation = ErrorPresenter.Present(TypedFailure.Create(reason.Code));
            visible.Add(($"{reason.Code}:title", presentation.Title));
            visible.Add(($"{reason.Code}:what", presentation.WhatHappened));
            visible.Add(($"{reason.Code}:retry", presentation.RetryGuidance));
            visible.Add(($"{reason.Code}:action", presentation.UserAction));
        }

        var item = new AttentionItem("approval-1", "Sensitive title", "Sensitive body", AttentionDurability.Durable);
        SystemNotificationContent generic = AttentionModel.CreateSystemNotificationContent(item);
        visible.Add(("notification:title", generic.Title));
        visible.Add(("notification:body", generic.Body));

        foreach (ShellShutdownState state in new[]
        {
            new ShellShutdownState(1, 0, 0),
            new ShellShutdownState(1, 2, 0),
            new ShellShutdownState(1, 0, 1),
            new ShellShutdownState(1, 3, 4),
        })
        {
            visible.Add(($"shutdown:{state.ActiveWorkCount}:{state.UnsavedItemCount}", ShellLifecycleCoordinator.CreateShutdownPrompt(state).Consequences));
        }

        foreach (ShellSurface surface in ShellSurfaceCatalog.All)
        {
            foreach (AccessibleNode node in Flatten(surface.Root))
            {
                if (node.Name is not null)
                {
                    visible.Add(($"{node.Id}:name", ShellText.Resolve(node.Name, CultureInfo.InvariantCulture)));
                }

                if (node.Description is not null)
                {
                    visible.Add(($"{node.Id}:description", ShellText.Resolve(node.Description, CultureInfo.InvariantCulture)));
                }
            }
        }

        Assert.True(visible.Count > 150);
        Assert.All(visible, entry => Assert.True(PseudoLocaliser.IsWholePseudoMessage(entry.Text), $"{entry.Source} is not one whole pseudo-localised message: {entry.Text}"));

        // Joining two resolved messages in code is exactly the defect the pass must reveal.
        string joined = visible[0].Text + visible[1].Text;
        Assert.False(PseudoLocaliser.IsWholePseudoMessage(joined));
    }

    [Fact]
    public async Task PseudoLocalisationIsScopedToTheExecutionFlowAndRestoresOnDispose()
    {
        var probe = new LocalizedText("settings.name");
        string neutral = ShellText.Resolve(probe, CultureInfo.InvariantCulture);
        Assert.False(ShellText.IsPseudoLocalising);
        Assert.False(PseudoLocaliser.IsWholePseudoMessage(neutral));

        IDisposable outer = ShellText.BeginPseudoLocalisation();
        IDisposable inner = ShellText.BeginPseudoLocalisation();
        string whileActive = await Task.Run(() => ShellText.Resolve(probe, CultureInfo.InvariantCulture), TestContext.Current.CancellationToken);
        Assert.True(PseudoLocaliser.IsWholePseudoMessage(whileActive));

        inner.Dispose();
        inner.Dispose();
        Assert.True(ShellText.IsPseudoLocalising);
        outer.Dispose();
        Assert.False(ShellText.IsPseudoLocalising);
        Assert.Equal(neutral, ShellText.Resolve(probe, CultureInfo.InvariantCulture));
    }

    [Fact]
    public void ResolveFailsClosedForAnUndefinedKeyWithoutLeakingIt()
    {
        var missing = new LocalizedText("surface.not-defined-anywhere.name");

        InvalidOperationException failure = Assert.Throws<InvalidOperationException>(() => ShellText.Resolve(missing, CultureInfo.InvariantCulture));
        Assert.DoesNotContain("not-defined-anywhere", failure.Message, StringComparison.Ordinal);
        Assert.Throws<ArgumentNullException>(() => ShellText.Resolve(null!));
    }

    [Fact]
    public void ShutdownConsequencesUseWholePluralSentencesRatherThanItemParenthesisHacks()
    {
        CultureInfo previous = CultureInfo.CurrentUICulture;
        try
        {
            CultureInfo.CurrentUICulture = CultureInfo.GetCultureInfo("en-US");
            string one = ShellLifecycleCoordinator.CreateShutdownPrompt(new ShellShutdownState(1, 1, 1)).Consequences;
            string many = ShellLifecycleCoordinator.CreateShutdownPrompt(new ShellShutdownState(1, 2, 3)).Consequences;

            Assert.Contains("1 active item to reach", one, StringComparison.Ordinal);
            Assert.Contains("1 unsaved item must be saved", one, StringComparison.Ordinal);
            Assert.Contains("2 active items to reach", many, StringComparison.Ordinal);
            Assert.Contains("3 unsaved items must be saved", many, StringComparison.Ordinal);
            Assert.DoesNotContain("(s)", one + many, StringComparison.Ordinal);

            // Each singular and plural branch of the single-count sentences is asserted on its own.
            Assert.Equal(
                "Quitting will stop new writes and wait for 1 active item to reach a safe point; active work will not be silently discarded.",
                ShellLifecycleCoordinator.CreateShutdownPrompt(new ShellShutdownState(1, 1, 0)).Consequences);
            Assert.Equal(
                "Quitting will stop new writes and wait for 2 active items to reach a safe point; active work will not be silently discarded.",
                ShellLifecycleCoordinator.CreateShutdownPrompt(new ShellShutdownState(1, 2, 0)).Consequences);
            Assert.Equal(
                "1 unsaved item must be saved before writes are flushed and services are disconnected.",
                ShellLifecycleCoordinator.CreateShutdownPrompt(new ShellShutdownState(1, 0, 1)).Consequences);
            Assert.Equal(
                "2 unsaved items must be saved before writes are flushed and services are disconnected.",
                ShellLifecycleCoordinator.CreateShutdownPrompt(new ShellShutdownState(1, 0, 2)).Consequences);
        }
        finally
        {
            CultureInfo.CurrentUICulture = previous;
        }
    }

    internal static IEnumerable<(string Set, string Key, string Value)> AllResourceStrings()
    {
        foreach (string set in new[] { ShellText.SurfaceSet, ShellText.ErrorSet })
        {
            var manager = new ResourceManager(set, typeof(ShellText).Assembly);
            ResourceSet resources = manager.GetResourceSet(CultureInfo.InvariantCulture, createIfNotExists: true, tryParents: false)
                ?? throw new InvalidOperationException("Missing neutral resource set.");
            foreach (DictionaryEntry entry in resources.Cast<DictionaryEntry>().OrderBy(static entry => (string)entry.Key, StringComparer.Ordinal))
            {
                yield return (set, (string)entry.Key, (string)entry.Value!);
            }
        }
    }

    internal static IEnumerable<AccessibleNode> Flatten(AccessibleNode node)
    {
        yield return node;
        foreach (AccessibleNode child in node.Children)
        {
            foreach (AccessibleNode nested in Flatten(child))
            {
                yield return nested;
            }
        }
    }
}
