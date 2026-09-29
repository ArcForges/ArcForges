// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Capabilities;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Foundation;
using ArcForges.Foundation.Errors;
using ArcForges.Desktop.Shell.Commands;
using Google.Protobuf.WellKnownTypes;
using Xunit;

namespace ArcForges.Desktop.Shell.Tests;

public sealed class CommandPaletteTests
{
    [Fact]
    public void TryRegisterRejectsDuplicateIdsAndNormalizedShortcutConflictsAtomically()
    {
        var provider = new CountingCapabilityProvider();
        var palette = new ShellCommandPalette(provider);
        var first = Command(
            "workspace.open",
            "Open workspace",
            "shell.action.workspace.open",
            shortcut: new CommandShortcut("k", CommandShortcutModifiers.Control));

        Assert.True(palette.TryRegister(first));
        Assert.False(palette.TryRegister(Command(
            "workspace.search",
            "Search workspace",
            "shell.action.workspace.search",
            shortcut: new CommandShortcut("K", CommandShortcutModifiers.Control))));
        Assert.False(palette.TryRegister(Command(
            "workspace.open",
            "Open another workspace",
            "shell.action.workspace.open-again",
            shortcut: new CommandShortcut("O", CommandShortcutModifiers.Control))));

        Assert.Throws<ArgumentException>(() => new CommandShortcut("two keys", CommandShortcutModifiers.Control));
        Assert.Throws<ArgumentOutOfRangeException>(() => new CommandShortcut("K", (CommandShortcutModifiers)16));
        Assert.Equal(new CommandShortcut("return", CommandShortcutModifiers.Control),
            new CommandShortcut("ENTER", CommandShortcutModifiers.Control));
        Assert.Equal(first, Assert.Single(palette.Snapshot()));
        Assert.Equal(0, provider.CallCount);
    }

    [Fact]
    public void SnapshotIsStableReadOnlyAndOrderedByCommandId()
    {
        var palette = new ShellCommandPalette(new CountingCapabilityProvider());
        var second = Command("workspace.close", "Close workspace", "shell.action.workspace.close");
        var first = Command("workspace.open", "Open workspace", "shell.action.workspace.open");

        Assert.True(palette.TryRegister(second));
        Assert.True(palette.TryRegister(first));
        var before = palette.Snapshot();
        Assert.Equal([first, second], before);
        Assert.True(Assert.IsAssignableFrom<IList<ShellCommand>>(before).IsReadOnly);

        Assert.True(palette.TryRegister(Command("workspace.save", "Save workspace", "shell.action.workspace.save")));

        Assert.Equal(2, before.Count);
        Assert.Equal(3, palette.Snapshot().Count);
    }

    [Fact]
    public void SearchPaletteRanksRelevantMatchesDeterministicallyWithoutAvailabilityEvaluation()
    {
        var provider = new CountingCapabilityProvider();
        var palette = new ShellCommandPalette(provider);
        var exact = Command("workspace.rename", "Rename", "shell.action.workspace.rename", keywords: ["open"]);
        var prefix = Command("workspace.open", "Open workspace", "shell.action.workspace.open");
        var substring = Command(
            "settings.workspace",
            "Workspace settings",
            "shell.action.settings.workspace",
            description: "Quickly open the selected workspace settings.");
        var unrelated = Command("help.about", "About", "shell.action.help.about");

        Assert.True(palette.TryRegister(unrelated));
        Assert.True(palette.TryRegister(substring));
        Assert.True(palette.TryRegister(prefix));
        Assert.True(palette.TryRegister(exact));

        Assert.Equal([exact, prefix, substring], palette.SearchPalette("open"));
        Assert.Equal([exact, prefix], palette.SearchPalette("workspace open", maximumResults: 2));
        Assert.Equal([exact, prefix], palette.SearchPalette("open", maximumResults: 2));
        Assert.Empty(palette.SearchPalette("not-a-command"));
        Assert.Equal(0, provider.CallCount);
    }

    [Fact]
    public async Task AvailabilityEvaluationAgreesWithTheCanonicalCapabilityProvider()
    {
        var asOf = new DateTimeOffset(2026, 9, 29, 12, 0, 0, TimeSpan.Zero);
        var owner = NewInstance(AppIdentity.ArcScope);
        var scope = new AvailabilityProviderScope(owner, "principal:test-user", "session:commands");
        const string capabilityKey = "IScopeOperations.GetSession";
        var target = AvailabilityTargetKey.ForProductInstance(NewInstance(AppIdentity.ArcScope));
        var registrations = new List<ActionAvailabilityRegistration>();
        var evidence = new List<AvailabilityEvidenceRecord>();
        var expected = new[]
        {
            AvailabilityResult.Available,
            AvailabilityResult.NotApplicableToContext,
            AvailabilityResult.AppNotInstalled,
            AvailabilityResult.AppNotRunning,
            AvailabilityResult.IncompatibleVersion,
            AvailabilityResult.PermissionRequired,
            AvailabilityResult.EntitlementRequired,
            AvailabilityResult.PolicyDisabled,
            AvailabilityResult.TemporarilyUnavailable,
        };

        for (int index = 0; index < expected.Length; index++)
        {
            string actionId = $"shell.action.availability.{index:D2}";
            string acceptedContext = index == 1 ? BoolValue.Descriptor.FullName : StringValue.Descriptor.FullName;
            var registration = new ActionAvailabilityRegistration(new ActionDescriptor
            {
                Key = actionId,
                TitleKey = $"{actionId}.title",
                AvailabilityRule = "capability.availability.v1",
                Capabilities = { capabilityKey },
                AcceptedContext = { acceptedContext },
            });
            registrations.Add(registration);

            var permissionDisposition = index == 5
                ? AvailabilityPermissionDisposition.Required
                : AvailabilityPermissionDisposition.Granted;
            var entitlementDisposition = index == 6
                ? AvailabilityEntitlementDisposition.Required
                : AvailabilityEntitlementDisposition.Satisfied;
            var policyDisposition = index == 7
                ? AvailabilityPolicyDisposition.Disabled
                : AvailabilityPolicyDisposition.Enabled;
            evidence.Add(new AvailabilityEvidenceRecord(
                registration.Key,
                capabilityKey,
                target,
                new AvailabilityTargetFacts(
                    index == 2 ? AvailabilityFactState.No : AvailabilityFactState.Yes,
                    index is 2 or 3 ? AvailabilityFactState.No : AvailabilityFactState.Yes,
                    index == 4 ? AvailabilityFactState.No : AvailabilityFactState.Yes,
                    index == 8 ? AvailabilityFactState.No : AvailabilityFactState.Yes,
                    AvailabilityFactState.Yes,
                    "2.4.0",
                    "target.generation.1",
                    asOf.AddMinutes(-1)),
                new AvailabilityPermissionEvidence(
                    owner,
                    scope.PrincipalKey,
                    capabilityKey,
                    permissionDisposition,
                    "scope:current-user",
                    ["constraint.owner", "constraint.read"],
                    asOf.AddHours(-1),
                    asOf.AddHours(1),
                    "permission.generation.1"),
                new AvailabilityEntitlementEvidence(
                    capabilityKey,
                    entitlementDisposition,
                    entitlementDisposition == AvailabilityEntitlementDisposition.Required
                        ? "entitlement.required"
                        : "entitlement.satisfied",
                    "producer.version.1",
                    "entitlement.generation.1"),
                new AvailabilityPolicyEvidence(policyDisposition, "policy.source", "policy.revision.1")));
        }

        var provider = new CapabilityAvailabilityProvider(
            CapabilityRegistry.CreateInitial(),
            registrations,
            scope,
            new AvailabilityEvidenceSnapshot(scope, asOf, AvailabilityFreshnessDisposition.Current, evidence));
        var context = FrozenContextSnapshot.Freeze(
            owner,
            [new StringValue { Value = "captured command context" }],
            ContextSnapshotBudget.Default);
        var palette = new ShellCommandPalette(provider);
        var commandIds = new string[registrations.Count];

        for (int index = 0; index < registrations.Count; index++)
        {
            commandIds[index] = $"command.availability.{index:D2}";
            Assert.True(palette.TryRegister(new ShellCommand(
                commandIds[index],
                $"Availability {index:D2}",
                registrations[index].Key)));
        }

        for (int index = 0; index < registrations.Count; index++)
        {
            var canonical = await ((ICapabilityProvider)provider).EvaluateAvailabilityAsync(
                registrations[index].Key,
                context,
                TestContext.Current.CancellationToken);
            var shell = await palette.EvaluateAvailabilityAsync(
                commandIds[index],
                context,
                TestContext.Current.CancellationToken);

            Assert.Equal(OutcomeKind.Success, canonical.Kind);
            Assert.Equal(OutcomeKind.Success, shell.Kind);
            Assert.True(canonical.TryGetValue(out var canonicalValue));
            Assert.True(shell.TryGetValue(out var shellValue));
            Assert.Equal(expected[index], canonicalValue);
            Assert.Equal(canonicalValue, shellValue);
        }

        var unknown = await palette.EvaluateAvailabilityAsync(
            "command.missing",
            context,
            TestContext.Current.CancellationToken);
        Assert.Equal(OutcomeKind.Failure, unknown.Kind);
        Assert.True(unknown.TryGetFailure(out var failure));
        Assert.Equal("validation.invalid_request", failure!.Code);
    }

    [Fact]
    public void TryResolveShortcutUsesNormalizedBindingsAndRefusesUnknownGestures()
    {
        var palette = new ShellCommandPalette(new CountingCapabilityProvider());
        var bound = Command(
            "workspace.open",
            "Open workspace",
            "shell.action.workspace.open",
            shortcut: new CommandShortcut("return", CommandShortcutModifiers.Control));
        Assert.True(palette.TryRegister(bound));

        Assert.True(palette.TryResolveShortcut(
            new CommandShortcut("ENTER", CommandShortcutModifiers.Control),
            out var resolved));
        Assert.Same(bound, resolved);
        Assert.False(palette.TryRegister(Command(
            "workspace.submit",
            "Submit workspace",
            "shell.action.workspace.submit",
            shortcut: new CommandShortcut("ENTER", CommandShortcutModifiers.Control))));
        Assert.True(palette.TryResolveShortcut(
            new CommandShortcut("RETURN", CommandShortcutModifiers.Control),
            out var stillBound));
        Assert.Same(bound, stillBound);

        Assert.False(palette.TryResolveShortcut(new CommandShortcut("F24"), out var unknown));
        Assert.Null(unknown);
    }

    private static ShellCommand Command(
        string id,
        string title,
        string actionKey,
        string description = "",
        IEnumerable<string>? keywords = null,
        CommandShortcut? shortcut = null) =>
        new(id, title, new ActionKey(actionKey), description, keywords, shortcut);

    private static InstanceIdentity NewInstance(AppIdentity app) =>
        new(
            new InstallationIdentity(app, IdentityGeneration.NewDevice(), IdentityGeneration.NewInstallation()),
            IdentityGeneration.NewInstance(),
            1);

    private sealed class CountingCapabilityProvider : ICapabilityProvider
    {
        public int CallCount { get; private set; }

        ValueTask<Outcome<AvailabilityResult>> ICapabilityProvider.EvaluateAvailabilityAsync(
            ActionKey actionKey,
            FrozenContextSnapshot context,
            CancellationToken cancellationToken)
        {
            CallCount++;
            return ValueTask.FromResult(Outcome.Success(AvailabilityResult.Available));
        }
    }
}
