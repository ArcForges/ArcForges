// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Contracts.Node.V1;

namespace ArcForges.Node.Store.Policy;

/// <summary>
/// The default <see cref="PolicyDocument"/>, stored as policy revision 1 when a store is created (node-store.md,
/// 13-distribution-updates section 3.5). It sets every default that policy.proto states as a value, the built-in pools
/// (03 section 4) and the secret name patterns (04 section 2). Defaults that are derived from the machine or user at use
/// (<c>global_max_running</c> = 0 meaning automatic, <c>max_task_memory_bytes</c>, <c>allow_unenforced</c>, the sccache port
/// slice) stay unset, and list defaults that other architecture sections define as data for their own subsystems (routing
/// heavy and passthrough patterns, 08 section 4.1; the diagnosis action table, 07 section 2.2; root and cache quotas, 06
/// section 1 and 05 section 4) are left to the tasks that implement those subsystems.
/// </summary>
public static class DefaultPolicy
{
    private const ulong GiB = 1024UL * 1024 * 1024;
    private const ulong MiB = 1024UL * 1024;

    /// <summary>The default secret name patterns (04-execution section 2; policy <c>privacy.secret_name_patterns</c>).</summary>
    public static IReadOnlyList<string> SecretNamePatterns { get; } =
    [
        "*TOKEN*", "*SECRET*", "*PASSWORD*", "*PASSWD*", "*_KEY", "*APIKEY*", "AWS_*", "AZURE_*", "GH_*", "GITHUB_TOKEN", "NPM_TOKEN",
    ];

    /// <summary>The built-in pools (03-resource-control section 4).</summary>
    public static IReadOnlyList<string> BuiltInPools { get; } = ["interactive", "default", "background", "agents"];

    /// <summary>A new copy of the default document.</summary>
    public static PolicyDocument Create()
    {
        var document = new PolicyDocument
        {
            Resources = new ResourcePolicy
            {
                ReserveCpuFixedMillicores = 1_000,
                ReserveCpuFraction = 0.10,
                ReserveMemFixedBytes = 2 * GiB,
                ReserveMemFraction = 0.10,
                MinManagedCpuMillicores = 1_000,
                OvercommitCpu = 1.5,
                OvercommitMem = 1.0,
                SmoothingAlphaUp = 0.5,
                SmoothingAlphaDown = 0.1,
                GlobalMaxRunning = 0,
                StarvationBoundMs = 10 * 60 * 1_000,
                LargeTaskBypassMs = 2 * 60 * 1_000,
                CommitFactor = 1.5,
                Pressure = new PressureThresholds
                {
                    TightAvailableFraction = 0.10,
                    PressureAvailableFraction = 0.05,
                    CriticalAvailableFraction = 0.02,
                    MemoryPsiSomeAvg10 = 20,
                    FreezeOnPressure = true,
                    CancelOnCritical = true,
                },
                SwapAllowanceBytes = 0,
                LargeTaskReservationMaxMs = 30 * 60 * 1_000,
            },
            Agents = new AgentPolicy
            {
                AllowInteractivePriority = false,
                DefaultPool = "agents",
                MaxRunningPerSession = 0,
            },
            Routing = new RoutingPolicy
            {
                DefaultMode = RoutingMode.Observe,
                BypassCpuThresholdMillicores = 1_000,
                BypassMemThresholdBytes = GiB,
                RewritePermission = ClientPermission.Ask,
                GuideWhenLongerThanClientTimeout = true,
                HandoffMarginMs = 15_000,
                JoinExistingRewrites = true,
                LightCpuMillicores = 250,
                LightMemBytes = 128 * MiB,
            },
            Diagnosis = new DiagnosisPolicy
            {
                CheckIntervalMs = 15_000,
                StallThresholdMs = 5 * 60 * 1_000,
                IdleThresholdMs = 60_000,
            },
            Storage = new StoragePolicy
            {
                LogRetentionDays = 14,
                LogRetentionBytes = 5 * GiB,
                RecordRetentionDays = 90,
                KeepFailedTmp = true,
                KeepFailedTmpHours = 24,
                AutoRegisterWorkspaces = true,
                MinFreeBytes = GiB,
                SecretRetentionHours = 24,
                MaxAttemptOutputBytes = 2 * GiB,
                MaxAttemptTmpBytes = 20 * GiB,
                CriticalFreeBytes = 512 * MiB,
                DiskLimitAction = DiskLimitAction.Terminate,
                LowFreeCapBytes = 20 * GiB,
                GuardTakeoverMs = 5_000,
                MaxAttemptTmpEntries = 1_000_000,
            },
            Cleanup = new CleanupPolicy
            {
                AgentExecute = AgentCleanupMode.Approval,
                QuarantineHours = 24,
                AbandonedWorktreeDays = 14,
            },
            Caches = new CachePolicy
            {
                DotnetSharedBuildServers = false,
                RedirectToolCaches = true,
                UsageScanBudgetMs = 2_000,
            },
            Privacy = new PrivacyPolicy
            {
                RemoteCommandLines = false,
                RemoteOutputTail = false,
                PeerCommandLines = false,
            },
            Remote = new RemoteControlPolicy
            {
                Enabled = false,
                MaxRisk = RiskClass.Low,
                AllowApprovals = false,
            },
            Updates = new UpdatePolicy
            {
                Mode = UpdateMode.Auto,
                Channel = "stable",
                Metered = MeteredBehavior.Defer,
            },
            Lan = new LanPolicy
            {
                Enabled = false,
                Port = 47_820,
                Advertise = true,
                AdvertiseAccountHint = false,
                MaxWorkspaceSlots = 2,
            },
            Approvals = new ApprovalPolicy
            {
                DefaultTtlMs = 24 * 60 * 60 * 1_000,
                NotifyDesktop = true,
                NotifyPush = true,
            },
            ResultCache = new ResultCachePolicy
            {
                DefaultMode = ResultCacheMode.Off,
            },
            RetrySafety = new RetrySafetyPolicy
            {
                AcceptAgentAssertions = false,
            },
        };

        document.Agents.AllowedCommandPatterns.Add(".*");
        document.Privacy.SecretNamePatterns.AddRange(SecretNamePatterns);
        foreach (var pool in BuiltInPools)
        {
            document.Pools.Add(new PoolPolicy
            {
                Name = pool,
                Weight = 1,
                MaxParallelMode = ParallelismMode.Auto,
                BuiltIn = true,
            });
        }

        return document;
    }
}
