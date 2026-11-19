// SPDX-License-Identifier: AGPL-3.0-only
namespace ArcForges.RunSupervisor.Protocol;

public enum RunTerminalMode
{
    Pipes = 1,
    Interactive = 2,
}

public enum RunOwnerState
{
    Ready,
    Starting,
    Running,
    Stopping,
    Draining,
    Exited,
    Failed,
    RecoveryRequired,
}

public enum RunPayloadStart
{
    Unknown = 1,
    NotStarted = 2,
    Confirmed = 3,
}

public static class RunExitSources
{
    public const string OfficialExecutor = "official_executor";
    public const string Payload = "payload";
    public const string Supervisor = "supervisor";
    public const string Unknown = "unknown";
}

public sealed record RunEnvironment(string Name, string Value);

public sealed record RunMount(string HostPath, string SandboxPath, bool Writable, string? NativeIdentity = null);

public sealed record RunNetwork(bool EgressAllowed, bool IngressAllowed, bool HostLoopback, string[] Destinations);

/// <summary>One private handoff from the authorized Node to one owner. The workload must never read this record.</summary>
public sealed record RunLaunchSpec
{
    public required string RunId { get; init; }
    public required string SandboxId { get; init; }
    public required string Epoch { get; init; }
    public required string OwnerId { get; init; }
    public required string LaunchSha256 { get; init; }
    public required string ControlDirectory { get; init; }
    public required string ControlEndpoint { get; init; }
    public required byte[] ControlKey { get; init; }
    public required string SupervisorPath { get; init; }
    public required string SupervisorSha256 { get; init; }
    public required string InstallationRoot { get; init; }
    public required string ProfileId { get; init; }
    public required string ProfileVersion { get; init; }
    public required string PrivateRoot { get; init; }
    public string? PrivateRootIdentity { get; init; }
    public required string WorkingDirectory { get; init; }
    public string? WorkingDirectoryIdentity { get; init; }
    public string? ExecutableIdentity { get; init; }
    public required string[] Argv { get; init; }
    public required RunEnvironment[] Environment { get; init; }
    public required RunMount[] Mounts { get; init; }
    public required RunNetwork Network { get; init; }
    public required RunTerminalMode TerminalMode { get; init; }
    public required uint Rows { get; init; }
    public required uint Columns { get; init; }
    public required uint CpuMillicores { get; init; }
    public required ulong MemoryMaxBytes { get; init; }
    public required uint MaxProcesses { get; init; }
    public uint? CpuWeight { get; init; }
    public required ulong OutputLimitBytes { get; init; }
    public string? BubblewrapPath { get; init; }
    public string? BubblewrapIdentity { get; init; }
    public string? BoundaryDescriptor { get; init; }
    public int LauncherProcessId { get; init; }
    public string? LauncherCreationIdentity { get; init; }
    public string? LauncherPath { get; init; }
}

public sealed record RunOwnerIdentity(
    string InstanceId, string BootId, int ProcessId, string CreationIdentity, string Endpoint,
    string BoundaryIdentity, string BackendId, string Cohort, string ControlEpoch);

public sealed record RunRelease(long? NativeBoundaryHandle = null);

public sealed record RunOwnerObservation(
    RunOwnerState State,
    RunPayloadStart PayloadStarted,
    bool GroupEmptyVerified,
    int? RawExitCode = null,
    string? ExitSource = null,
    string? TerminationReason = null,
    string? NativeError = null)
{
    public bool IsTerminal => State is RunOwnerState.Exited or RunOwnerState.Failed;
}

/// <summary>Starts the trusted owner and binds its native scope before any runnable payload can enter it.</summary>
public interface IRunLauncher
{
    ValueTask<IRunOwnerLease> PrepareAsync(RunLaunchSpec spec, CancellationToken cancellationToken);
}

public interface IRunOwnerLease : IAsyncDisposable
{
    RunOwnerIdentity Identity { get; }
    ValueTask ActivateAsync(CancellationToken cancellationToken);
    ValueTask StopAsync(TimeSpan grace, CancellationToken cancellationToken);
    ValueTask<RunOwnerObservation> ObserveAsync(CancellationToken cancellationToken);
}

/// <summary>Owner-local execution. These handles outlive the Node connection that activated the Run.</summary>
public interface IRunWorkerSession : IAsyncDisposable
{
    ValueTask StopAsync(TimeSpan grace, CancellationToken cancellationToken);
    ValueTask<RunOwnerObservation> ObserveAsync(CancellationToken cancellationToken);
}

public sealed class RunNativeException(string phase, string nativeCode, bool boundaryEmptyVerified = false,
    bool payloadNotStarted = false) : IOException(phase)
{
    public string Phase { get; } = phase;
    public string NativeCode { get; } = nativeCode;
    public bool BoundaryEmptyVerified { get; } = boundaryEmptyVerified;
    public bool PayloadNotStarted { get; } = payloadNotStarted;
}
