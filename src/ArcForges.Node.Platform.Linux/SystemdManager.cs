// SPDX-License-Identifier: AGPL-3.0-only
using System.Collections.Concurrent;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Text;
using Tmds.DBus.Protocol;

namespace ArcForges.Node.Platform.Linux;

/// <summary>
/// A command of a unit's <c>ExecStart</c>, <c>ExecStop</c> or <c>ExecStopPost</c>. Written as the <c>Ex</c> form (D-Bus <c>a(sasas)</c>,
/// systemd 243 and later) with the flag <c>no-env-expand</c>, because systemd otherwise expands <c>$VAR</c>, <c>${VAR}</c> and <c>$$</c>
/// in the arguments: the program must receive its argument vector exactly (R-EXE-003). <c>ignore-failure</c> is the <c>-</c> prefix.
/// </summary>
/// <param name="Path">The executable.</param>
/// <param name="Argv">The argument vector, <c>argv[0]</c> included.</param>
/// <param name="IgnoreFailure">The <c>-</c> prefix: a failure does not change the unit's result.</param>
public sealed record ExecCommand(string Path, IReadOnlyList<string> Argv, bool IgnoreFailure)
{
    /// <summary>The flags of the <c>Ex</c> form.</summary>
    public string[] Flags => IgnoreFailure ? ["ignore-failure", "no-env-expand"] : ["no-env-expand"];
}

/// <summary>Exit statuses and signals that count as success (D-Bus <c>(aiai)</c>, <c>SuccessExitStatus</c>).</summary>
/// <param name="Statuses">Exit statuses.</param>
/// <param name="Signals">Signal numbers.</param>
public sealed record ExitStatusSet(IReadOnlyList<int> Statuses, IReadOnlyList<int> Signals);

/// <summary>One unit property of <c>StartTransientUnit</c> or <c>SetUnitProperties</c>.</summary>
/// <param name="Name">The property name.</param>
/// <param name="Value">A <see cref="string"/> (s), <see cref="ulong"/> (t), <see cref="int"/> (i), <see cref="bool"/> (b), a
/// <see cref="string"/> array (as), a <see cref="uint"/> array (au), a <see cref="SafeHandle"/> (h), a list of <see cref="ExecCommand"/> (a(sasb)) or an
/// <see cref="ExitStatusSet"/> ((aiai)).</param>
public readonly record struct UnitProperty(string Name, object Value);

/// <summary>A unit's state as the node reads it (properties of <c>org.freedesktop.systemd1.Unit</c> and <c>.Service</c>).</summary>
/// <param name="ActiveState">active, reloading, inactive, failed, activating or deactivating.</param>
/// <param name="SubState">The service's sub-state.</param>
/// <param name="Result">The service's result (success, exit-code, signal, oom-kill, timeout, ...).</param>
/// <param name="MainPid">The main process, or 0.</param>
/// <param name="ControlGroup">The unit's cgroup path, or empty.</param>
/// <param name="ExecMainCode">The main process's <c>si_code</c>: 1 exited, 2 killed, 3 dumped, 0 none.</param>
/// <param name="ExecMainStatus">Its exit status or signal number.</param>
/// <param name="MemoryPeak">The unit's peak memory (systemd's record; survives a failed unit).</param>
/// <param name="MemorySwapPeak">The unit's peak swap.</param>
/// <param name="CpuUsageNs">The unit's CPU time.</param>
/// <param name="ControlPid">The running control process (<c>ExecStop</c>, <c>ExecStopPost</c>), or 0.</param>
/// <param name="ExecMainPid">The main process of the last start, also after it exited.</param>
/// <param name="ExecMainStartUs">When that main process started (realtime microseconds), or 0.</param>
public sealed record UnitState(string ActiveState, string SubState, string Result, uint MainPid, string ControlGroup, int ExecMainCode, int ExecMainStatus,
    ulong MemoryPeak, ulong MemorySwapPeak, ulong CpuUsageNs, uint ControlPid, uint ExecMainPid, ulong ExecMainStartUs);

/// <summary>
/// A client of the systemd user manager's D-Bus API (AD-0005 Linux section 2) over the user bus, or over the manager's private socket
/// where the user has no bus (<see cref="DefaultAddress"/>), with <c>Tmds.DBus.Protocol</c> (AOT-compatible). It subscribes to the manager's signals (<c>JobRemoved</c>, and <c>PropertiesChanged</c>
/// of units) and offers the calls the platform and the guard make, each bounded by <see cref="CallTimeout"/>. Signal handlers never block.
/// </summary>
[SupportedOSPlatform("linux")]
public sealed class SystemdManager : IDisposable
{
    /// <summary>The manager's bus name.</summary>
    public const string Service = "org.freedesktop.systemd1";

    /// <summary>The manager object.</summary>
    public const string ManagerPath = "/org/freedesktop/systemd1";

    /// <summary>The manager interface.</summary>
    public const string ManagerInterface = "org.freedesktop.systemd1.Manager";

    /// <summary>The unit interface.</summary>
    public const string UnitInterface = "org.freedesktop.systemd1.Unit";

    /// <summary>The service interface.</summary>
    public const string ServiceInterface = "org.freedesktop.systemd1.Service";

    /// <summary>The error of a unit that is not loaded.</summary>
    public const string NoSuchUnit = "org.freedesktop.systemd1.NoSuchUnit";

    /// <summary>The bound of every call.</summary>
    public static readonly TimeSpan CallTimeout = TimeSpan.FromSeconds(10);

    private const string PropertiesInterface = "org.freedesktop.DBus.Properties";
    private static readonly TimeSpan FinishedJobRetention = TimeSpan.FromMinutes(2);
    private readonly DBusConnection _connection;
    private readonly ConcurrentDictionary<string, TaskCompletionSource<string>> _jobWaiters = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, (string Result, long At)> _finishedJobs = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, Action> _unitWatchers = new(StringComparer.Ordinal);
    private readonly List<IDisposable> _matches = [];
    private int _disposed;

    private SystemdManager(DBusConnection connection, string address)
    {
        _connection = connection;
        Address = address;
    }

    /// <summary>The address connected to.</summary>
    public string Address { get; }

    /// <summary>The manager's version (for example <c>257.13-1~deb13u1</c>).</summary>
    public string Version { get; private set; } = string.Empty;

    /// <summary>True once the connection closed (the user manager restarted or stopped).</summary>
    public bool Closed { get; private set; }

    /// <summary>
    /// The user manager's address: the user bus <c>$XDG_RUNTIME_DIR/bus</c> (or <c>/run/user/&lt;uid&gt;/bus</c>) when it exists, where the
    /// manager is <c>org.freedesktop.systemd1</c>; otherwise its private socket <c>$XDG_RUNTIME_DIR/systemd/private</c>; null when neither
    /// exists (no user manager runs for this user). The bus comes first: on the private (peer) socket, Tmds.DBus.Protocol's connection
    /// setup stalls in about one connection in four on systemd 257 (seen in WSL2 Debian), while it never did on the bus.
    /// </summary>
    public static string? DefaultAddress()
    {
        var runtime = Environment.GetEnvironmentVariable("XDG_RUNTIME_DIR");
        if (string.IsNullOrEmpty(runtime) || !Path.IsPathFullyQualified(runtime))
        {
            runtime = "/run/user/" + ProcFs.UserId.ToString(CultureInfo.InvariantCulture);
        }

        var privateSocket = Path.Combine(runtime, "systemd", "private");
        if (!File.Exists(privateSocket))
        {
            return null;
        }

        var bus = Path.Combine(runtime, "bus");
        return File.Exists(bus) ? "unix:path=" + bus : "unix:path=" + privateSocket;
    }

    /// <summary>True when connected to a bus (signals need match rules there), false on the manager's private socket.</summary>
    public bool OnBus => !Address.EndsWith("/systemd/private", StringComparison.Ordinal);

    /// <summary>
    /// Connects, subscribes to the manager's signals and reads its version, within <paramref name="timeout"/>. One connection attempt is
    /// bounded to 1 s and retried: on systemd 257 an attempt occasionally stalls in the authentication exchange (seen in about one in four
    /// connections in WSL2 Debian) while the next one completes in milliseconds.
    /// </summary>
    /// <exception cref="DBusExceptionBase">The manager refused.</exception>
    /// <exception cref="TimeoutException">It did not answer within <paramref name="timeout"/>.</exception>
    public static SystemdManager Connect(string address, TimeSpan timeout)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(address);
        var deadline = Environment.TickCount64 + (long)timeout.TotalMilliseconds;
        var attempts = 0;
        while (true)
        {
            attempts++;
            var remaining = TimeSpan.FromMilliseconds(Math.Max(100, deadline - Environment.TickCount64));
            var attempt = remaining < TimeSpan.FromSeconds(1) ? remaining : TimeSpan.FromSeconds(1);
            try
            {
                return ConnectOnce(address, attempt);
            }
            catch (TimeoutException exception) when (Environment.TickCount64 < deadline)
            {
                // Retried; the last attempt's failure is reported.
                _ = exception;
            }
            catch (TimeoutException exception)
            {
                throw new TimeoutException($"The systemd user manager did not answer in time ({attempts} attempts; {exception.Message}).", exception);
            }
        }
    }

    private static SystemdManager ConnectOnce(string address, TimeSpan timeout)
    {
        var connection = new DBusConnection(new DBusConnectionOptions(address) { AutoConnect = false });
        var manager = new SystemdManager(connection, address);
        var step = "connect";
        try
        {
            Run(async () =>
            {
                await connection.ConnectAsync().AsTask().WaitAsync(timeout).ConfigureAwait(false);
                step = "subscribe";
                await manager.SubscribeAsync().WaitAsync(timeout).ConfigureAwait(false);
                step = "version";
                manager.Version = (await manager.GetAsync(ManagerPath, ManagerInterface, "Version").WaitAsync(timeout).ConfigureAwait(false)).GetString();
                step = "done";
                return true;
            }, timeout + timeout);
            _ = connection.DisconnectedAsync().ContinueWith(_ => manager.Closed = true, TaskScheduler.Default);
            return manager;
        }
        catch (TimeoutException exception)
        {
            manager.Dispose();
            throw new TimeoutException("step " + step, exception);
        }
        catch
        {
            manager.Dispose();
            throw;
        }
    }
    /// <summary>The object path of a unit name (systemd's bus label escaping).</summary>
    public static string UnitPath(string unit)
    {
        ArgumentNullException.ThrowIfNull(unit);
        var builder = new StringBuilder("/org/freedesktop/systemd1/unit/");
        for (var index = 0; index < unit.Length; index++)
        {
            var character = unit[index];
            if (char.IsAsciiLetter(character) || (char.IsAsciiDigit(character) && index > 0))
            {
                builder.Append(character);
            }
            else
            {
                foreach (var value in Encoding.UTF8.GetBytes(character.ToString()))
                {
                    builder.Append('_').Append(value.ToString("x2", CultureInfo.InvariantCulture));
                }
            }
        }

        return builder.ToString();
    }

    /// <summary>The manager's environment block (<c>Environment</c>).</summary>
    public string[] ManagerEnvironment() => Run(async () => (await GetAsync(ManagerPath, ManagerInterface, "Environment").ConfigureAwait(false)).GetArray<string>());

    /// <summary>A manager property as text.</summary>
    public string ManagerString(string property) => Run(async () => (await GetAsync(ManagerPath, ManagerInterface, property).ConfigureAwait(false)).GetString());

    /// <summary>A manager property as an unsigned 64-bit number.</summary>
    public ulong ManagerNumber(string property) => Run(async () => (await GetAsync(ManagerPath, ManagerInterface, property).ConfigureAwait(false)).GetUInt64());

    /// <summary><c>StartTransientUnit(name, "fail", properties, [])</c>; returns the job's object path.</summary>
    public string StartTransientUnit(string name, IReadOnlyList<UnitProperty> properties)
    {
        ArgumentNullException.ThrowIfNull(properties);
        var writer = _connection.GetMessageWriter();
        MessageBuffer message;
        try
        {
            writer.WriteMethodCallHeader(Service, ManagerPath, ManagerInterface, "StartTransientUnit", "ssa(sv)a(sa(sv))", MessageFlags.None);
            writer.WriteString(name);
            writer.WriteString("fail");
            WriteProperties(ref writer, properties);
            var auxiliary = writer.WriteArrayStart(DBusType.Struct);
            writer.WriteArrayEnd(auxiliary);
            message = writer.CreateMessage();
        }
        finally
        {
            writer.Dispose();
        }

        return Run(() => _connection.CallMethodAsync(message, static (Message reply, object? _) => reply.GetBodyReader().ReadObjectPathAsString()));
    }

    /// <summary><c>SetUnitProperties(name, runtime, properties)</c>.</summary>
    public void SetUnitProperties(string name, bool runtime, IReadOnlyList<UnitProperty> properties)
    {
        ArgumentNullException.ThrowIfNull(properties);
        var writer = _connection.GetMessageWriter();
        MessageBuffer message;
        try
        {
            writer.WriteMethodCallHeader(Service, ManagerPath, ManagerInterface, "SetUnitProperties", "sba(sv)", MessageFlags.None);
            writer.WriteString(name);
            writer.WriteBool(runtime);
            WriteProperties(ref writer, properties);
            message = writer.CreateMessage();
        }
        finally
        {
            writer.Dispose();
        }

        Run(async () =>
        {
            await _connection.CallMethodAsync(message).ConfigureAwait(false);
            return true;
        });
    }

    /// <summary>Waits for a job's <c>JobRemoved</c> signal; returns its result (<c>done</c>, <c>failed</c>, ...) or null on timeout.</summary>
    public string? WaitJob(string job, TimeSpan timeout)
    {
        ArgumentNullException.ThrowIfNull(job);
        var waiter = _jobWaiters.GetOrAdd(job, _ => new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously));
        if (_finishedJobs.TryRemove(job, out var finished))
        {
            waiter.TrySetResult(finished.Result);
        }

        try
        {
            return waiter.Task.Wait(timeout) ? waiter.Task.Result : null;
        }
        finally
        {
            _jobWaiters.TryRemove(job, out _);
        }
    }

    /// <summary><c>GetUnit(name)</c>: the unit's object path, or null when it is not loaded.</summary>
    public string? GetUnit(string name)
    {
        try
        {
            return Run(() => _connection.CallMethodAsync(Message("GetUnit", "s", name), static (Message reply, object? _) => reply.GetBodyReader().ReadObjectPathAsString()));
        }
        catch (DBusErrorReplyException exception) when (exception.ErrorName == NoSuchUnit)
        {
            return null;
        }
    }

    /// <summary><c>LoadUnit(name)</c>: its <c>LoadState</c>, <c>ActiveState</c> and <c>FragmentPath</c> (empty without a unit file).</summary>
    public (string LoadState, string ActiveState, string FragmentPath) LoadUnit(string name) => Run(async () =>
    {
        var path = await _connection.CallMethodAsync(Message("LoadUnit", "s", name), static (Message reply, object? _) => reply.GetBodyReader().ReadObjectPathAsString())
            .ConfigureAwait(false);
        var unit = await GetAllAsync(path, UnitInterface).ConfigureAwait(false);
        return (Text(unit, "LoadState"), Text(unit, "ActiveState"), Text(unit, "FragmentPath"));
    });

    /// <summary>The state of a loaded unit, or null when it is not loaded.</summary>
    public UnitState? State(string name)
    {
        var path = GetUnit(name);
        if (path is null)
        {
            return null;
        }

        try
        {
            return Run(async () =>
            {
                var unit = await GetAllAsync(path, UnitInterface).ConfigureAwait(false);
                var service = await GetAllAsync(path, ServiceInterface).ConfigureAwait(false);
                return new UnitState(
                    Text(unit, "ActiveState"), Text(unit, "SubState"), Text(service, "Result"), Number32(service, "MainPID"), Text(service, "ControlGroup"),
                    Int32(service, "ExecMainCode"), Int32(service, "ExecMainStatus"), Number64(service, "MemoryPeak"), Number64(service, "MemorySwapPeak"),
                    Number64(service, "CPUUsageNSec"), Number32(service, "ControlPID"), Number32(service, "ExecMainPID"), Number64(service, "ExecMainStartTimestamp"));
            });
        }
        catch (DBusErrorReplyException exception) when (exception.ErrorName is NoSuchUnit or "org.freedesktop.DBus.Error.UnknownObject")
        {
            return null;
        }
    }

    /// <summary>The cgroup path of a loaded scope unit (<c>org.freedesktop.systemd1.Scope.ControlGroup</c>), or null when it is not loaded.</summary>
    public string? ScopeControlGroup(string name)
    {
        var path = GetUnit(name);
        return path is null ? null : Run(async () => (await GetAsync(path, "org.freedesktop.systemd1.Scope", "ControlGroup").ConfigureAwait(false)).GetString());
    }

    /// <summary><c>KillUnit(name, whom, signal)</c>.</summary>
    public void KillUnit(string name, string whom, int signal) => Call(Message("KillUnit", "ssi", name, whom, signal));

    /// <summary>
    /// <c>AttachProcessesToUnit(name, "", pids)</c> (systemd 238): moves processes into a running unit's cgroup. The user manager can move
    /// only processes inside its own subtree (V-L01); others are refused with an error reply.
    /// </summary>
    public void AttachProcessesToUnit(string name, uint[] pids) => Call(Message("AttachProcessesToUnit", "ssau", name, string.Empty, pids));

    /// <summary><c>FreezeUnit(name)</c>: returns once the unit's cgroup is frozen.</summary>
    public void FreezeUnit(string name) => Call(Message("FreezeUnit", "s", name));

    /// <summary><c>ThawUnit(name)</c>.</summary>
    public void ThawUnit(string name) => Call(Message("ThawUnit", "s", name));

    /// <summary><c>ResetFailedUnit(name)</c>: a failed unit is unloaded.</summary>
    public void ResetFailedUnit(string name) => Call(Message("ResetFailedUnit", "s", name));

    /// <summary><c>ListUnitsByPatterns(["failed"], [pattern])</c>: the names of the failed units matching <paramref name="pattern"/>.</summary>
    public HashSet<string> FailedUnits(string pattern) => Run(() => _connection.CallMethodAsync(Message("ListUnitsByPatterns", "asas", (string[])["failed"], (string[])[pattern]),
        static (Message reply, object? _) =>
        {
            // a(ssssssouso): name, description, load, active, sub, following, unit path, job id, job type, job path.
            var names = new HashSet<string>(StringComparer.Ordinal);
            var reader = reply.GetBodyReader();
            var end = reader.ReadArrayStart(DBusType.Struct);
            while (reader.HasNext(end))
            {
                reader.AlignStruct();
                names.Add(reader.ReadString());
                for (var field = 0; field < 5; field++)
                {
                    _ = reader.ReadString();
                }

                _ = reader.ReadObjectPathAsString();
                _ = reader.ReadUInt32();
                _ = reader.ReadString();
                _ = reader.ReadObjectPathAsString();
            }

            return names;
        }));

    /// <summary><c>StartUnit(name, "replace")</c>; returns the job.</summary>
    public string StartUnit(string name) =>
        Run(() => _connection.CallMethodAsync(Message("StartUnit", "ss", name, "replace"), static (Message reply, object? _) => reply.GetBodyReader().ReadObjectPathAsString()));

    /// <summary><c>StopUnit(name, "replace")</c>; returns the job.</summary>
    public string StopUnit(string name) =>
        Run(() => _connection.CallMethodAsync(Message("StopUnit", "ss", name, "replace"), static (Message reply, object? _) => reply.GetBodyReader().ReadObjectPathAsString()));

    /// <summary>Calls <paramref name="changed"/> (on the connection's thread, never blocking it) when a property of the unit at <paramref name="unitPath"/> changes.</summary>
    public IDisposable WatchUnit(string unitPath, Action changed)
    {
        ArgumentNullException.ThrowIfNull(unitPath);
        _unitWatchers[unitPath] = changed;
        return new Unwatch(this, unitPath);
    }

    /// <inheritdoc />
    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        foreach (var match in _matches)
        {
            match.Dispose();
        }

        _connection.Dispose();
        foreach (var waiter in _jobWaiters.Values)
        {
            waiter.TrySetCanceled();
        }
    }

    /// <summary>Runs a call on the thread pool and waits for it, bounded by <see cref="CallTimeout"/>.</summary>
    internal static T Run<T>(Func<Task<T>> operation, TimeSpan? timeout = null)
    {
        var task = Task.Run(operation);
        try
        {
            return task.WaitAsync(timeout ?? CallTimeout).GetAwaiter().GetResult();
        }
        catch (TimeoutException)
        {
            throw new TimeoutException("The systemd user manager did not answer in time.");
        }
    }

    private void Call(MessageBuffer message) => Run(async () =>
    {
        await _connection.CallMethodAsync(message).ConfigureAwait(false);
        return true;
    });

    private async Task SubscribeAsync()
    {
        _matches.Add(await _connection.AddMatchAsync(
            new MatchRule { Type = MessageType.Signal, Interface = ManagerInterface, Member = "JobRemoved" },
            static (Message message, object? _) =>
            {
                var reader = message.GetBodyReader();
                _ = reader.ReadUInt32();
                var job = reader.ReadObjectPathAsString();
                var unit = reader.ReadString();
                return (Job: job, Unit: unit, Result: reader.ReadString());
            },
            (Notification<(string Job, string Unit, string Result)> notification) =>
            {
                if (!notification.HasValue)
                {
                    return;
                }

                var removed = notification.Value;
                if (_jobWaiters.TryGetValue(removed.Job, out var waiter))
                {
                    waiter.TrySetResult(removed.Result);
                }
                else if (removed.Unit.StartsWith("arcforges", StringComparison.Ordinal))
                {
                    var now = Environment.TickCount64;
                    _finishedJobs[removed.Job] = (removed.Result, now);
                    foreach (var (key, value) in _finishedJobs)
                    {
                        if (now - value.At > FinishedJobRetention.TotalMilliseconds)
                        {
                            _finishedJobs.TryRemove(key, out _);
                        }
                    }
                }
            },
            false, OnBus ? ObserverFlags.None : ObserverFlags.NoSubscribe, null).ConfigureAwait(false));
        _matches.Add(await _connection.AddMatchAsync(
            new MatchRule { Type = MessageType.Signal, Interface = PropertiesInterface, Member = "PropertiesChanged" },
            static (Message message, object? _) => message.PathAsString ?? string.Empty,
            (Notification<string> notification) =>
            {
                if (notification.HasValue && _unitWatchers.TryGetValue(notification.Value, out var changed))
                {
                    changed();
                }
            },
            false, OnBus ? ObserverFlags.None : ObserverFlags.NoSubscribe, null).ConfigureAwait(false));
        await _connection.CallMethodAsync(Message("Subscribe", null)).ConfigureAwait(false);
    }

    private Task<VariantValue> GetAsync(string path, string @interface, string property)
    {
        var writer = _connection.GetMessageWriter();
        try
        {
            writer.WriteMethodCallHeader(Service, path, PropertiesInterface, "Get", "ss", MessageFlags.None);
            writer.WriteString(@interface);
            writer.WriteString(property);
            var message = writer.CreateMessage();
            return _connection.CallMethodAsync(message, static (Message reply, object? _) => reply.GetBodyReader().ReadVariantValue());
        }
        finally
        {
            writer.Dispose();
        }
    }

    private Task<Dictionary<string, VariantValue>> GetAllAsync(string path, string @interface)
    {
        var writer = _connection.GetMessageWriter();
        try
        {
            writer.WriteMethodCallHeader(Service, path, PropertiesInterface, "GetAll", "s", MessageFlags.None);
            writer.WriteString(@interface);
            var message = writer.CreateMessage();
            return _connection.CallMethodAsync(message, static (Message reply, object? _) => reply.GetBodyReader().ReadDictionaryOfStringToVariantValue());
        }
        finally
        {
            writer.Dispose();
        }
    }

    private MessageBuffer Message(string member, string? signature, params object[] arguments)
    {
        var writer = _connection.GetMessageWriter();
        try
        {
            writer.WriteMethodCallHeader(Service, ManagerPath, ManagerInterface, member, signature, MessageFlags.None);
            foreach (var argument in arguments)
            {
                switch (argument)
                {
                    case string text:
                        writer.WriteString(text);
                        break;
                    case int number:
                        writer.WriteInt32(number);
                        break;
                    case bool flag:
                        writer.WriteBool(flag);
                        break;
                    case uint[] numbers:
                        writer.WriteArray(numbers);
                        break;
                    case string[] texts:
                        var array = writer.WriteArrayStart(DBusType.String);
                        foreach (var text in texts)
                        {
                            writer.WriteString(text);
                        }

                        writer.WriteArrayEnd(array);
                        break;
                    default:
                        throw new ArgumentException("Unsupported argument type.", nameof(arguments));
                }
            }

            return writer.CreateMessage();
        }
        finally
        {
            writer.Dispose();
        }
    }

    private static void WriteProperties(ref MessageWriter writer, IReadOnlyList<UnitProperty> properties)
    {
        var array = writer.WriteArrayStart(DBusType.Struct);
        foreach (var property in properties)
        {
            writer.WriteStructureStart();
            writer.WriteString(property.Name);
            switch (property.Value)
            {
                case string text:
                    writer.WriteVariantString(text);
                    break;
                case ulong number:
                    writer.WriteVariantUInt64(number);
                    break;
                case int number:
                    writer.WriteVariantInt32(number);
                    break;
                case bool flag:
                    writer.WriteVariantBool(flag);
                    break;
                case string[] texts:
                    writer.WriteSignature("as");
                    writer.WriteArray(texts);
                    break;
                case uint[] numbers:
                    writer.WriteSignature("au");
                    writer.WriteArray(numbers);
                    break;
                case SafeHandle handle:
                    writer.WriteVariantHandle(handle);
                    break;
                case IReadOnlyList<ExecCommand> commands:
                    // ExecStartEx, ExecStopEx, ExecStopPostEx: a(sasas) with flags; the plain names take a(sasb).
                    var extended = property.Name.EndsWith("Ex", StringComparison.Ordinal);
                    writer.WriteSignature(extended ? "a(sasas)" : "a(sasb)");
                    var list = writer.WriteArrayStart(DBusType.Struct);
                    foreach (var command in commands)
                    {
                        writer.WriteStructureStart();
                        writer.WriteString(command.Path);
                        writer.WriteArray(command.Argv.ToArray());
                        if (extended)
                        {
                            writer.WriteArray(command.Flags);
                        }
                        else
                        {
                            writer.WriteBool(command.IgnoreFailure);
                        }
                    }

                    writer.WriteArrayEnd(list);
                    break;
                case ExitStatusSet set:
                    writer.WriteSignature("(aiai)");
                    writer.WriteStructureStart();
                    writer.WriteArray(set.Statuses.ToArray());
                    writer.WriteArray(set.Signals.ToArray());
                    break;
                default:
                    throw new ArgumentException($"Unsupported value of unit property {property.Name}.", nameof(properties));
            }
        }

        writer.WriteArrayEnd(array);
    }

    private static string Text(Dictionary<string, VariantValue> values, string name) =>
        values.TryGetValue(name, out var value) && value.Type == VariantValueType.String ? value.GetString() : string.Empty;

    private static uint Number32(Dictionary<string, VariantValue> values, string name) =>
        values.TryGetValue(name, out var value) && value.Type == VariantValueType.UInt32 ? value.GetUInt32() : 0;

    private static int Int32(Dictionary<string, VariantValue> values, string name) =>
        values.TryGetValue(name, out var value) && value.Type == VariantValueType.Int32 ? value.GetInt32() : 0;

    private static ulong Number64(Dictionary<string, VariantValue> values, string name) =>
        values.TryGetValue(name, out var value) && value.Type == VariantValueType.UInt64 ? value.GetUInt64() : 0;

    private sealed class Unwatch(SystemdManager manager, string path) : IDisposable
    {
        public void Dispose() => manager._unitWatchers.TryRemove(path, out _);
    }
}
