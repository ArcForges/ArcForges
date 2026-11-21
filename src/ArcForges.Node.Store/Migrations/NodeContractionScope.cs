// SPDX-License-Identifier: AGPL-3.0-only
using System.Buffers.Binary;
using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using Microsoft.Data.Sqlite;
using Microsoft.Win32;
using Microsoft.Win32.SafeHandles;

namespace ArcForges.Node.Store.Migrations;

/// <summary>Holds the original store read-only while a detached copy is contracted.</summary>
internal sealed partial class NodeContractionScope : IDisposable
{
    private readonly IDisposable _owner;
    private readonly FileStream _database;
    private readonly FileIdentity _identity;
    private readonly bool _prepareSchema15;
    private readonly byte[] _databaseDigest;
    private bool _disposed;

    private NodeContractionScope(string root, IDisposable owner, FileStream database, bool prepareSchema15)
    {
        DataRoot = root;
        _owner = owner;
        _database = database;
        _identity = Identity(database.SafeFileHandle);
        _prepareSchema15 = prepareSchema15;
        (ReceiptSha256, _databaseDigest) = Observe();
    }

    internal string DataRoot { get; }

    internal string ReceiptSha256 { get; }

    internal static string ReadCurrentBootIdentity() => OperatingSystem.IsWindows() ? WindowsBoot()
        : OperatingSystem.IsLinux() ? "linux:" + ReadLinuxBootId() : throw Refused("native_boot_unavailable");

    internal static NodeContractionScope Acquire(string dataRoot, bool prepareSchema15 = false)
    {
        if (!Path.IsPathFullyQualified(dataRoot) || !(OperatingSystem.IsWindows() || OperatingSystem.IsLinux()))
            throw Refused("local_absolute_data_root_required");

        string root = Path.TrimEndingDirectorySeparator(Path.GetFullPath(dataRoot));
        if (OperatingSystem.IsWindows() && new DriveInfo(Path.GetPathRoot(root)!).DriveType != DriveType.Fixed)
            throw Refused("local_fixed_windows_store_required");
        RequireDirectoryChain(Path.Combine(root, "store"));
        IDisposable owner = OperatingSystem.IsWindows() ? new WindowsOwnerLease() : new LinuxOwnerLease(root);
        FileStream? database = null;
        try
        {
            string path = StorePaths.Database(root);
            RequireRegular(path);
            database = File.OpenRead(path);
            return new NodeContractionScope(root, owner, database, prepareSchema15);
        }
        catch
        {
            database?.Dispose();
            owner.Dispose();
            throw;
        }
    }

    internal void VerifyHeld()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (!string.Equals(ReceiptSha256, Observe().ReceiptSha256, StringComparison.Ordinal))
            throw Refused("native_custody_changed");
    }

    public void Dispose()
    {
        if (_disposed)
            return;

        _disposed = true;
        _database.Dispose();
        _owner.Dispose();
    }

    private (string ReceiptSha256, byte[] DatabaseDigest) Observe()
    {
        string path = StorePaths.Database(DataRoot);
        RequireNamedDatabase(path);
        if (_owner is LinuxOwnerLease linux)
            linux.VerifyHeld();
        if (OperatingSystem.IsWindows() && _owner is WindowsOwnerLease windows)
            windows.VerifyHeld();

        string boot = ReadCurrentBootIdentity();
        string? uri = NodeStore.ImmutableStoreUri(path);
        if (uri is null)
            throw Refused("immutable_source_path_unavailable");

        SQLitePCL.Batteries_V2.Init();
        using var sqlite = new SqliteConnection(StorePaths.ConnectionString(uri, SqliteOpenMode.ReadOnly));
        sqlite.Open();
        byte[] nodeId = ReadOwner(sqlite, boot);
        if (_prepareSchema15)
            VerifiedNodeContractionArchive.VerifySchema15(sqlite);
        if (OperatingSystem.IsWindows())
            CheckWindowsSessions();
        else
        {
            RequireLinuxProcView();
            ObserveLinuxUnit("arcforges-guard.service");
        }

        var attempts = ObserveAttempts(sqlite, nodeId, boot);
        if (OperatingSystem.IsLinux())
            ObserveLinuxInventory(attempts);
        ObserveFileWorkers(sqlite, boot);
        RequireOwnedAttemptDirectories(attempts);
        RequireNamedDatabase(path);

        // Include the exact original bytes rather than just the rows observed by the native check.
        _database.Position = 0;
        byte[] dbDigest = SHA256.HashData(_database);
        string receipt = Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(FormattableString.Invariant(
            $"arcforges-node-native-drain-v1\n{DataRoot}\n{_identity}\n{boot}\n{Convert.ToHexStringLower(nodeId)}\n{Convert.ToHexStringLower(dbDigest)}"))));
        return (receipt, dbDigest);
    }

    private void RequireNamedDatabase(string path)
    {
        RequireDirectoryChain(Path.GetDirectoryName(path)!);
        RequireRegular(path);
        using var named = File.OpenRead(path);
        if (Identity(named.SafeFileHandle) != _identity)
            throw Refused("original_database_identity_changed");

        foreach (string suffix in new[] { "-wal", "-shm", "-journal" })
            if (TryAttributes(path + suffix) is not null)
                throw Refused("original_database_has_sidecars");
    }

    private byte[] ReadOwner(SqliteConnection sqlite, string boot)
    {
        using var command = sqlite.CreateCommand();
        command.CommandText = "SELECT node_id, schema_version, node_role, boot_identity, clean_shutdown_at, min_reader_version FROM store_meta WHERE singleton=1;";
        using var rows = command.ExecuteReader();
        if (!rows.Read() || rows.GetValue(0) is not byte[] { Length: 16 } id || rows.GetInt32(1) is < 15 or > 19 ||
            rows.GetInt32(2) != 1 || !TryCompareBoot(rows.GetString(3), boot, out _) || rows.IsDBNull(4))
            throw Refused("original_node_or_boot_unconfirmed");

        if (_prepareSchema15 && (rows.GetInt32(1) != 15 || rows.GetInt32(5) != 15))
            throw Refused("original_schema15_required");

        return id;
    }

    private static HashSet<string> ObserveAttempts(SqliteConnection sqlite, byte[] node, string boot)
    {
        var attempts = new HashSet<string>(StringComparer.Ordinal);
        string windowsPrefix = @"Local\ArcForges." + LegacyId(node) + ".";
        if (OperatingSystem.IsWindows())
            RequireWindowsJobAbsent(windowsPrefix + "root");

        using var command = sqlite.CreateCommand();
        command.CommandText = """
            SELECT attempt_id, executor_node_id, state, container_name, root_pid, root_start, boot_identity,
                   leftover_count, effect, termination_reason, finished_at
            FROM attempt ORDER BY attempt_id;
            """;
        using var rows = command.ExecuteReader();
        while (rows.Read())
        {
            string attempt = LegacyId((byte[])rows.GetValue(0));
            if (!attempts.Add(attempt) || !node.AsSpan().SequenceEqual((byte[])rows.GetValue(1)) || rows.GetInt32(2) != 9 ||
                rows.GetInt64(7) != 0 || rows.IsDBNull(8) || rows.GetInt32(8) is not (1 or 2) ||
                rows.IsDBNull(9) || rows.GetInt32(9) is 8 or 12 || rows.IsDBNull(10))
                throw Refused("legacy_attempt_custody_unresolved");

            string? owner = rows.IsDBNull(3) ? null : rows.GetString(3);
            if (OperatingSystem.IsWindows())
            {
                string job = windowsPrefix + attempt;
                if (owner is not null && !string.Equals(owner, job, StringComparison.Ordinal))
                    throw Refused("foreign_windows_job");
                RequireWindowsJobAbsent(job);
                RequireWindowsAckAbsent(job + ".ack");
            }
            else
            {
                string service = "arcforges-a-" + attempt + ".service";
                string scope = "arcforges-x-" + attempt + ".scope";
                if (owner is not null && owner != service && owner != scope)
                    throw Refused("foreign_linux_unit");
                ObserveLinuxUnit(service);
                ObserveLinuxUnit(scope);
            }

            if (rows.IsDBNull(4) != rows.IsDBNull(5))
                throw Refused("legacy_process_identity_incomplete");
            bool sameBoot = false;
            if (!rows.IsDBNull(6) && !TryCompareBoot(rows.GetString(6), boot, out sameBoot))
                throw Refused("legacy_process_boot_unconfirmed");
            if (!rows.IsDBNull(4))
            {
                if (rows.IsDBNull(6))
                    throw Refused("legacy_process_boot_unconfirmed");
                RequireProcessEnded(rows.GetInt32(4), rows.GetInt64(5), nativeTicks: false, sameBoot);
            }
        }

        return attempts;
    }

    private static void ObserveFileWorkers(SqliteConnection sqlite, string boot)
    {
        using var command = sqlite.CreateCommand();
        command.CommandText = """
            SELECT 2, boot_id, pid_namespace, process_id, start_ticks, ended FROM file_effect_worker
            UNION ALL
            SELECT identity_platform, boot_identity, pid_namespace, process_id, start_ticks, ended FROM file_stage_worker;
            """;
        using var rows = command.ExecuteReader();
        while (rows.Read())
        {
            bool windows = OperatingSystem.IsWindows();
            string recordedBoot = rows.GetString(1);
            if (!windows && Guid.TryParseExact(recordedBoot, "D", out _))
                recordedBoot = "linux:" + recordedBoot;

            if (rows.GetInt32(0) != (windows ? 1 : 2) || rows.GetInt32(5) != 1 ||
                !TryCompareBoot(recordedBoot, boot, out bool sameBoot) ||
                (!windows && (rows.IsDBNull(2) || rows.GetString(2) != PidNamespace("self"))))
                throw Refused("legacy_worker_identity_unresolved");

            RequireProcessEnded(rows.GetInt32(3), rows.GetInt64(4), nativeTicks: true, sameBoot);
        }
    }

    private static bool TryCompareBoot(string recorded, string current, out bool sameBoot)
    {
        if (!OperatingSystem.IsWindows())
        {
            sameBoot = string.Equals(recorded, current, StringComparison.OrdinalIgnoreCase);
            return sameBoot;
        }

        sameBoot = false;
        if (!TryParseWindowsBoot(recorded, out var recordedMachine, out long recordedTime) ||
            !TryParseWindowsBoot(current, out var currentMachine, out long currentTime) ||
            recordedMachine != currentMachine || recordedTime > currentTime)
            return false;

        sameBoot = recordedTime == currentTime;
        return true;
    }

    private static bool TryParseWindowsBoot(string value, out Guid machine, out long time)
    {
        machine = Guid.Empty;
        time = 0;
        if (!value.StartsWith("windows:", StringComparison.Ordinal))
            return false;

        var identity = value.AsSpan(8);
        int separator = identity.IndexOf(':');
        if (separator != 36 || !Guid.TryParseExact(identity[..separator], "D", out machine) || machine == Guid.Empty)
            return false;

        var timestamp = identity[(separator + 1)..];
        return !timestamp.IsEmpty && timestamp.IndexOfAnyExceptInRange('0', '9') < 0 &&
            long.TryParse(timestamp, NumberStyles.None, CultureInfo.InvariantCulture, out time) &&
            time > 0 && time <= DateTimeOffset.MaxValue.ToFileTime() / TimeSpan.TicksPerSecond;
    }

    private static void RequireProcessEnded(int pid, long start, bool nativeTicks, bool sameBoot)
    {
        if (pid <= 1 || start <= 0)
            throw Refused("legacy_process_identity_invalid");
        // On Windows this identity has already been bound to an earlier boot of this exact machine.
        if (!sameBoot)
            return;

        if (OperatingSystem.IsWindows())
        {
            using var process = OpenProcess(0x1000, false, pid); // PROCESS_QUERY_LIMITED_INFORMATION
            if (process.IsInvalid)
            {
                if (Marshal.GetLastPInvokeError() == 87) // ERROR_INVALID_PARAMETER: no such PID
                    return;
                throw Refused("legacy_process_identity_unobservable");
            }

            if (!GetProcessTimes(process, out long creation, out long exit, out _, out _))
                throw Refused("legacy_process_identity_unobservable");
            long observed = nativeTicks ? creation : StoreTime.ToMicroseconds(DateTimeOffset.FromFileTime(creation));
            if (observed == start && exit == 0)
                throw Refused("legacy_process_still_live");
            return;
        }

        if (LinuxProcessAbsent(pid))
            return;

        string stat;
        try
        {
            stat = File.ReadAllText($"/proc/{pid.ToString(CultureInfo.InvariantCulture)}/stat");
        }
        catch (IOException) when (LinuxProcessAbsent(pid))
        {
            return;
        }
        int open = stat.IndexOf('(');
        int close = stat.LastIndexOf(')');
        if (open < 1 || close <= open || !int.TryParse(stat.AsSpan(0, open).Trim(), NumberStyles.None, CultureInfo.InvariantCulture, out int observedPid) || observedPid != pid)
            throw Refused("legacy_process_identity_unobservable");
        string[] fields = stat[(close + 1)..].Split(' ', StringSplitOptions.RemoveEmptyEntries);
        if (fields.Length < 20 || fields[0].Length != 1 || !long.TryParse(fields[19], NumberStyles.None, CultureInfo.InvariantCulture, out long ticks) || ticks <= 0)
            throw Refused("legacy_process_identity_unobservable");
        long observedLinux = nativeTicks ? ticks : LinuxStartMicroseconds(ticks);
        if (fields[0] is not ("Z" or "X"))
        {
            if (observedLinux == start)
                throw Refused("legacy_process_still_live");
            // The old attempt root used wall-clock conversion, unlike the worker's exact kernel tick.
            if (!nativeTicks)
                throw Refused("legacy_process_identity_unconfirmed");
        }
    }

    private static bool LinuxProcessAbsent(int pid)
    {
        if (SignalZero(pid, 0) == 0)
            return false;
        if (Marshal.GetLastPInvokeError() == 3) // ESRCH in this PID namespace
            return true;
        throw Refused("legacy_process_identity_unobservable");
    }

    private static long LinuxStartMicroseconds(long startTicks)
    {
        long tickRate = Sysconf(2); // _SC_CLK_TCK
        string? boot = File.ReadLines("/proc/stat").SingleOrDefault(line => line.StartsWith("btime ", StringComparison.Ordinal));
        if (tickRate <= 0 || boot is null || !long.TryParse(boot.AsSpan(6), NumberStyles.None, CultureInfo.InvariantCulture, out long seconds))
            throw Refused("linux_boot_time_unavailable");
        // The predecessor's ProcFs.StartInstant rounded to milliseconds.
        return checked((seconds * 1_000 + startTicks * 1_000 / tickRate) * 1_000);
    }

    private static string ReadLinuxBootId() =>
        Guid.TryParseExact(File.ReadAllText("/proc/sys/kernel/random/boot_id").Trim(), "D", out var boot) && boot != Guid.Empty
            ? boot.ToString("D") : throw Refused("linux_boot_unavailable");

    private static string PidNamespace(string pid) => new FileInfo($"/proc/{pid}/ns/pid").LinkTarget ?? "";

    private static void RequireLinuxProcView()
    {
        string stat = File.ReadAllText("/proc/self/stat");
        int open = stat.IndexOf('(');
        string pidNamespace = PidNamespace("self");
        if (open < 1 || !int.TryParse(stat.AsSpan(0, open).Trim(), NumberStyles.None, CultureInfo.InvariantCulture, out int pid) ||
            pid != Environment.ProcessId || !pidNamespace.StartsWith("pid:[", StringComparison.Ordinal) || !pidNamespace.EndsWith(']'))
            throw Refused("linux_pid_namespace_unavailable");
    }

    private static void ObserveLinuxInventory(HashSet<string> attempts)
    {
        // These are the complete predecessor names, including the old test slice and capability probes.
        // Do not ask the manager for an unfiltered unit list or include the current V2 Run families.
        var (output, exit) = QueryLinuxManager([
            "list-units", "--all", "--plain", "--no-legend", "--full", "--type=service,scope,slice", "--",
            "arcforges-a-*.service", "arcforges-x-*.scope", "arcforges-probe-*.service", "arcforges.slice", "arcforges-test-*.slice",
        ]);
        if (exit != 0)
            throw Refused("systemd_inventory_unconfirmed");

        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (string line in output.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            int separator = line.IndexOfAny([' ', '\t']);
            if (separator <= 0 || !seen.Add(line[..separator]) || seen.Count > 4096)
                throw Refused("systemd_inventory_unconfirmed");
            string unit = line[..separator];
            if (unit == "arcforges.slice" || unit.StartsWith("arcforges-test-", StringComparison.Ordinal) && unit.EndsWith(".slice", StringComparison.Ordinal))
            {
                ObserveLinuxUnit(unit, slice: true);
                continue;
            }

            string? attempt = UnitMiddle(unit, "arcforges-a-", ".service") ?? UnitMiddle(unit, "arcforges-x-", ".scope");
            if (attempt is not null)
            {
                if (!attempts.Contains(attempt) && !line.AsSpan(separator).TrimStart().StartsWith("not-found ", StringComparison.Ordinal))
                    throw Refused("legacy_unit_without_attempt_record");
                ObserveLinuxUnit(unit);
            }
            else if (UnitMiddle(unit, "arcforges-probe-", ".service") is not null)
            {
                ObserveLinuxUnit(unit);
            }
            else
            {
                throw Refused("systemd_inventory_unconfirmed");
            }
        }

        // A still-populated old slice can outlive registration in its user manager.
        // Look only beneath that manager's own cgroup, where the retired default slice was rooted.
        var (managerGroup, managerExit) = QueryLinuxManager(["show", "--property=ControlGroup", "--value"]);
        managerGroup = managerGroup.TrimEnd('\n', '\r');
        if (managerExit != 0 || !ValidLinuxCgroupPath(managerGroup))
            throw Refused("systemd_manager_cgroup_unconfirmed");
        _ = ObserveEmptyLinuxCgroup(Path.Combine("/sys/fs/cgroup", managerGroup[1..], "arcforges.slice"));
    }

    private static string? UnitMiddle(string unit, string prefix, string suffix) =>
        unit.Length >= prefix.Length + suffix.Length && unit.StartsWith(prefix, StringComparison.Ordinal) && unit.EndsWith(suffix, StringComparison.Ordinal)
            ? unit[prefix.Length..^suffix.Length] : null;

    private static void ObserveLinuxUnit(string unit, bool slice = false)
    {
        var (output, exit) = QueryLinuxManager([
            "show", "--property=Id,LoadState,ActiveState,MainPID,ControlGroup", "--", unit,
        ]);
        var fields = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (string line in output.Split('\n', StringSplitOptions.RemoveEmptyEntries))
        {
            int split = line.IndexOf('=');
            if (split <= 0 || !fields.TryAdd(line[..split], line[(split + 1)..]))
                throw Refused("systemd_observation_unconfirmed");
        }

        string? active = fields.GetValueOrDefault("ActiveState");
        string? cgroup = fields.GetValueOrDefault("ControlGroup");
        if (fields.GetValueOrDefault("Id") != unit || fields.GetValueOrDefault("MainPID") is not (null or "0") ||
            !(active is "inactive" or "failed" || slice && active == "active" && !string.IsNullOrEmpty(cgroup)))
            throw Refused("legacy_unit_live_or_unconfirmed");
        if (fields.GetValueOrDefault("LoadState") == "not-found" && string.IsNullOrEmpty(cgroup))
            return;
        if (exit != 0 || fields.GetValueOrDefault("LoadState") != "loaded")
            throw Refused("systemd_observation_unconfirmed");
        if (string.IsNullOrEmpty(cgroup))
            return;
        if (!ValidLinuxCgroupPath(cgroup) || Path.GetFileName(cgroup) != unit)
            throw Refused("legacy_cgroup_identity_unconfirmed");

        string scope = Path.Combine("/sys/fs/cgroup", cgroup[1..]);
        if (!ObserveEmptyLinuxCgroup(scope) && slice && active == "active")
            throw Refused("legacy_cgroup_identity_unconfirmed");
    }

    private static bool ValidLinuxCgroupPath(string path) => path.StartsWith('/') && path.Length > 1 &&
        path[1..].Split('/').All(part => part.Length != 0 && part is not ("." or "..") && !part.Any(char.IsControl));

    private static bool ObserveEmptyLinuxCgroup(string path)
    {
        if (TryAttributes(path) is not { } attributes)
            return false;
        if ((attributes & (FileAttributes.Directory | FileAttributes.ReparsePoint)) != FileAttributes.Directory)
            throw Refused("legacy_cgroup_identity_unconfirmed");
        if (!File.ReadLines(Path.Combine(path, "cgroup.events")).Contains("populated 0", StringComparer.Ordinal))
            throw Refused("legacy_cgroup_still_populated");
        return true;
    }

    private static (string Output, int Exit) QueryLinuxManager(string[] arguments)
    {
        var start = new ProcessStartInfo("/usr/bin/systemctl") { UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true };
        foreach (string argument in new[] { "--user", "--no-pager" }.Concat(arguments))
            start.ArgumentList.Add(argument);
        string runtime = "/run/user/" + GetEffectiveUid().ToString(CultureInfo.InvariantCulture);
        start.Environment["XDG_RUNTIME_DIR"] = runtime;
        start.Environment["DBUS_SESSION_BUS_ADDRESS"] = "unix:path=" + runtime + "/bus";
        start.Environment["LC_ALL"] = "C";
        start.Environment["SYSTEMD_COLORS"] = "0";
        using var child = Process.Start(start) ?? throw Refused("systemd_observation_unavailable");
        var output = ReadBoundedAsync(child.StandardOutput);
        var error = ReadBoundedAsync(child.StandardError);
        if (!child.WaitForExit(5_000))
        {
            if (!child.HasExited)
            {
                child.Kill(); // The short-lived systemctl observation child belongs to this call.
                _ = child.WaitForExit(5_000);
            }
            throw Refused("systemd_observation_timed_out");
        }
        _ = error.GetAwaiter().GetResult();
        return (output.GetAwaiter().GetResult(), child.ExitCode);
    }

    private static async Task<string> ReadBoundedAsync(StreamReader reader)
    {
        const int maximum = 512 * 1024;
        var result = new StringBuilder();
        var buffer = new char[4096];
        int read;
        while ((read = await reader.ReadAsync(buffer.AsMemory()).ConfigureAwait(false)) > 0)
        {
            if (result.Length + read > maximum)
                throw Refused("systemd_observation_limit");
            result.Append(buffer, 0, read);
        }
        return result.ToString();
    }

    private void RequireOwnedAttemptDirectories(HashSet<string> ids)
    {
        string logs = Path.Combine(DataRoot, "logs");
        if (TryAttributes(logs) is null)
            return;
        RequireDirectoryChain(logs);
        foreach (string entry in Directory.EnumerateDirectories(logs))
        {
            string name = Path.GetFileName(entry);
            if (name.Length == 26 && name[0] is >= '0' and <= '7' && name.All("0123456789abcdefghjkmnpqrstvwxyz".Contains) && !ids.Contains(name))
                throw Refused("legacy_attempt_directory_without_record");
        }
    }

    private static string LegacyId(byte[] id)
    {
        if (id.Length != 16)
            throw Refused("legacy_id_invalid");
        var value = new UInt128(BinaryPrimitives.ReadUInt64BigEndian(id), BinaryPrimitives.ReadUInt64BigEndian(id.AsSpan(8)));
        Span<char> text = stackalloc char[26];
        for (int index = text.Length - 1; index >= 0; index--, value >>= 5)
            text[index] = "0123456789abcdefghjkmnpqrstvwxyz"[(int)(value & 31)];
        return new string(text);
    }

    private static FileAttributes? TryAttributes(string path)
    {
        try { return File.GetAttributes(path); }
        catch (Exception failure) when (failure is FileNotFoundException or DirectoryNotFoundException) { return null; }
    }

    private static void RequireDirectoryChain(string path)
    {
        for (DirectoryInfo? entry = new(path); entry is not null; entry = entry.Parent)
            if ((File.GetAttributes(entry.FullName) & (FileAttributes.Directory | FileAttributes.ReparsePoint)) != FileAttributes.Directory)
                throw Refused("source_directory_alias_or_type");
    }

    private static void RequireRegular(string path)
    {
        if ((File.GetAttributes(path) & (FileAttributes.Directory | FileAttributes.ReparsePoint | FileAttributes.Device)) != 0)
            throw Refused("source_file_alias_or_type");
    }

    private static StoreIncompatibleException Refused(string reason) => new("node_contraction_native_scope_refused: " + reason);

    private sealed class LinuxOwnerLease : IDisposable
    {
        private readonly string _path;
        private readonly SafeFileHandle _file;
        private readonly FileIdentity _identity;

        internal LinuxOwnerLease(string root)
        {
            _path = Path.Combine(root, "node.lock");
            RequireRegular(_path);
            _file = File.OpenHandle(_path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            try
            {
                _identity = Identity(_file);
                if (Flock(_file.DangerousGetHandle().ToInt32(), 2 | 4) != 0) // LOCK_EX | LOCK_NB, matching the predecessor
                    throw Refused("original_node_lock_held");
                VerifyHeld();
            }
            catch
            {
                _file.Dispose();
                throw;
            }
        }

        internal void VerifyHeld()
        {
            RequireRegular(_path);
            if (Statx(-100, _path, 0x100, 0x10b, out var status) != 0 || LinuxIdentity(status) != _identity)
                throw Refused("original_node_lock_identity_changed");
        }

        public void Dispose() => _file.Dispose();
    }

    [SupportedOSPlatform("windows")]
    private sealed class WindowsOwnerLease : IDisposable
    {
        private readonly ManualResetEventSlim _entered = new();
        private readonly ManualResetEventSlim _release = new();
        private readonly Thread _owner;
        private Exception? _failure;

        internal WindowsOwnerLease()
        {
            using var identity = WindowsIdentity.GetCurrent();
            string sid = identity.User?.Value ?? throw Refused("windows_owner_unavailable");
            string instanceKey = Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(sid)).AsSpan(0, 16));
            _owner = new Thread(() => Hold(@"Local\ArcForges.Node." + instanceKey)) { IsBackground = true };
            _owner.Start();
            _entered.Wait();
            if (_failure is not null)
            {
                Dispose();
                throw Refused("original_node_mutex_unavailable");
            }
        }

        private void Hold(string name)
        {
            try
            {
                using var mutex = new Mutex(false, name);
                bool held;
                try { held = mutex.WaitOne(0); }
                catch (AbandonedMutexException) { held = true; }
                if (!held)
                    throw Refused("original_node_mutex_held");
                _entered.Set();
                _release.Wait();
                mutex.ReleaseMutex();
            }
            catch (Exception failure) when (failure is not OutOfMemoryException)
            {
                _failure = failure;
                _entered.Set();
            }
        }

        public void Dispose()
        {
            _release.Set();
            _owner.Join();
            _release.Dispose();
            _entered.Dispose();
        }

        internal void VerifyHeld()
        {
            if (!_owner.IsAlive || Volatile.Read(ref _failure) is not null)
                throw Refused("original_node_mutex_no_longer_held");
        }
    }

    [SupportedOSPlatform("windows")]
    private static string WindowsBoot()
    {
        string? machine = Registry.GetValue(@"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography", "MachineGuid", null) as string;
        if (!Guid.TryParseExact(machine, "D", out _) || NtQuerySystemInformation(3, out var info, 48, out _) != 0 || info.Time <= info.Bias)
            throw Refused("windows_boot_unavailable");
        return FormattableString.Invariant($"windows:{machine}:{(info.Time - info.Bias) / 10_000_000}");
    }

    [SupportedOSPlatform("windows")]
    private static void CheckWindowsSessions()
    {
        using var user = WindowsIdentity.GetCurrent();
        string userName = user.Name.Split('\\')[^1];
        using var process = Process.GetCurrentProcess();
        int current = process.SessionId;
        if (current == 0 || !WTSEnumerateSessions(IntPtr.Zero, 0, 1, out var list, out int count))
            throw Refused("windows_owner_session_unavailable");
        bool foundCurrent = false;
        try
        {
            if (count is < 1 or > 1024)
                throw Refused("windows_owner_session_unavailable");
            int size = Marshal.SizeOf<WindowsSession>();
            for (int index = 0; index < count; index++)
            {
                var session = Marshal.PtrToStructure<WindowsSession>(list + index * size);
                if (session.Id == 0 || session.State is 6 or 7 or 8 or 9)
                    continue;
                if (!WTSQuerySessionInformation(IntPtr.Zero, session.Id, 5, out var value, out int length))
                    throw Refused("windows_owner_session_unavailable");
                try
                {
                    string? observed = length >= 2 ? Marshal.PtrToStringUni(value) : null;
                    if (string.Equals(observed, userName, StringComparison.OrdinalIgnoreCase))
                    {
                        if (session.Id != current)
                            throw Refused("windows_owner_in_multiple_sessions");
                        foundCurrent = true;
                    }
                }
                finally { WTSFreeMemory(value); }
            }
        }
        finally { WTSFreeMemory(list); }

        if (!foundCurrent)
            throw Refused("windows_owner_session_unavailable");
    }

    [SupportedOSPlatform("windows")]
    private static void RequireWindowsJobAbsent(string name)
    {
        using var handle = OpenJobObject(4, false, name); // JOB_OBJECT_QUERY
        if (!handle.IsInvalid || Marshal.GetLastPInvokeError() != 2)
            throw Refused("legacy_windows_job_live_or_unconfirmed");
    }

    [SupportedOSPlatform("windows")]
    private static void RequireWindowsAckAbsent(string name)
    {
        using var handle = OpenEvent(0x100000, false, name); // SYNCHRONIZE
        if (!handle.IsInvalid || Marshal.GetLastPInvokeError() != 2)
            throw Refused("legacy_windows_holder_live_or_unconfirmed");
    }

    private static FileIdentity Identity(SafeFileHandle file)
    {
        if (OperatingSystem.IsWindows())
        {
            if (!GetFileInformationByHandleEx(file, 18, out var info, 24)) // FileIdInfo
                throw new Win32Exception(Marshal.GetLastPInvokeError());
            return new(info.Volume, info.High, info.Low);
        }

        if (Statx(file.DangerousGetHandle().ToInt32(), "", 0x1000 | 0x100, 0x10b, out var status) != 0)
            throw Refused("linux_file_identity_unavailable");
        return LinuxIdentity(status);
    }

    private static FileIdentity LinuxIdentity(LinuxFileStatus info)
    {
        if ((info.Mask & 0x10b) != 0x10b || (info.Mode & 0xf000) != 0x8000 || info.Owner != GetEffectiveUid())
            throw Refused("linux_file_identity_unavailable");
        return new(info.DeviceMajor, info.DeviceMinor, info.Inode);
    }

    private readonly record struct FileIdentity(ulong A, ulong B, ulong C);

    [StructLayout(LayoutKind.Explicit, Size = 256)]
    private struct LinuxFileStatus
    {
        [FieldOffset(0)] internal uint Mask;
        [FieldOffset(20)] internal uint Owner;
        [FieldOffset(28)] internal ushort Mode;
        [FieldOffset(32)] internal ulong Inode;
        [FieldOffset(136)] internal uint DeviceMajor;
        [FieldOffset(140)] internal uint DeviceMinor;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WindowsFileId
    {
        internal ulong Volume;
        internal ulong Low;
        internal ulong High;
    }

    [StructLayout(LayoutKind.Explicit, Size = 48)]
    private struct WindowsBootInfo
    {
        [FieldOffset(0)] internal long Time;
        [FieldOffset(32)] internal long Bias;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WindowsSession
    {
        internal int Id;
        internal IntPtr Station;
        internal int State;
    }

    [LibraryImport("libc", EntryPoint = "flock", SetLastError = true)]
    private static partial int Flock(int descriptor, int operation);

    [LibraryImport("libc", EntryPoint = "statx", StringMarshalling = StringMarshalling.Utf8, SetLastError = true)]
    private static partial int Statx(int descriptor, string path, int flags, uint mask, out LinuxFileStatus status);

    [LibraryImport("libc", EntryPoint = "geteuid")]
    private static partial uint GetEffectiveUid();

    [LibraryImport("libc", EntryPoint = "sysconf")]
    private static partial nint Sysconf(int name);

    [LibraryImport("libc", EntryPoint = "kill", SetLastError = true)]
    private static partial int SignalZero(int pid, int signal);

    [LibraryImport("kernel32.dll", EntryPoint = "OpenJobObjectW", StringMarshalling = StringMarshalling.Utf16, SetLastError = true)]
    private static partial SafeFileHandle OpenJobObject(uint access, [MarshalAs(UnmanagedType.Bool)] bool inherit, string name);

    [LibraryImport("kernel32.dll", EntryPoint = "OpenEventW", StringMarshalling = StringMarshalling.Utf16, SetLastError = true)]
    private static partial SafeWaitHandle OpenEvent(uint access, [MarshalAs(UnmanagedType.Bool)] bool inherit, string name);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    private static partial SafeProcessHandle OpenProcess(uint access, [MarshalAs(UnmanagedType.Bool)] bool inherit, int pid);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool GetProcessTimes(SafeProcessHandle process, out long creation, out long exit, out long kernel, out long user);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool GetFileInformationByHandleEx(SafeFileHandle handle, int infoClass, out WindowsFileId info, uint size);

    [LibraryImport("ntdll.dll")]
    private static partial int NtQuerySystemInformation(int infoClass, out WindowsBootInfo info, uint size, out uint returned);

    [LibraryImport("wtsapi32.dll", EntryPoint = "WTSEnumerateSessionsW", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool WTSEnumerateSessions(IntPtr server, int reserved, int version, out IntPtr sessions, out int count);

    [LibraryImport("wtsapi32.dll", EntryPoint = "WTSQuerySessionInformationW", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool WTSQuerySessionInformation(IntPtr server, int session, int field, out IntPtr value, out int length);

    [LibraryImport("wtsapi32.dll")]
    private static partial void WTSFreeMemory(IntPtr value);
}
