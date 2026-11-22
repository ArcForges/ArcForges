// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using System.Runtime.Versioning;
using System.Text;
using System.Text.Json;
using ArcForges.Client;
using ArcForges.Node.Store.Migrations;

namespace ArcForges.Node.Core.Updates;

/// <summary>Temporarily inhibits only the managed user unit's old executable while an update is being prepared.</summary>
[SupportedOSPlatform("linux")]
internal static class NodeUpdateSystemdHandoff
{
    private const string Systemctl = "/usr/bin/systemctl";
    private const string Busctl = "/usr/bin/busctl";
    private const string Marker = ".native-update-systemd-block";
    private const string DropIn = "90-arcforges-native-update.conf";
    private const string UnitService = "org.freedesktop.systemd1";
    private const string UnitInterface = UnitService + ".Unit";
    private const string ServiceInterface = UnitService + ".Service";
    private const int MaximumManagerOutput = 16 * 1024;

    internal static async Task AcquireAsync(string appRoot, Guid operationId, bool testMode, CancellationToken ct)
    {
        var location = Locate(appRoot, testMode);
        using var app = new ContractionPaths.UpdateDirectory(appRoot);
        var existing = ReadOwned(app, Marker);
        if (existing is not null && !existing.AsSpan().SequenceEqual(OperationBytes(operationId)))
            throw Refused("marker_owner_changed");

        bool loaded = await RequireEffectiveUnitAsync(location, guardRequired: false, ct).ConfigureAwait(false);
        using var unitFolder = new ContractionPaths.UpdateDirectory(location.UnitFolder);
        using var dropIns = unitFolder.EnsurePrivateSubdirectory(location.Unit + ".d");
        var guard = Encoding.UTF8.GetBytes("[Unit]\nConditionPathExists=!" + location.MarkerPath + "\n");
        InstallExactFile(dropIns, DropIn, guard);
        if (!loaded)
            _ = await ManagerAsync(Systemctl, ["daemon-reload"], ct).ConfigureAwait(false);
        await RequireEffectiveUnitAsync(location, guardRequired: true, ct).ConfigureAwait(false);
        InstallExactFile(app, Marker, OperationBytes(operationId));
    }

    internal static async Task RequireArmedAsync(string appRoot, Guid operationId, bool testMode, CancellationToken ct)
    {
        var location = Locate(appRoot, testMode);
        using var app = new ContractionPaths.UpdateDirectory(appRoot);
        if (ReadOwned(app, Marker) is not { } marker || !marker.AsSpan().SequenceEqual(OperationBytes(operationId)))
            throw Refused("marker_owner_unconfirmed");
        await RequireEffectiveUnitAsync(location, guardRequired: true, ct).ConfigureAwait(false);
    }

    internal static async Task ReleaseAsync(string appRoot, Guid operationId, bool testMode, CancellationToken ct)
    {
        var location = Locate(appRoot, testMode);
        using var app = new ContractionPaths.UpdateDirectory(appRoot);
        var marker = ReadOwned(app, Marker);
        if (marker is null)
        {
            app.SynchronizeDirectory();
            return;
        }
        if (!marker.AsSpan().SequenceEqual(OperationBytes(operationId)))
            throw Refused("marker_owner_changed");

        await RequireEffectiveUnitAsync(location, guardRequired: true, ct).ConfigureAwait(false);
        if (ReadOwned(app, Marker) is not { } current || !current.AsSpan().SequenceEqual(OperationBytes(operationId)))
            throw Refused("marker_owner_changed");
        app.DeleteTemporary(Marker);
        app.SynchronizeDirectory();
    }

    private sealed record Location(string Unit, string UnitFolder, string MarkerPath, string BusPath, string[] Command)
    {
        internal string Fragment => Path.Combine(UnitFolder, Unit);
        internal string ExpectedDropIn => Path.Combine(UnitFolder, Unit + ".d", DropIn);
    }

    private static Location Locate(string appRoot, bool testMode)
    {
        if (!NodeAutoStart.UserManagerAvailable() || NodeLocations.ForcedAutostart(testMode) == "setsid")
            throw Refused("user_manager_required");

        string unit = NodeLocations.NodeUnit(testMode);
        if (unit.Length > 128 || !unit.StartsWith("arcforges-", StringComparison.Ordinal) || !unit.EndsWith(".service", StringComparison.Ordinal) ||
            unit.Any(character => !char.IsAsciiLetterOrDigit(character) && character is not ('.' or '-' or '_')) ||
            testMode && (unit == NodeLocations.DefaultNodeUnit || NodeLocations.EndpointOverride(testMode) is null))
            throw Refused("unit_identity_unconfirmed");

        if (!Path.IsPathFullyQualified(appRoot) || Path.TrimEndingDirectorySeparator(Path.GetFullPath(appRoot)) != appRoot ||
            appRoot.Any(character => char.IsControl(character) || character is '%' or '\\' or '"' or '\''))
            throw Refused("app_root_invalid");

        string runtime = Environment.GetEnvironmentVariable("XDG_RUNTIME_DIR") ?? "";
        string unitRoot = testMode ? runtime : Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".config");
        if (!Path.IsPathFullyQualified(unitRoot) || !Path.IsPathFullyQualified(runtime))
            throw Refused("unit_directory_unavailable");

        using var ownedRuntime = new ContractionPaths.UpdateDirectory(runtime);
        string exe = NodeUpdateLauncher.Executable(Path.Combine(appRoot, "current"));
        string[] command = testMode ? [exe, "node", "run", "--systemd", NodeLocations.TestModeOption] : [exe, "node", "run", "--systemd"];
        string bus = "/org/freedesktop/systemd1/unit/" + string.Concat(unit.Select(character =>
            char.IsAsciiLetterOrDigit(character) ? character.ToString() : FormattableString.Invariant($"_{(int)character:x2}")));
        return new(unit, Path.Combine(unitRoot, "systemd", "user"), Path.Combine(appRoot, Marker), bus, command);
    }

    private static async Task<bool> RequireEffectiveUnitAsync(Location location, bool guardRequired, CancellationToken ct)
    {
        var metadata = (await ManagerAsync(Systemctl, ["show", "--property=Id,FragmentPath,LoadState,NeedDaemonReload", "--", location.Unit], ct)
            .ConfigureAwait(false)).Split('\n', StringSplitOptions.RemoveEmptyEntries);
        if (!metadata.Contains("Id=" + location.Unit, StringComparer.Ordinal) ||
            !metadata.Contains("FragmentPath=" + location.Fragment, StringComparer.Ordinal) ||
            !metadata.Contains("LoadState=loaded", StringComparer.Ordinal) ||
            guardRequired && !metadata.Contains("NeedDaemonReload=no", StringComparer.Ordinal))
            throw Refused("unit_fragment_unconfirmed");

        using var unit = new ContractionPaths.UpdateDirectory(location.UnitFolder);
        using var fragment = unit.TryRead(location.Unit) ?? throw Refused("unit_fragment_missing");
        RequireFileMode(fragment);
        var dropIns = await PropertyAsync(location, UnitInterface, "DropInPaths", "as", ct).ConfigureAwait(false);
        bool guarded = dropIns.GetArrayLength() == 1 && dropIns[0].GetString() == location.ExpectedDropIn;
        if (guardRequired && !guarded || !guarded && dropIns.GetArrayLength() != 0)
            throw Refused("unit_dropins_unconfirmed");

        var conditions = await PropertyAsync(location, UnitInterface, "Conditions", "a(sbbsi)", ct).ConfigureAwait(false);
        if (guarded ? !HasExactCondition(conditions, location.MarkerPath) : conditions.GetArrayLength() != 0)
            throw Refused("unit_condition_unconfirmed");
        if (guarded)
        {
            using var folder = new ContractionPaths.UpdateDirectory(Path.GetDirectoryName(location.ExpectedDropIn)!);
            var expected = Encoding.UTF8.GetBytes("[Unit]\nConditionPathExists=!" + location.MarkerPath + "\n");
            if (ReadOwned(folder, DropIn) is not { } bytes || !bytes.AsSpan().SequenceEqual(expected))
                throw Refused("unit_dropin_bytes_changed");
        }

        const string commandType = "a(sasbttttuii)";
        var command = await PropertyAsync(location, ServiceInterface, "ExecStart", commandType, ct).ConfigureAwait(false);
        if (command.GetArrayLength() != 1 || command[0].GetArrayLength() != 10 || command[0][0].GetString() != location.Command[0] ||
            !command[0][1].EnumerateArray().Select(value => value.GetString()).SequenceEqual(location.Command) || command[0][2].GetBoolean())
            throw Refused("unit_exec_start_unconfirmed");

        foreach (string hook in new[] { "ExecCondition", "ExecStartPre", "ExecStartPost" })
        {
            if ((await PropertyAsync(location, ServiceInterface, hook, commandType, ct).ConfigureAwait(false)).GetArrayLength() != 0)
                throw Refused("unit_start_hook_unconfirmed");
        }
        return guarded;
    }

    private static bool HasExactCondition(JsonElement conditions, string marker) => conditions.GetArrayLength() == 1 &&
        conditions[0].GetArrayLength() == 5 && conditions[0][0].GetString() == "ConditionPathExists" &&
        !conditions[0][1].GetBoolean() && conditions[0][2].GetBoolean() && conditions[0][3].GetString() == marker;

    private static async Task<JsonElement> PropertyAsync(Location location, string contract, string property, string type, CancellationToken ct)
    {
        var output = await ManagerAsync(Busctl, ["--json=short", "get-property", UnitService, location.BusPath, contract, property], ct)
            .ConfigureAwait(false);
        using var document = JsonDocument.Parse(output);
        var value = document.RootElement;
        if (value.ValueKind != JsonValueKind.Object || !value.TryGetProperty("type", out var actual) || actual.GetString() != type ||
            !value.TryGetProperty("data", out var data) || data.ValueKind != JsonValueKind.Array)
            throw Refused("manager_property_unconfirmed");
        return data.Clone();
    }

    private static async Task<string> ManagerAsync(string program, string[] arguments, CancellationToken ct)
    {
        var start = new ProcessStartInfo(program)
        {
            UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true, RedirectStandardInput = true,
            WorkingDirectory = "/",
        };
        // Use the standard bus of the native user runtime, not an alternate session bus from the caller's shell.
        start.Environment.Remove("DBUS_SESSION_BUS_ADDRESS");
        start.ArgumentList.Add("--user");
        foreach (string argument in arguments)
            start.ArgumentList.Add(argument);
        using var process = Process.Start(start) ?? throw Refused("manager_command_unavailable");
        process.StandardInput.Close();
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeout.CancelAfter(TimeSpan.FromSeconds(10));
        try
        {
            var stdout = ReadBoundedAsync(process.StandardOutput, timeout.Token);
            var stderr = ReadBoundedAsync(process.StandardError, timeout.Token);
            await Task.WhenAll(stdout, stderr, process.WaitForExitAsync(timeout.Token)).ConfigureAwait(false);
            if (process.ExitCode != 0)
                throw Refused("manager_command_failed:" + process.ExitCode.ToString(System.Globalization.CultureInfo.InvariantCulture));
            return stdout.Result;
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            throw Refused("manager_command_deadline");
        }
        finally
        {
            if (!process.HasExited)
                process.Kill(entireProcessTree: false);
        }
    }

    private static async Task<string> ReadBoundedAsync(StreamReader stream, CancellationToken ct)
    {
        char[] buffer = new char[MaximumManagerOutput + 1];
        int length = await stream.ReadBlockAsync(buffer, ct).ConfigureAwait(false);
        if (length > MaximumManagerOutput)
            throw Refused("manager_command_output_limit");
        return new string(buffer, 0, length);
    }

    private static byte[]? ReadOwned(ContractionPaths.UpdateDirectory directory, string name)
    {
        using var read = directory.TryRead(name);
        if (read is null)
            return null;
        RequireFileMode(read);
        if (read.Length is <= 0 or > 8192)
            throw Refused("guard_file_size_invalid");
        byte[] bytes = new byte[checked((int)read.Length)];
        read.ReadExactly(bytes);
        return bytes;
    }

    private static void RequireFileMode(FileStream file)
    {
        if ((File.GetUnixFileMode(file.SafeFileHandle) & (UnixFileMode.GroupWrite | UnixFileMode.OtherWrite)) != 0)
            throw Refused("guard_file_owner_unconfirmed");
    }

    private static void InstallExactFile(ContractionPaths.UpdateDirectory directory, string name, byte[] contents)
    {
        if (ReadOwned(directory, name) is { } existing)
        {
            if (!existing.AsSpan().SequenceEqual(contents))
                throw Refused("guard_file_changed");
            directory.SynchronizeFile(name);
            directory.SynchronizeDirectory();
            return;
        }

        string temporary = ".update-" + Guid.NewGuid().ToString("N") + ".partial";
        try
        {
            using (var file = directory.Create(temporary))
            {
                file.Write(contents);
                file.Flush(flushToDisk: true);
            }
            directory.PublishNew(temporary, name);
        }
        finally
        {
            directory.DeleteTemporary(temporary);
        }
    }

    private static byte[] OperationBytes(Guid operationId)
    {
        if (operationId == Guid.Empty)
            throw Refused("operation_id_required");
        return Encoding.ASCII.GetBytes(operationId.ToString("D") + "\n");
    }

    private static IOException Refused(string reason) => new("native_update_systemd_handoff_" + reason);
}
