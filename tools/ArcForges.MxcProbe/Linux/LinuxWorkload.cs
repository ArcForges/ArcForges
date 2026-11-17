// SPDX-License-Identifier: AGPL-3.0-only
using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace ArcForges.MxcProbe.Linux;

// Untrusted, bounded experiment payload. Neither stdout nor its writable
// observation files establishes SDK ownership, cgroup membership or cleanup.
internal static partial class LinuxWorkload
{
    private const int CloseOnExec = 0x80000;
    private const int ObservationLimit = 64 * 1024;
    private static readonly object OutputGate = new();
    private static readonly byte[] FileSentinel = "AFV2_FILE_SENTINEL\n"u8.ToArray();
    private static readonly byte[] PersistenceSentinel = "AFV2_PERSISTENCE_SENTINEL\n"u8.ToArray();
    private static readonly byte[] NetworkSentinel = "AFV2_NET_SENTINEL\n"u8.ToArray();
    private static string? observationPath;
    private static bool observationInitialized;
    private static int observationBytes;

    internal static async Task<int> RunAsync(string[] args)
    {
        if (!OperatingSystem.IsLinux() || RuntimeInformation.ProcessArchitecture != Architecture.X64)
        {
            Emit("unsupported", "admission", writer => writer.WriteString("reason", "linux-x64-required"));
            return 77;
        }

        try
        {
            if (args.Length == 0) throw new ArgumentException("A fixed fixture mode is required.");
            if (args[0] is not ("terminal-info" or "terminal" or "argv" or "environment" or "known-folders" or "exit" or "fake-errors" or "flood" or "load" or "load-child" or "commit" or "short-burst" or "root-exit-child" or "filesystem" or "persistence" or "network" or "combined"))
                throw new ArgumentException("Unknown fixture mode.");
            Emit("entry", "entry", writer => writer.WriteString("mode", args[0]));
            return args[0] switch
            {
                "terminal-info" when args.Length == 1 => TerminalInformation(),
                "terminal" when args.Length == 3 => await TerminalAsync(args[1], Number(args[2], 100, 60_000)).ConfigureAwait(false),
                "argv" when args.Length <= 33 => Arguments(args),
                "environment" when args.Length is >= 2 and <= 17 => EnvironmentVariables(args),
                "known-folders" when args.Length == 1 => KnownFolders(),
                "exit" when args.Length == 2 => Exit(Number(args[1], 0, 255)),
                "fake-errors" when args.Length == 2 => FakeErrors(Number(args[1], 0, 255)),
                "flood" when args.Length == 2 => await FloodAsync(Number(args[1], 1, 8 * 1024 * 1024)).ConfigureAwait(false),
                "load" when args.Length == 4 => Load(Number(args[1], 100, 60_000), Number(args[2], 0, 256), Number(args[3], 0, 8)),
                "load-child" when args.Length == 3 => Load(Number(args[1], 100, 60_000), Number(args[2], 0, 16), 0),
                "commit" when args.Length == 3 => await CommitAsync(Number(args[1], 1, 256), Number(args[2], 100, 60_000)).ConfigureAwait(false),
                "short-burst" when args.Length == 2 => await ShortBurstAsync(Number(args[1], 1, 8)).ConfigureAwait(false),
                "root-exit-child" when args.Length is 2 or 3 => await RootExitChildAsync(Number(args[1], 1000, 60_000), args.Length == 3 ? Number(args[2], 0, 60_000) : 0).ConfigureAwait(false),
                "filesystem" when args.Length == 6 => Filesystem(args),
                "persistence" when args.Length == 3 => Persistence(args[1], args[2]),
                "network" when args.Length is 5 or 6 => await NetworkAsync(args[1], args[2], Number(args[3], 1, 65535), Number(args[4], 100, 4000), gated: args.Length == 6 && (args[5] == "gated" ? true : throw new ArgumentException("Unknown fixture gate."))).ConfigureAwait(false),
                "combined" when args.Length == 11 => await CombinedAsync(args, Number(args[1], 3000, 60_000), Number(args[2], 0, 256), Number(args[3], 0, 8), Number(args[5], 1, 65535)).ConfigureAwait(false),
                _ => throw new ArgumentException("Unknown fixture mode or argument count.")
            };
        }
        catch (OperationCanceledException)
        {
            Emit("deadline", "deadline", writer => writer.WriteString("reason", "fixture-deadline"));
            return 124;
        }
        catch (ArgumentException)
        {
            Emit("invalid-arguments", "admission", _ => { });
            return 64;
        }
        catch (OutOfMemoryException)
        {
            Emit("allocation-failed", "allocation", _ => { });
            return 72;
        }
        catch (Exception exception)
        {
            Emit("error", "execute", writer => WriteException(writer, exception));
            return 70;
        }
    }

    private static int Number(string value, int minimum, int maximum)
        => int.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out var number) && number >= minimum && number <= maximum
            ? number : throw new ArgumentException("A fixture bound is invalid.");

    private static void Emit(string name, string phase, Action<Utf8JsonWriter> fields)
    {
        using var buffer = new MemoryStream();
        using (var writer = new Utf8JsonWriter(buffer))
        {
            writer.WriteStartObject();
            writer.WriteString("fixture", "linux-workload-v1");
            writer.WriteNumber("pid", Environment.ProcessId);
            writer.WriteString("event", name);
            writer.WriteString("phase", phase);
            fields(writer);
            writer.WriteEndObject();
        }

        lock (OutputGate)
        {
            var bytes = buffer.GetBuffer().AsSpan(0, checked((int)buffer.Length));
            AppendObservation(bytes);
            Console.WriteLine(Encoding.UTF8.GetString(bytes));
        }
    }

    private static void AppendObservation(ReadOnlySpan<byte> value)
    {
        if (!OperatingSystem.IsLinux()) return;
        try
        {
            if (!observationInitialized)
            {
                observationInitialized = true;
                var directory = Environment.GetEnvironmentVariable("AFV2_MXC_OBSERVATIONS_DIR");
                if (directory is null) return;
                RequirePath(directory);
                if (!Directory.Exists(directory)) throw new IOException("The explicitly owned observation directory is unavailable.");
                var path = Path.Combine(directory, Environment.ProcessId.ToString(CultureInfo.InvariantCulture) + ".jsonl");
                var created = OpenNative(path, 1 | 64 | 128 | CloseOnExec, 0x180);
                if (created < 0) throw NativeFailure("observation.create", created);
                if (CloseNative(created) != 0) throw NativeFailure("observation.close", -1);
                observationPath = path;
            }

            // Each case has at most this root plus eight non-recursive children:
            // nine capped files remain below one MiB, including short bursts.
            if (observationPath is null || value.Length + 1 > ObservationLimit - observationBytes) return;
            var fd = OpenNative(observationPath, 1 | 1024 | CloseOnExec, 0);
            if (fd < 0) throw NativeFailure("observation.append", fd);
            try
            {
                WriteAll(fd, value, "observation.write");
                WriteAll(fd, "\n"u8, "observation.write");
                observationBytes += value.Length + 1;
            }
            finally
            {
                if (CloseNative(fd) != 0)
                {
                    var errno = Marshal.GetLastPInvokeError();
                    observationPath = null;
                    Console.Error.WriteLine($"{{\"fixture\":\"linux-workload-v1\",\"event\":\"observation-cleanup-failed\",\"phase\":\"observation.cleanup\",\"errno\":{errno.ToString(CultureInfo.InvariantCulture)}}}");
                }
            }
        }
        catch (Exception exception) when (exception is NativeOperationException or IOException or UnauthorizedAccessException or ArgumentException)
        {
            observationPath = null;
            var errno = exception is NativeOperationException native ? native.Errno : 0;
            Console.Error.WriteLine($"{{\"fixture\":\"linux-workload-v1\",\"pid\":{Environment.ProcessId.ToString(CultureInfo.InvariantCulture)},\"event\":\"observation-log-failed\",\"phase\":\"observation\",\"errno\":{errno.ToString(CultureInfo.InvariantCulture)},\"hresult\":{exception.HResult.ToString(CultureInfo.InvariantCulture)}}}");
        }
    }

    private static void WriteException(Utf8JsonWriter writer, Exception exception)
    {
        writer.WriteString("errorType", exception.GetType().Name);
        writer.WriteNumber("hresult", exception.HResult);
        if (exception is NativeOperationException native)
        {
            writer.WriteString("operation", native.Operation);
            writer.WriteNumber("errno", native.Errno);
            writer.WriteNumber("nativeResult", native.Result);
        }
        else if (exception is Win32Exception win32) writer.WriteNumber("errno", win32.NativeErrorCode);
        else writer.WriteNull("errno");
        if (exception is SocketException socket)
        {
            writer.WriteNumber("socketErrorCode", (int)socket.SocketErrorCode);
            writer.WriteNumber("nativeErrorCode", socket.NativeErrorCode);
        }
    }

    private static void Digest(Utf8JsonWriter writer, string value)
    {
        var bytes = Encoding.UTF8.GetBytes(value);
        writer.WriteNumber("length", value.Length);
        writer.WriteNumber("utf8Bytes", bytes.Length);
        writer.WriteString("sha256", Convert.ToHexStringLower(SHA256.HashData(bytes)));
    }

    private static int Arguments(string[] args)
    {
        if (args.Skip(1).Any(value => value.Length > 4096)) throw new ArgumentException("A synthetic argument is too long.");
        Emit("argv-count", "argv", writer => writer.WriteNumber("count", args.Length - 1));
        for (var index = 1; index < args.Length; index++)
        {
            var item = index;
            Emit("argv", "argv", writer => { writer.WriteNumber("index", item - 1); Digest(writer, args[item]); });
        }
        return 0;
    }

    private static int EnvironmentVariables(string[] args)
    {
        if (args.Skip(1).Any(name => !name.StartsWith("AFV2_MXC_", StringComparison.Ordinal) || name.Length > 80 || name.Any(character => !char.IsAsciiLetterOrDigit(character) && character != '_')))
            throw new ArgumentException("Only explicit synthetic environment names are accepted.");
        foreach (var name in args.Skip(1))
        {
            var value = Environment.GetEnvironmentVariable(name);
            if (value is { Length: > 32_768 }) throw new ArgumentException("A synthetic value is too long.");
            Emit("environment", "environment", writer => { writer.WriteString("name", name); writer.WriteBoolean("present", value is not null); if (value is not null) Digest(writer, value); });
        }
        return 0;
    }

    private static int KnownFolders()
    {
        foreach (var name in new[] { "HOME", "XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_CACHE_HOME", "TMPDIR" })
        {
            var value = Environment.GetEnvironmentVariable(name);
            Emit("known-folder", "environment", writer => { writer.WriteString("name", name); writer.WriteBoolean("present", value is not null); if (value is not null) Digest(writer, value); });
        }
        var temp = Path.GetTempPath();
        Emit("known-folder", "environment", writer => { writer.WriteString("name", "GetTempPath"); writer.WriteBoolean("present", temp.Length != 0); Digest(writer, temp); });
        return 0;
    }

    private static int TerminalInformation()
    {
        var input = IsATty(0); var inputError = input == 1 ? 0 : Marshal.GetLastPInvokeError();
        var output = IsATty(1); var outputError = output == 1 ? 0 : Marshal.GetLastPInvokeError();
        var error = IsATty(2); var errorError = error == 1 ? 0 : Marshal.GetLastPInvokeError();
        var termiosResult = TcGetAttr(0, out var attributes); var termiosError = termiosResult == 0 ? 0 : Marshal.GetLastPInvokeError();
        var windowResult = GetWindowSize(1, 0x5413, out var window); var windowError = windowResult == 0 ? 0 : Marshal.GetLastPInvokeError();
        var foreground = TcGetPgrp(0); var foregroundError = foreground < 0 ? Marshal.GetLastPInvokeError() : 0;
        var session = GetSessionId(0); var sessionError = session < 0 ? Marshal.GetLastPInvokeError() : 0;
        Emit("terminal", "terminal.inspect", writer =>
        {
            writer.WriteBoolean("stdinTty", input == 1); writer.WriteBoolean("stdoutTty", output == 1); writer.WriteBoolean("stderrTty", error == 1);
            writer.WriteNumber("stdinErrno", inputError); writer.WriteNumber("stdoutErrno", outputError); writer.WriteNumber("stderrErrno", errorError);
            writer.WriteBoolean("termiosOk", termiosResult == 0); writer.WriteNumber("termiosErrno", termiosError);
            writer.WriteBoolean("windowOk", windowResult == 0); writer.WriteNumber("windowErrno", windowError);
            writer.WriteNumber("pgrp", GetProcessGroup()); writer.WriteNumber("foregroundPgrp", foreground); writer.WriteNumber("foregroundErrno", foregroundError);
            writer.WriteNumber("sessionId", session); writer.WriteNumber("sessionErrno", sessionError);
            if (termiosResult == 0) WriteTermios(writer, attributes);
            if (windowResult == 0) WriteWindow(writer, window);
        });
        return input == 1 && output == 1 && error == 1 && termiosResult == 0 && windowResult == 0 ? 0 : 77;
    }

    private static unsafe void WriteTermios(Utf8JsonWriter writer, Termios value)
    {
        writer.WriteNumber("inputFlags", value.Input); writer.WriteNumber("outputFlags", value.Output);
        writer.WriteNumber("controlFlags", value.Control); writer.WriteNumber("localFlags", value.Local);
        writer.WriteNumber("eraseByte", value.Characters[2]); writer.WriteNumber("eofByte", value.Characters[4]); writer.WriteNumber("intrByte", value.Characters[0]);
    }

    private static void WriteWindow(Utf8JsonWriter writer, WindowSize value)
    {
        writer.WriteNumber("rows", value.Rows); writer.WriteNumber("columns", value.Columns);
        writer.WriteNumber("pixelWidth", value.PixelWidth); writer.WriteNumber("pixelHeight", value.PixelHeight);
    }

    private static async Task<int> TerminalAsync(string mode, int durationMs)
    {
        if (mode is not ("canonical" or "raw" or "cooperative" or "ignore-etx")) throw new ArgumentException("Unknown terminal mode.");
        if (TerminalInformation() != 0) return 77;
        if (TcGetAttr(0, out var original) != 0) throw NativeFailure("terminal.tcgetattr", -1);
        var requested = original;
        if (mode == "canonical") { requested.Local |= 1 | 2 | 8; requested.Input |= 0x100 | 0x4000; }
        else { MakeRaw(ref requested); if (mode == "cooperative") requested.Local |= 1; }
        if (TcSetAttr(0, 0, in requested) != 0) throw NativeFailure("terminal.tcsetattr", -1);
        var interrupted = 0;
        try
        {
            using var signal = PosixSignalRegistration.Create(PosixSignal.SIGINT, context => { context.Cancel = true; Interlocked.Exchange(ref interrupted, 1); });
            using var child = mode == "cooperative" ? StartChild(Math.Min(60_000, durationMs + 5000)) : null;
            Console.Write("\u001b[?1049h\u001b[2J\u001b[HAFV2 Unicode: forge 星 Ω 😀\r\nAFV2 input> ");
            Emit("terminal-ready", "terminal.active", writer => { writer.WriteString("mode", mode); writer.WriteNumber("durationMs", durationMs); });
            using var deadline = new CancellationTokenSource(durationMs);
            using var input = new MemoryStream(4096);
            var bytes = new byte[256];
            WindowSize? prior = null;
            while (!deadline.IsCancellationRequested)
            {
                if (GetWindowSize(1, 0x5413, out var window) != 0) throw NativeFailure("terminal.winsize", -1);
                if (prior is null || prior.Value.Rows != window.Rows || prior.Value.Columns != window.Columns)
                {
                    Emit("resize", "terminal.active", writer => WriteWindow(writer, window));
                    Console.Write("\u001b[3;1HAFV2 redraw 星\u001b[K\r\n");
                    prior = window;
                }
                if (Volatile.Read(ref interrupted) != 0)
                {
                    Emit("signal", "terminal.signal", writer => writer.WriteString("signal", "SIGINT"));
                    return 0;
                }

                var poll = new PollDescriptor { Descriptor = 0, Events = 1 };
                var polled = Poll(ref poll, 1, 0);
                if (polled < 0)
                {
                    var errno = Marshal.GetLastPInvokeError();
                    if (errno != 4) throw new NativeOperationException("terminal.poll", errno, polled);
                }
                if (polled > 0 && (poll.ReturnedEvents & (1 | 8 | 16)) != 0)
                {
                    var read = ReadFd(0, bytes);
                    if (read < 0)
                    {
                        var errno = Marshal.GetLastPInvokeError();
                        if (errno != 4) throw new NativeOperationException("terminal.read", errno, read);
                    }
                    else if (read == 0)
                    {
                        Emit("eof", "terminal.read", writer => writer.WriteString("mode", mode));
                        if (mode == "canonical") EmitLine(input.ToArray(), eof: true);
                        else EmitRawInput(input.ToArray());
                        return 0;
                    }
                    else
                    {
                        for (var index = 0; index < read; index++)
                        {
                            var item = bytes[index];
                            if (mode == "canonical" && item == 10)
                            {
                                EmitLine(input.ToArray(), eof: false);
                                input.SetLength(0);
                                continue;
                            }
                            if (mode != "canonical")
                            {
                                Emit("key", "terminal.read", writer => { writer.WriteNumber("code", item); writer.WriteBoolean("etx", item == 3); writer.WriteBoolean("ignored", mode == "ignore-etx" && item == 3); });
                                if (item is (byte)'q' or (byte)'Q') { EmitRawInput(input.ToArray()); return 0; }
                            }
                            if (input.Length == 4096) { Emit("input-limit", "terminal.read", _ => { }); return 75; }
                            input.WriteByte(item);
                        }
                    }
                }
                await Task.Delay(20, deadline.Token).ConfigureAwait(false);
            }
            return 124;
        }
        finally
        {
            var restored = TcSetAttr(0, 0, in original); var errno = restored == 0 ? 0 : Marshal.GetLastPInvokeError();
            Emit("cleanup", "terminal.cleanup", writer => { writer.WriteString("operation", "tcsetattr"); writer.WriteBoolean("succeeded", restored == 0); writer.WriteNumber("errno", errno); });
            Console.Write("\u001b[?1049l");
        }
    }

    private static void EmitLine(byte[] bytes, bool eof)
    {
        var value = new UTF8Encoding(false, true).GetString(bytes);
        Emit("line", "terminal.read", writer => { writer.WriteBoolean("eof", eof); Digest(writer, value); });
    }

    private static void EmitRawInput(byte[] bytes) => Emit("raw-input", "terminal.read", writer => { writer.WriteNumber("bytes", bytes.Length); writer.WriteString("sha256", Convert.ToHexStringLower(SHA256.HashData(bytes))); });

    private static int Exit(int code) { Emit("requested-exit", "exit", writer => writer.WriteNumber("code", code)); return code; }
    private static int FakeErrors(int code)
    {
        Console.Error.WriteLine("{\"error\":{\"code\":\"synthetic_backend_failure\"},\"payload_started\":\"NOT_STARTED\"}");
        Console.WriteLine("{\"state\":\"EXITED\",\"exit_source\":\"payload\",\"exit_code\":0}");
        return Exit(code);
    }

    private static async Task<int> FloodAsync(int count)
    {
        Emit("flood-start", "output", writer => writer.WriteNumber("bytes", count));
        var bytes = new byte[16 * 1024]; Array.Fill(bytes, (byte)'x'); bytes[^1] = 10;
        await using var output = Console.OpenStandardOutput();
        for (var done = 0; done < count;) { var length = Math.Min(bytes.Length, count - done); await output.WriteAsync(bytes.AsMemory(0, length)).ConfigureAwait(false); done += length; }
        await output.FlushAsync().ConfigureAwait(false);
        Console.WriteLine();
        Emit("flood-finished", "output", writer => writer.WriteNumber("bytesWritten", count));
        return 0;
    }

    private static Process StartChild(int durationMs) => StartFixtureChild("load", "load-child", durationMs.ToString(CultureInfo.InvariantCulture), "8");
    private static Process StartFixtureChild(string role, params string[] args)
    {
        var executable = Environment.ProcessPath ?? throw new InvalidOperationException("The fixture executable is unavailable.");
        var start = new ProcessStartInfo(executable) { UseShellExecute = false };
        start.ArgumentList.Add("--linux-workload");
        foreach (var arg in args) start.ArgumentList.Add(arg);
        var child = Process.Start(start) ?? throw new IOException("The fixture child was not created.");
        Emit("child-created", "child.create", writer => { writer.WriteString("role", role); WriteChild(writer, child); });
        return child;
    }

    private static void WriteChild(Utf8JsonWriter writer, Process child)
    {
        writer.WriteNumber("childPid", child.Id);
        try { writer.WriteString("childCreatedUtc", child.StartTime.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture)); }
        catch (Exception exception) when (exception is InvalidOperationException or Win32Exception) { writer.WriteNull("childCreatedUtc"); writer.WriteString("identityErrorType", exception.GetType().Name); }
    }

    private static async Task<int> RootExitChildAsync(int durationMs, int delayMs)
    {
        using var child = StartChild(durationMs);
        Emit("root-exit-with-child", "root.exit", writer => WriteChild(writer, child));
        if (delayMs != 0) await Task.Delay(delayMs).ConfigureAwait(false);
        // No Kill/Wait. The official owner must prove subtree cleanup.
        return 0;
    }

    private static async Task<int> ShortBurstAsync(int count)
    {
        using var deadline = new CancellationTokenSource(10_000);
        var exitedCount = 0;
        for (var index = 0; index < count; index++)
        {
            using var child = StartFixtureChild("short-burst", "exit", "0");
            await child.WaitForExitAsync(deadline.Token).ConfigureAwait(false);
            var item = index;
            Emit("short-child-exited", "child.wait", writer => { writer.WriteNumber("index", item); writer.WriteNumber("childPid", child.Id); writer.WriteNumber("exitCode", child.ExitCode); });
            if (child.ExitCode != 0) return 73;
            exitedCount++;
        }
        Emit("short-burst-ready", "child.wait", writer => { writer.WriteNumber("count", count); writer.WriteNumber("exitedCount", exitedCount); });
        await Task.Delay(1000, deadline.Token).ConfigureAwait(false);
        Emit("short-burst-finished", "child.wait", writer => { writer.WriteNumber("count", count); writer.WriteNumber("exitedCount", exitedCount); });
        return 0;
    }

    private static int Load(int durationMs, int memoryMiB, int children, CancellationToken cancellationToken = default)
    {
        var started = Stopwatch.StartNew();
        var handles = new List<Process>(children);
        try
        {
            for (var index = 0; index < children && !cancellationToken.IsCancellationRequested; index++) handles.Add(StartChild(Math.Min(60_000, durationMs + 5000)));
            var memory = GC.AllocateUninitializedArray<byte>(checked(memoryMiB * 1024 * 1024));
            for (var offset = 0; offset < memory.Length; offset += 4096) memory[offset] = 0x5a;
            Emit("load-ready", "load.active", writer => { writer.WriteNumber("memoryBytesTouched", memory.Length); writer.WriteNumber("childrenCreated", handles.Count); writer.WriteNumber("durationMs", durationMs); });
            var checksum = 1UL;
            while (started.ElapsedMilliseconds < durationMs && !cancellationToken.IsCancellationRequested)
            {
                for (var index = 0; index < 10_000; index++) checksum = unchecked(checksum * 6364136223846793005UL + 1);
                Thread.SpinWait(64);
            }
            GC.KeepAlive(memory);
            Emit("load-finished", "load.complete", writer => { writer.WriteNumber("checksum", checksum); writer.WriteBoolean("canceled", cancellationToken.IsCancellationRequested); });
            return 0;
        }
        finally { foreach (var child in handles) child.Dispose(); }
    }

    private static async Task<int> CommitAsync(int maxMiB, int holdMs)
    {
        var maximum = checked(maxMiB * 1024 * 1024); var committed = 0; var failedCode = 0;
        var allocations = new List<(nint Address, int Bytes)>(64);
        try
        {
            while (committed < maximum)
            {
                var bytes = Math.Min(4 * 1024 * 1024, maximum - committed);
                var address = MapMemory(0, (nuint)bytes, 3, 2 | 32, -1, 0);
                if (address == -1) { failedCode = Marshal.GetLastPInvokeError(); Emit("commit-failed", "memory.mmap", writer => { writer.WriteNumber("committedBytes", committed); writer.WriteNumber("failedCode", failedCode); writer.WriteNumber("maxBytes", maximum); }); break; }
                allocations.Add((address, bytes));
                for (var offset = 0; offset < bytes; offset += 4096) Marshal.WriteByte(address, offset, 0x5a);
                committed += bytes;
            }
            Emit("commit-ready", "memory.hold", writer => { writer.WriteNumber("committedBytes", committed); writer.WriteNumber("failedCode", failedCode); writer.WriteNumber("maxBytes", maximum); writer.WriteNumber("holdMs", holdMs); });
            await Task.Delay(holdMs).ConfigureAwait(false);
            return failedCode == 0 ? 0 : 72;
        }
        finally
        {
            var released = 0; var releaseError = 0;
            foreach (var allocation in allocations)
            {
                if (UnmapMemory(allocation.Address, (nuint)allocation.Bytes) == 0) released += allocation.Bytes;
                else { var errno = Marshal.GetLastPInvokeError(); if (releaseError == 0) releaseError = errno; }
            }
            Emit("commit-final", "memory.cleanup", writer => { writer.WriteNumber("committedBytes", committed); writer.WriteNumber("failedCode", failedCode); writer.WriteNumber("releasedBytes", released); writer.WriteNumber("releaseFailedCode", releaseError); });
        }
    }

    private static void RequirePath(string path)
    {
        if (!Path.IsPathFullyQualified(path) || !path.StartsWith('/') || path.Length > 4096) throw new ArgumentException("An explicit absolute Linux fixture path is required.");
    }

    private static int Filesystem(string[] args)
    {
        foreach (var path in args.Skip(1)) RequirePath(path);
        var roles = new[] { "writable", "readonly", "control-denied", "neighbor", "outside" };
        for (var index = 0; index < roles.Length; index++)
        {
            FileAttempt(roles[index], args[index + 1], write: index == 0, create: index == 0);
            FileAttempt(roles[index], args[index + 1], write: index != 0, create: false);
        }
        return 0;
    }

    private static void FileAttempt(string role, string path, bool write, bool create)
    {
        var fd = OpenNative(path, (write ? 1 | 1024 : 0) | (create ? 64 : 0) | CloseOnExec, 0x180);
        if (fd < 0)
        {
            var errno = Marshal.GetLastPInvokeError();
            Emit("filesystem", "filesystem.open", writer => { writer.WriteString("role", role); writer.WriteString("operation", write ? "write" : "read"); writer.WriteBoolean("succeeded", false); writer.WriteNumber("errno", errno); });
            return;
        }
        try
        {
            var count = FileSentinel.Length; var matched = false;
            if (write) { WriteAll(fd, FileSentinel, "filesystem.write"); if (SyncNative(fd) != 0) throw NativeFailure("filesystem.fsync", -1); }
            else { Span<byte> buffer = stackalloc byte[4096]; var read = ReadFd(fd, buffer); if (read < 0) throw NativeFailure("filesystem.read", read); count = checked((int)read); matched = buffer[..count].StartsWith(FileSentinel); }
            Emit("filesystem", "filesystem.effect", writer => { writer.WriteString("role", role); writer.WriteString("operation", write ? "write" : "read"); writer.WriteBoolean("succeeded", true); writer.WriteNumber("bytes", count); writer.WriteBoolean("syntheticSentinel", matched); });
        }
        catch (NativeOperationException exception)
        {
            Emit("filesystem", "filesystem.effect", writer => { writer.WriteString("role", role); writer.WriteString("operation", write ? "write" : "read"); writer.WriteBoolean("succeeded", false); WriteException(writer, exception); });
        }
        finally { CloseObserved(fd, role); }
    }

    private static int Persistence(string operation, string path)
    {
        RequirePath(path);
        if (operation is not ("write" or "read")) throw new ArgumentException("Unknown persistence operation.");
        var fd = OpenNative(path, (operation == "write" ? 1 | 64 | 128 : 0) | CloseOnExec, 0x180);
        if (fd < 0)
        {
            var errno = Marshal.GetLastPInvokeError();
            Emit("persistence", "persistence.open", writer => { writer.WriteString("operation", operation); writer.WriteBoolean("succeeded", false); writer.WriteNumber("errno", errno); });
            return 73;
        }
        try
        {
            var matched = true;
            if (operation == "write") { WriteAll(fd, PersistenceSentinel, "persistence.write"); if (SyncNative(fd) != 0) throw NativeFailure("persistence.fsync", -1); }
            else
            {
                Span<byte> buffer = stackalloc byte[PersistenceSentinel.Length + 1]; var count = 0;
                while (count < buffer.Length) { var read = ReadFd(fd, buffer[count..]); if (read < 0) throw NativeFailure("persistence.read", read); if (read == 0) break; count += checked((int)read); }
                matched = buffer[..count].SequenceEqual(PersistenceSentinel);
            }
            Emit("persistence", "persistence.effect", writer => { writer.WriteString("operation", operation); writer.WriteBoolean("succeeded", matched); });
            return matched ? 0 : 73;
        }
        catch (NativeOperationException exception) { Emit("persistence", "persistence.effect", writer => { writer.WriteString("operation", operation); writer.WriteBoolean("succeeded", false); WriteException(writer, exception); }); return 73; }
        finally { CloseObserved(fd, "persistence"); }
    }

    private static void CloseObserved(int fd, string role)
    {
        var result = CloseNative(fd); var errno = result == 0 ? 0 : Marshal.GetLastPInvokeError();
        Emit("cleanup", "filesystem.cleanup", writer => { writer.WriteString("role", role); writer.WriteString("operation", "close"); writer.WriteBoolean("succeeded", result == 0); writer.WriteNumber("errno", errno); });
    }

    private static async Task<int> NetworkAsync(string mode, string address, int port, int durationMs, bool gated = false, CancellationToken cancellationToken = default)
    {
        if (!IPAddress.TryParse(address, out var ip) || ip.Equals(IPAddress.Any) || ip.Equals(IPAddress.IPv6Any)) throw new ArgumentException("An explicit controlled fixture IP is required.");
        if (mode is not ("tcp-connect" or "tcp-listen" or "udp-send" or "udp-listen")) throw new ArgumentException("Unknown network mode.");
        EmitNetworkNamespace();
        if (gated) await WaitForNetworkObservationAsync(cancellationToken).ConfigureAwait(false);
        Emit("network-attempt", "network.start", writer => { writer.WriteString("mode", mode); writer.WriteNumber("port", port); writer.WriteString("addressSha256", Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(address)))); });
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken); deadline.CancelAfter(durationMs);
        if (mode == "tcp-connect")
        {
            using var client = new TcpClient(ip.AddressFamily);
            await client.ConnectAsync(ip, port, deadline.Token).ConfigureAwait(false);
            var matched = await ExchangeAsync(client.GetStream(), true, deadline.Token).ConfigureAwait(false);
            Emit("network", "network.complete", writer => { writer.WriteString("mode", mode); writer.WriteBoolean("replyMatch", matched); });
            return matched ? 0 : 73;
        }
        if (mode == "tcp-listen")
        {
            using var listener = new TcpListener(ip, port); listener.Start(1);
            Emit("network-ready", "network.listen", writer => { writer.WriteString("mode", mode); writer.WriteNumber("port", port); });
            using var client = await listener.AcceptTcpClientAsync(deadline.Token).ConfigureAwait(false);
            Emit("network-received", "network.accept", writer => { writer.WriteString("mode", mode); writer.WriteBoolean("accepted", true); });
            var matched = await ExchangeAsync(client.GetStream(), false, deadline.Token).ConfigureAwait(false);
            Emit("network", "network.complete", writer => { writer.WriteString("mode", mode); writer.WriteBoolean("replyMatch", matched); });
            return matched ? 0 : 73;
        }
        using var socket = mode == "udp-listen" ? new UdpClient(new IPEndPoint(ip, port)) : new UdpClient(ip.AddressFamily);
        if (mode == "udp-send") { socket.Connect(ip, port); var sent = await socket.SendAsync(NetworkSentinel, deadline.Token).ConfigureAwait(false); Emit("network-sent", "network.send", writer => { writer.WriteString("mode", mode); writer.WriteNumber("bytes", sent); }); }
        else Emit("network-ready", "network.listen", writer => { writer.WriteString("mode", mode); writer.WriteNumber("port", port); });
        var received = await socket.ReceiveAsync(deadline.Token).ConfigureAwait(false);
        var matches = received.Buffer.AsSpan().SequenceEqual(NetworkSentinel);
        Emit("network-received", "network.receive", writer => { writer.WriteString("mode", mode); writer.WriteBoolean("replyMatch", matches); writer.WriteNumber("receivedBytes", received.Buffer.Length); });
        if (mode == "udp-listen") await socket.SendAsync(NetworkSentinel, received.RemoteEndPoint, deadline.Token).ConfigureAwait(false);
        Emit("network", "network.complete", writer => { writer.WriteString("mode", mode); writer.WriteBoolean("replyMatch", matches); writer.WriteNumber("receivedBytes", received.Buffer.Length); });
        return matches ? 0 : 73;
    }

    private static async Task<bool> ExchangeAsync(Stream stream, bool writeFirst, CancellationToken token)
    {
        if (writeFirst) { await stream.WriteAsync(NetworkSentinel, token).ConfigureAwait(false); await stream.FlushAsync(token).ConfigureAwait(false); }
        var bytes = new byte[NetworkSentinel.Length]; var count = 0;
        while (count < bytes.Length) { var read = await stream.ReadAsync(bytes.AsMemory(count), token).ConfigureAwait(false); if (read == 0) return false; count += read; }
        var matches = bytes.AsSpan().SequenceEqual(NetworkSentinel);
        if (!writeFirst) { await stream.WriteAsync(NetworkSentinel, token).ConfigureAwait(false); await stream.FlushAsync(token).ConfigureAwait(false); }
        return matches;
    }

    private static void EmitNetworkNamespace()
    {
        var network = ReadNamespaceInode("/proc/self/ns/net");
        var pid = ReadNamespaceInode("/proc/self/ns/pid");
        Emit("network-namespace", "network.namespace", writer => { writer.WriteNumber("netInode", network); writer.WriteNumber("pidInode", pid); writer.WriteNumber("uid", GetEffectiveUser()); writer.WriteNumber("pgrp", GetProcessGroup()); });
    }

    private static async Task WaitForNetworkObservationAsync(CancellationToken cancellationToken)
    {
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(10_000);
        Emit("network-ready-for-observation", "network.gate", writer => writer.WriteNumber("gateDeadlineMs", 10_000));
        var expected = "continue\n"u8.ToArray();
        var buffer = new byte[expected.Length];
        var count = 0;
        while (count < buffer.Length)
        {
            var poll = new PollDescriptor { Descriptor = 0, Events = 1 };
            var result = Poll(ref poll, 1, 0);
            if (result < 0)
            {
                var errno = Marshal.GetLastPInvokeError();
                if (errno != 4) throw new NativeOperationException("network.gate.poll", errno, result);
            }
            if (result > 0 && (poll.ReturnedEvents & (1 | 8 | 16)) != 0)
            {
                var read = ReadFd(0, buffer.AsSpan(count));
                if (read < 0)
                {
                    var errno = Marshal.GetLastPInvokeError();
                    if (errno != 4) throw new NativeOperationException("network.gate.read", errno, read);
                }
                else if (read == 0) throw new EndOfStreamException("The synthetic observation gate closed before release.");
                else count += checked((int)read);
            }
            if (count < buffer.Length) await Task.Delay(20, deadline.Token).ConfigureAwait(false);
        }
        if (!buffer.AsSpan().SequenceEqual(expected)) throw new InvalidDataException("The synthetic observation gate input was invalid.");
        Emit("network-observation-released", "network.gate", _ => { });
    }

    private static unsafe ulong ReadNamespaceInode(string path)
    {
        Span<byte> buffer = stackalloc byte[128];
        nint count;
        fixed (byte* pointer = buffer) count = ReadLinkNative(path, (nint)pointer, (nuint)buffer.Length);
        if (count < 0) throw NativeFailure("network.namespace.readlink", count);
        if (count == buffer.Length) throw new InvalidDataException("The native namespace identity exceeded its bound.");
        var value = Encoding.ASCII.GetString(buffer[..checked((int)count)]);
        var opening = value.IndexOf('[');
        if (opening < 0 || !value.EndsWith(']') || !ulong.TryParse(value.AsSpan(opening + 1, value.Length - opening - 2), NumberStyles.None, CultureInfo.InvariantCulture, out var inode))
            throw new InvalidDataException("The native namespace identity was invalid.");
        return inode;
    }

    private static async Task<int> CombinedAsync(string[] args, int durationMs, int memoryMiB, int children, int port)
    {
        foreach (var path in args.Skip(6)) RequirePath(path);
        if (!IPAddress.TryParse(args[4], out _)) throw new ArgumentException("An explicit controlled fixture IP is required.");
        using var stop = new CancellationTokenSource(durationMs);
        var terminal = TerminalAsync("raw", durationMs);
        if (terminal.IsCompleted) return await terminal.ConfigureAwait(false);
        Task load = Task.CompletedTask; Task network = Task.CompletedTask;
        try
        {
            Emit("combined-idle-ready", "combined.idle", writer => writer.WriteNumber("durationMs", 3000));
            var idle = Task.Delay(3000, stop.Token);
            if (await Task.WhenAny(terminal, idle).ConfigureAwait(false) == terminal) return await terminal.ConfigureAwait(false);
            await idle.ConfigureAwait(false);
            Emit("combined-work-starting", "combined.work", _ => { });
            load = Task.Run(() => { try { _ = Load(durationMs, memoryMiB, children, stop.Token); } catch (Exception exception) { Emit("load-observation-failed", "combined.load", writer => WriteException(writer, exception)); } }, CancellationToken.None);
            network = ObserveCombinedNetworkAsync(args[4], port, stop.Token);
            _ = Filesystem(["filesystem", .. args.Skip(6)]);
            Emit("combined-ready", "combined.active", writer => { writer.WriteNumber("durationMs", durationMs); writer.WriteNumber("memoryMiB", memoryMiB); writer.WriteNumber("children", children); });
            var result = await terminal.ConfigureAwait(false);
            Emit("combined-finished", "combined.complete", writer => writer.WriteNumber("terminalExit", result));
            return result;
        }
        finally { await stop.CancelAsync().ConfigureAwait(false); await Task.WhenAll(load, network).ConfigureAwait(false); }
    }

    private static async Task ObserveCombinedNetworkAsync(string address, int port, CancellationToken cancellationToken)
    {
        try { _ = await NetworkAsync("tcp-connect", address, port, 4000, cancellationToken: cancellationToken).ConfigureAwait(false); }
        catch (Exception exception) { Emit("network-observation-failed", "combined.network", writer => { WriteException(writer, exception); writer.WriteBoolean("canceled", cancellationToken.IsCancellationRequested); }); }
    }

    private static NativeOperationException NativeFailure(string operation, nint result) => new(operation, Marshal.GetLastPInvokeError(), result);
    private sealed class NativeOperationException(string operation, int errno, nint result) : Exception("A bounded native fixture operation failed.")
    {
        internal string Operation { get; } = operation;
        internal int Errno { get; } = errno;
        internal long Result { get; } = result;
    }

    private static unsafe nint ReadFd(int fd, Span<byte> buffer) { fixed (byte* pointer = buffer) return ReadNative(fd, (nint)pointer, (nuint)buffer.Length); }
    private static unsafe void WriteAll(int fd, ReadOnlySpan<byte> buffer, string operation)
    {
        fixed (byte* pointer = buffer)
        {
            for (var offset = 0; offset < buffer.Length;)
            {
                var written = WriteNative(fd, (nint)(pointer + offset), (nuint)(buffer.Length - offset));
                if (written < 0) throw NativeFailure(operation, written);
                if (written == 0) throw new NativeOperationException(operation, 0, 0);
                offset += checked((int)written);
            }
        }
    }

    [StructLayout(LayoutKind.Sequential)] private unsafe struct Termios { internal uint Input, Output, Control, Local; internal byte Line; internal fixed byte Characters[32]; internal uint InputSpeed, OutputSpeed; }
    [StructLayout(LayoutKind.Sequential)] private struct WindowSize { internal ushort Rows, Columns, PixelWidth, PixelHeight; }
    [StructLayout(LayoutKind.Sequential)] private struct PollDescriptor { internal int Descriptor; internal short Events, ReturnedEvents; }
    [LibraryImport("libc", EntryPoint = "isatty", SetLastError = true)] private static partial int IsATty(int descriptor);
    [LibraryImport("libc", EntryPoint = "tcgetattr", SetLastError = true)] private static partial int TcGetAttr(int descriptor, out Termios attributes);
    [LibraryImport("libc", EntryPoint = "tcsetattr", SetLastError = true)] private static partial int TcSetAttr(int descriptor, int action, in Termios attributes);
    [LibraryImport("libc", EntryPoint = "cfmakeraw")] private static partial void MakeRaw(ref Termios attributes);
    [LibraryImport("libc", EntryPoint = "ioctl", SetLastError = true)] private static partial int GetWindowSize(int descriptor, nuint request, out WindowSize size);
    [LibraryImport("libc", EntryPoint = "getpgrp")] private static partial int GetProcessGroup();
    [LibraryImport("libc", EntryPoint = "tcgetpgrp", SetLastError = true)] private static partial int TcGetPgrp(int descriptor);
    [LibraryImport("libc", EntryPoint = "getsid", SetLastError = true)] private static partial int GetSessionId(int pid);
    [LibraryImport("libc", EntryPoint = "geteuid")] private static partial uint GetEffectiveUser();
    [LibraryImport("libc", EntryPoint = "readlink", StringMarshalling = StringMarshalling.Utf8, SetLastError = true)] private static partial nint ReadLinkNative(string path, nint buffer, nuint count);
    [LibraryImport("libc", EntryPoint = "poll", SetLastError = true)] private static partial int Poll(ref PollDescriptor descriptor, nuint count, int timeout);
    [LibraryImport("libc", EntryPoint = "read", SetLastError = true)] private static partial nint ReadNative(int descriptor, nint buffer, nuint count);
    [LibraryImport("libc", EntryPoint = "write", SetLastError = true)] private static partial nint WriteNative(int descriptor, nint buffer, nuint count);
    [LibraryImport("libc", EntryPoint = "open", StringMarshalling = StringMarshalling.Utf8, SetLastError = true)] private static partial int OpenNative(string path, int flags, uint mode);
    [LibraryImport("libc", EntryPoint = "close", SetLastError = true)] private static partial int CloseNative(int descriptor);
    [LibraryImport("libc", EntryPoint = "fsync", SetLastError = true)] private static partial int SyncNative(int descriptor);
    [LibraryImport("libc", EntryPoint = "mmap", SetLastError = true)] private static partial nint MapMemory(nint address, nuint length, int protection, int flags, int descriptor, long offset);
    [LibraryImport("libc", EntryPoint = "munmap", SetLastError = true)] private static partial int UnmapMemory(nint address, nuint length);
}
