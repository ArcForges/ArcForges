// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using System.Globalization;
using System.IO.Pipes;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace ArcForges.MxcProbe;

// A bounded, deliberately untrusted payload of the native experiment. Its output
// is never the supervisor's admission, process identity, exit or cleanup proof.
internal static partial class WindowsWorkload
{
    private const uint ProcessedInput = 0x0001;
    private const uint LineInput = 0x0002;
    private const uint EchoInput = 0x0004;
    private const uint WindowInput = 0x0008;
    private const uint QuickEdit = 0x0040;
    private const uint ExtendedFlags = 0x0080;
    private const uint VirtualTerminalOutput = 0x0004;
    // At most this root plus eight non-recursive children can share the
    // driver's per-case directory: nine capped files stay below one MiB.
    private const int ObservationLimitBytes = 64 * 1024;
    private static readonly object OutputGate = new();
    private static readonly byte[] FileSentinel = "AFV2_FILE_SENTINEL\n"u8.ToArray();
    private static readonly byte[] NetworkSentinel = "AFV2_NET_SENTINEL\n"u8.ToArray();
    private static readonly byte[] PersistenceSentinel = "AFV2_PERSISTENCE_SENTINEL\n"u8.ToArray();
    private static string? observationPath;
    private static bool observationInitialized;
    private static int observationBytes;

    internal static async Task<int> RunAsync(string[] args)
    {
        if (!OperatingSystem.IsWindows())
        {
            Emit("unsupported", writer => writer.WriteString("reason", "windows-required"));
            return 77;
        }

        try
        {
            if (args.Length == 0)
            {
                throw new ArgumentException("A fixed workload mode is required.");
            }

            return args[0] switch
            {
                "console-info" when args.Length == 1 => ConsoleInformation(),
                "argv" when args.Length <= 33 => Arguments(args),
                "environment" when args.Length is >= 2 and <= 17 => EnvironmentVariables(args),
                "known-folders" when args.Length == 1 => KnownFolders(),
                "console" when args.Length == 3 => await ConsoleAsync(args[1], Number(args[2], 100, 60_000)).ConfigureAwait(false),
                "combined" when args.Length == 11 => await CombinedAsync(args, Number(args[1], 100, 60_000), Number(args[2], 0, 256), Number(args[3], 0, 8), Number(args[5], 1, 65535)).ConfigureAwait(false),
                "flood" when args.Length == 2 => await FloodAsync(Number(args[1], 1, 8 * 1024 * 1024)).ConfigureAwait(false),
                "exit" when args.Length == 2 => Exit(Number(args[1], 0, 255)),
                "fake-errors" when args.Length == 2 => FakeErrors(Number(args[1], 0, 255)),
                "load" when args.Length == 4 => Load(Number(args[1], 100, 60_000), Number(args[2], 0, 256), Number(args[3], 0, 8)),
                "load-child" when args.Length == 3 => Load(Number(args[1], 100, 60_000), Number(args[2], 0, 16), 0),
                "commit" when args.Length == 3 => await CommitAsync(Number(args[1], 1, 256), Number(args[2], 100, 60_000)).ConfigureAwait(false),
                "root-exit-child" when args.Length is 2 or 3 => RootExitChild(Number(args[1], 1000, 60_000), args.Length == 3 ? Number(args[2], 0, 60_000) : 0),
                "short-burst" when args.Length == 2 => await ShortBurstAsync(Number(args[1], 1, 8)).ConfigureAwait(false),
                "pipe-roundtrip" when args.Length == 2 => await PipeRoundtripAsync(args[1]).ConfigureAwait(false),
                "build-test" when args.Length == 5 => await BuildTestAsync(args[1], args[2], args[3], args[4]).ConfigureAwait(false),
                "persistence" when args.Length == 3 => Persistence(args[1], args[2]),
                "filesystem" when args.Length == 6 => Filesystem(args),
                "pipe" when args.Length == 4 => await PipeAsync(args[1], args[2], Number(args[3], 100, 60_000)).ConfigureAwait(false),
                "network" when args.Length == 5 => await NetworkAsync(args[1], args[2], Number(args[3], 1, 65535), Number(args[4], 100, 60_000)).ConfigureAwait(false),
                _ => throw new ArgumentException("Unknown workload mode or argument count.")
            };
        }
        catch (OperationCanceledException)
        {
            Emit("deadline", writer => writer.WriteString("reason", "fixture-deadline"));
            return 124;
        }
        catch (ArgumentException)
        {
            Emit("invalid-arguments", _ => { });
            return 64;
        }
        catch (OutOfMemoryException)
        {
            Emit("allocation-failed", _ => { });
            return 72;
        }
        catch (Exception exception)
        {
            EmitError("fixture", exception);
            return 70;
        }
    }

    private static int Number(string text, int minimum, int maximum)
    {
        if (!int.TryParse(text, NumberStyles.None, CultureInfo.InvariantCulture, out var value) || value < minimum || value > maximum)
        {
            throw new ArgumentException("A workload bound is invalid.");
        }

        return value;
    }

    private static void Emit(string name, Action<Utf8JsonWriter> fields)
    {
        using var buffer = new MemoryStream();
        using (var writer = new Utf8JsonWriter(buffer))
        {
            writer.WriteStartObject();
            writer.WriteString("fixture", "windows-workload-v1");
            writer.WriteNumber("pid", Environment.ProcessId);
            writer.WriteString("event", name);
            fields(writer);
            writer.WriteEndObject();
        }

        lock (OutputGate)
        {
            AppendObservation(buffer.GetBuffer().AsSpan(0, checked((int)buffer.Length)));
            Console.WriteLine(Encoding.UTF8.GetString(buffer.GetBuffer(), 0, checked((int)buffer.Length)));
        }
    }

    private static void AppendObservation(ReadOnlySpan<byte> value)
    {
        try
        {
            if (!observationInitialized)
            {
                observationInitialized = true;
                var directory = Environment.GetEnvironmentVariable("AFV2_MXC_OBSERVATIONS_DIR");
                if (directory is null)
                {
                    return;
                }

                if (!Path.IsPathFullyQualified(directory) || Path.GetPathRoot(directory) is not { Length: 3 } || !Directory.Exists(directory))
                {
                    throw new IOException("The explicitly owned observation directory is unavailable.");
                }

                var path = Path.Combine(directory, $"{Environment.ProcessId.ToString(CultureInfo.InvariantCulture)}.jsonl");
                using (var created = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.Read))
                {
                    created.Flush();
                }

                observationPath = path;
            }

            if (observationPath is null || value.Length + 1 > ObservationLimitBytes - observationBytes)
            {
                return;
            }

            using var file = new FileStream(observationPath, FileMode.Append, FileAccess.Write, FileShare.Read);
            file.Write(value);
            file.WriteByte((byte)'\n');
            file.Flush();
            observationBytes += value.Length + 1;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or System.Security.SecurityException or ArgumentException or NotSupportedException)
        {
            // This auxiliary log is still payload data. Missing or failed
            // observations must be rejected by the independent driver; they
            // neither suppress the real console nor invent trusted state.
            observationPath = null;
            Console.Error.WriteLine($"{{\"fixture\":\"windows-workload-v1\",\"pid\":{Environment.ProcessId.ToString(CultureInfo.InvariantCulture)},\"event\":\"observation-log-failed\",\"hresult\":{exception.HResult.ToString(CultureInfo.InvariantCulture)}}}");
        }
    }

    private static void EmitError(string operation, Exception exception) => Emit("error", writer =>
    {
        writer.WriteString("operation", operation);
        WriteException(writer, exception);
    });

    private static void WriteException(Utf8JsonWriter writer, Exception exception)
    {
        writer.WriteString("errorType", exception.GetType().Name);
        writer.WriteNumber("hresult", exception.HResult);
        writer.WriteNumber("win32Code", exception is System.ComponentModel.Win32Exception win32 ? win32.NativeErrorCode : exception.HResult & 0xffff);
        if (exception is SocketException socket)
        {
            writer.WriteNumber("socketErrorCode", (int)socket.SocketErrorCode);
            writer.WriteNumber("nativeErrorCode", socket.NativeErrorCode);
        }
    }

    private static void WriteDigest(Utf8JsonWriter writer, string value)
    {
        var bytes = Encoding.UTF8.GetBytes(value);
        writer.WriteNumber("length", value.Length);
        writer.WriteNumber("utf8Bytes", bytes.Length);
        writer.WriteString("sha256", Convert.ToHexStringLower(SHA256.HashData(bytes)));
    }

    private static int Arguments(string[] args)
    {
        if (args.Skip(1).Any(value => value.Length > 4096))
        {
            throw new ArgumentException("A synthetic argument exceeds the fixture bound.");
        }

        Emit("argv-count", writer => writer.WriteNumber("count", args.Length - 1));
        for (var index = 1; index < args.Length; index++)
        {
            var item = index;
            Emit("argv", writer => { writer.WriteNumber("index", item - 1); WriteDigest(writer, args[item]); });
        }

        return 0;
    }

    private static int EnvironmentVariables(string[] args)
    {
        if (args.Skip(1).Any(name => !name.StartsWith("AFV2_MXC_", StringComparison.Ordinal) || name.Length > 80 || name.Any(character => !char.IsAsciiLetterOrDigit(character) && character != '_')))
        {
            throw new ArgumentException("Only explicit synthetic environment names are accepted.");
        }

        foreach (var name in args.Skip(1))
        {
            var value = Environment.GetEnvironmentVariable(name);
            if (value is { Length: > 32_768 })
            {
                throw new ArgumentException("A synthetic environment value exceeds the fixture bound.");
            }

            Emit("environment", writer =>
            {
                writer.WriteString("name", name);
                writer.WriteBoolean("present", value is not null);
                if (value is not null)
                {
                    WriteDigest(writer, value);
                }
            });
        }

        return 0;
    }

    private static int KnownFolders()
    {
        var ownedCache = Environment.GetEnvironmentVariable("XDG_CACHE_HOME");
        foreach (var name in new[] { "HOME", "TEMP", "TMP", "USERPROFILE", "APPDATA", "LOCALAPPDATA" })
        {
            var value = Environment.GetEnvironmentVariable(name);
            Emit("known-folder", writer =>
            {
                writer.WriteString("source", "environment");
                writer.WriteString("name", name);
                writer.WriteBoolean("present", value is not null);
                if (value is not null)
                {
                    WriteDigest(writer, value);
                }

                if (name is "LOCALAPPDATA" or "TEMP" or "TMP")
                {
                    WriteOwnedCache(writer, value, ownedCache);
                }
            });
        }

        foreach (var folder in new[] { Environment.SpecialFolder.UserProfile, Environment.SpecialFolder.ApplicationData, Environment.SpecialFolder.LocalApplicationData })
        {
            var value = Environment.GetFolderPath(folder, Environment.SpecialFolderOption.DoNotVerify);
            Emit("known-folder", writer =>
            {
                writer.WriteString("source", "special-folder");
                writer.WriteString("name", folder.ToString());
                writer.WriteBoolean("present", value.Length != 0);
                WriteDigest(writer, value);
            });
        }

        var temporary = Path.GetTempPath();
        Emit("known-folder", writer => { writer.WriteString("source", "path"); writer.WriteString("name", "GetTempPath"); writer.WriteBoolean("present", temporary.Length != 0); WriteDigest(writer, temporary); WriteOwnedCache(writer, temporary, ownedCache); });
        return 0;
    }

    private static void WriteOwnedCache(Utf8JsonWriter writer, string? value, string? cache)
    {
        string? relative = null;
        try
        {
            if (value is not null && cache is not null && Path.IsPathFullyQualified(value) && Path.IsPathFullyQualified(cache)
                && Path.GetPathRoot(value) is { Length: 3 } && Path.GetPathRoot(cache) is { Length: 3 })
            {
                var root = Path.TrimEndingDirectorySeparator(Path.GetFullPath(cache));
                var candidate = Path.GetFullPath(value);
                var prefix = Path.EndsInDirectorySeparator(root) ? root : root + Path.DirectorySeparatorChar;
                if (candidate.Equals(root, StringComparison.OrdinalIgnoreCase) || candidate.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
                {
                    relative = Path.GetRelativePath(root, candidate).Replace(Path.DirectorySeparatorChar, '/');
                }
            }
        }
        catch (Exception exception) when (exception is ArgumentException or IOException or NotSupportedException)
        {
            // Invalid/outside paths expose no host pathname to the observer.
        }

        writer.WriteBoolean("underOwnedCache", relative is not null);
        if (relative is null)
        {
            writer.WriteNull("ownedCacheRelativePath");
        }
        else
        {
            writer.WriteString("ownedCacheRelativePath", relative);
        }
    }

    private static int ConsoleInformation()
    {
        var input = GetStdHandle(-10);
        var output = GetStdHandle(-11);
        var inputConsole = GetConsoleMode(input, out var inputMode);
        var inputError = inputConsole ? 0 : Marshal.GetLastPInvokeError();
        var outputConsole = GetConsoleMode(output, out var outputMode);
        var outputError = outputConsole ? 0 : Marshal.GetLastPInvokeError();
        var screen = GetConsoleScreenBufferInfo(output, out var info);
        var screenError = screen ? 0 : Marshal.GetLastPInvokeError();
        Emit("console", writer =>
        {
            writer.WriteBoolean("inputConsole", inputConsole);
            writer.WriteBoolean("outputConsole", outputConsole);
            writer.WriteBoolean("screenInfo", screen);
            writer.WriteNumber("inputError", inputError);
            writer.WriteNumber("outputError", outputError);
            writer.WriteNumber("screenError", screenError);
            writer.WriteNumber("inputMode", inputMode);
            writer.WriteNumber("outputMode", outputMode);
            if (screen)
            {
                WriteSize(writer, info);
            }
        });
        return inputConsole && outputConsole && screen ? 0 : 77;
    }

    private static void WriteSize(Utf8JsonWriter writer, ScreenBufferInfo info)
    {
        writer.WriteNumber("columns", info.Window.Right - info.Window.Left + 1);
        writer.WriteNumber("rows", info.Window.Bottom - info.Window.Top + 1);
        writer.WriteNumber("bufferColumns", info.Size.X);
        writer.WriteNumber("bufferRows", info.Size.Y);
    }

    private static async Task<int> ConsoleAsync(string mode, int durationMs)
    {
        if (mode is not ("line" or "raw" or "cooperative" or "ignore-etx"))
        {
            throw new ArgumentException("Unknown console mode.");
        }

        if (ConsoleInformation() != 0)
        {
            return 77;
        }

        var input = GetStdHandle(-10);
        var output = GetStdHandle(-11);
        if (!GetConsoleMode(input, out var originalInput) || !GetConsoleMode(output, out var originalOutput))
        {
            throw new IOException("The console modes disappeared.");
        }

        var requested = (originalInput | WindowInput | ExtendedFlags) & ~QuickEdit;
        requested = mode == "line"
            ? requested | ProcessedInput | LineInput | EchoInput
            : requested & ~(ProcessedInput | LineInput | EchoInput);
        if (mode == "cooperative")
        {
            requested |= ProcessedInput;
        }

        var cancel = new TaskCompletionSource<ConsoleSpecialKey>(TaskCreationOptions.RunContinuationsAsynchronously);
        ConsoleCancelEventHandler handler = (_, args) => { args.Cancel = true; cancel.TrySetResult(args.SpecialKey); };
        var originalInputEncoding = Console.InputEncoding;
        var originalOutputEncoding = Console.OutputEncoding;
        Console.CancelKeyPress += handler;
        try
        {
            if (!SetConsoleMode(input, requested) || !SetConsoleMode(output, originalOutput | VirtualTerminalOutput))
            {
                var error = Marshal.GetLastPInvokeError();
                Emit("console-mode-failed", writer => writer.WriteNumber("win32Code", error));
                return 77;
            }

            Console.InputEncoding = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false);
            Console.OutputEncoding = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false);
            // Keep a real bounded descendant alive when Ctrl+C completes the
            // foreground root. Disposing its handle never kills it: the
            // independent owner must observe and clean the containing Job.
            using var cooperativeChild = mode == "cooperative" ? StartChild(Math.Min(60_000, durationMs + 5000)) : null;
            Console.Write("\u001b[?1049h\u001b[2J\u001b[HAFV2 Unicode: forge 星 Ω 😀\r\n\u001b[2;1HAFV2 input> ");
            Emit("console-ready", writer => { writer.WriteString("mode", mode); writer.WriteNumber("durationMs", durationMs); });
            using var deadline = new CancellationTokenSource(durationMs);
            Task<string?>? line = mode == "line" ? Task.Run(Console.ReadLine, CancellationToken.None) : null;
            ScreenBufferInfo? prior = null;
            while (!deadline.IsCancellationRequested)
            {
                if (!GetConsoleScreenBufferInfo(output, out var info))
                {
                    var error = Marshal.GetLastPInvokeError();
                    Emit("console-readback-failed", writer => writer.WriteNumber("win32Code", error));
                    return 71;
                }

                if (prior is null || prior.Value.Window.Right != info.Window.Right || prior.Value.Window.Bottom != info.Window.Bottom || prior.Value.Window.Left != info.Window.Left || prior.Value.Window.Top != info.Window.Top)
                {
                    Emit("resize", writer => WriteSize(writer, info));
                    prior = info;
                    Console.Write("\u001b[3;1HAFV2 redraw 星\u001b[K\r\n");
                }

                if (cancel.Task.IsCompletedSuccessfully)
                {
                    Emit("ctrl", writer => writer.WriteString("key", cancel.Task.Result.ToString()));
                    return 0;
                }

                if (line is { IsCompleted: true })
                {
                    var value = await line.ConfigureAwait(false);
                    Emit("line", writer =>
                    {
                        writer.WriteBoolean("eof", value is null);
                        writer.WriteNumber("length", value?.Length ?? 0);
                        if (value is not null)
                        {
                            writer.WriteString("sha256", Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(value))));
                        }
                    });
                    return 0;
                }

                if (line is null)
                {
                    if (!GetNumberOfConsoleInputEvents(input, out var count))
                    {
                        var error = Marshal.GetLastPInvokeError();
                        Emit("console-input-failed", writer => writer.WriteNumber("win32Code", error));
                        return 71;
                    }

                    for (var index = 0U; index < Math.Min(count, 64U); index++)
                    {
                        if (!ReadConsoleInput(input, out var record, 1, out var read) || read != 1)
                        {
                            var error = Marshal.GetLastPInvokeError();
                            Emit("console-input-failed", writer => writer.WriteNumber("win32Code", error));
                            return 71;
                        }

                        if (record.EventType != 1 || record.KeyDown == 0)
                        {
                            continue;
                        }

                        Emit("key", writer =>
                        {
                            writer.WriteNumber("code", record.Character);
                            writer.WriteNumber("virtualKey", record.VirtualKeyCode);
                            writer.WriteBoolean("etx", record.Character == 3);
                            writer.WriteBoolean("ignored", mode == "ignore-etx" && record.Character == 3);
                        });
                        if (record.Character is 'q' or 'Q')
                        {
                            return 0;
                        }
                    }
                }

                await Task.Delay(25, deadline.Token).ConfigureAwait(false);
            }

            Emit("deadline", writer => writer.WriteString("reason", "console-deadline"));
            return 124;
        }
        finally
        {
            Console.CancelKeyPress -= handler;
            _ = SetConsoleMode(input, originalInput);
            _ = SetConsoleMode(output, originalOutput);
            Console.Write("\u001b[?1049l");
            Console.InputEncoding = originalInputEncoding;
            Console.OutputEncoding = originalOutputEncoding;
        }
    }

    private static async Task<int> FloodAsync(int bytes)
    {
        Emit("flood-start", writer => writer.WriteNumber("bytes", bytes));
        var block = new byte[16 * 1024];
        Array.Fill(block, (byte)'x');
        block[^1] = (byte)'\n';
        await using var output = Console.OpenStandardOutput();
        for (var written = 0; written < bytes;)
        {
            var count = Math.Min(block.Length, bytes - written);
            await output.WriteAsync(block.AsMemory(0, count)).ConfigureAwait(false);
            written += count;
        }

        await output.FlushAsync().ConfigureAwait(false);
        Console.WriteLine();
        Emit("flood-finished", writer => writer.WriteNumber("bytesWritten", bytes));
        return 0;
    }

    private static int Exit(int code)
    {
        Emit("requested-exit", writer => writer.WriteNumber("code", code));
        return code;
    }

    private static int FakeErrors(int code)
    {
        Console.Error.WriteLine("{\"error\":{\"code\":\"synthetic_backend_failure\"},\"payload_started\":\"NOT_STARTED\"}");
        Console.WriteLine("{\"state\":\"EXITED\",\"exit_source\":\"payload\",\"exit_code\":0}");
        return Exit(code);
    }

    private static Process StartChild(int durationMs)
        => StartFixtureChild("load", "load-child", durationMs.ToString(CultureInfo.InvariantCulture), "8");

    private static Process StartFixtureChild(string role, params string[] args)
    {
        var executable = Environment.ProcessPath ?? throw new InvalidOperationException("The fixture executable is unavailable.");
        var start = new ProcessStartInfo(executable) { UseShellExecute = false };
        start.ArgumentList.Add("--windows-workload");
        foreach (var value in args)
        {
            start.ArgumentList.Add(value);
        }

        var process = Process.Start(start) ?? throw new IOException("The child was not created.");
        _ = RecordChild(process, role);
        return process;
    }

    private static string RecordChild(Process process, string role)
    {
        var created = process.StartTime.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture);
        Emit("child-created", writer => { writer.WriteString("role", role); writer.WriteNumber("childPid", process.Id); writer.WriteString("childCreatedUtc", created); });
        return created;
    }

    private static async Task<int> ShortBurstAsync(int count)
    {
        using var deadline = new CancellationTokenSource(10_000);
        var exitedCount = 0;
        for (var index = 0; index < count; index++)
        {
            using var child = StartFixtureChild("short-burst", "exit", "0");
            var created = child.StartTime.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture);
            await child.WaitForExitAsync(deadline.Token).ConfigureAwait(false);
            var item = index;
            Emit("short-child-exited", writer => { writer.WriteNumber("index", item); writer.WriteNumber("childPid", child.Id); writer.WriteString("childCreatedUtc", created); writer.WriteNumber("exitCode", child.ExitCode); });
            if (child.ExitCode != 0)
            {
                return 73;
            }

            exitedCount++;
        }

        Emit("short-burst-ready", writer => { writer.WriteNumber("count", count); writer.WriteNumber("exitedCount", exitedCount); });
        await Task.Delay(1000, deadline.Token).ConfigureAwait(false);
        Emit("short-burst-finished", writer => { writer.WriteNumber("count", count); writer.WriteNumber("exitedCount", exitedCount); });
        return 0;
    }

    private static async Task<int> PipeRoundtripAsync(string name)
    {
        ValidatePipeName(name);
        using var deadline = new CancellationTokenSource(4000);
        await using var server = new NamedPipeServerStream(name, PipeDirection.InOut, 1, PipeTransmissionMode.Byte, PipeOptions.Asynchronous, 4096, 4096);
        using var child = StartFixtureChild("pipe-client", "pipe", "client", name, "4000");
        var created = child.StartTime.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture);
        await server.WaitForConnectionAsync(deadline.Token).ConfigureAwait(false);
        var matched = await ExchangeAsync(server, writeFirst: false, deadline.Token).ConfigureAwait(false);
        await child.WaitForExitAsync(deadline.Token).ConfigureAwait(false);
        Emit("pipe-roundtrip", writer => { writer.WriteBoolean("matched", matched); writer.WriteNumber("clientExit", child.ExitCode); writer.WriteNumber("childPid", child.Id); writer.WriteString("childCreatedUtc", created); });
        return matched && child.ExitCode == 0 ? 0 : 73;
    }

    private static async Task<int> BuildTestAsync(string compiler, string linker, string kernelLibrary, string work)
    {
        foreach (var path in new[] { compiler, linker, kernelLibrary, work })
        {
            if (!Path.IsPathFullyQualified(path) || Path.GetPathRoot(path) is not { Length: 3 })
            {
                throw new ArgumentException("Only explicit local build fixture paths are accepted.");
            }
        }

        if (!Directory.Exists(work))
        {
            throw new DirectoryNotFoundException("The explicitly owned build directory is unavailable.");
        }

        var source = Path.Combine(work, "afv2-fixture.c");
        var obj = Path.Combine(work, "afv2-fixture.obj");
        var executable = Path.Combine(work, "afv2-fixture.exe");
        if (File.Exists(obj) || File.Exists(executable))
        {
            throw new IOException("The explicitly owned build outputs already exist.");
        }

        using (var file = new FileStream(source, FileMode.CreateNew, FileAccess.Write, FileShare.Read))
        using (var writer = new StreamWriter(file, new UTF8Encoding(encoderShouldEmitUTF8Identifier: false)))
        {
            writer.Write("__declspec(dllimport) void __stdcall ExitProcess(unsigned int); void main(void){ExitProcess(23);}\n");
        }

        using var deadline = new CancellationTokenSource(30_000);
        int? compileExit = null;
        int? linkExit = null;
        int? testExit = null;
        var success = false;
        try
        {
            compileExit = await RunBuildChildAsync("compile", compiler, ["/nologo", "/c", "/Zl", "/GS-", $"/Fo{obj}", source], compiler, linker, work, deadline.Token).ConfigureAwait(false);
            if (compileExit != 0)
            {
                return 73;
            }

            linkExit = await RunBuildChildAsync("link", linker, ["/NOLOGO", "/ENTRY:main", "/NODEFAULTLIB", "/SUBSYSTEM:CONSOLE", $"/OUT:{executable}", obj, kernelLibrary], compiler, linker, work, deadline.Token).ConfigureAwait(false);
            if (linkExit != 0)
            {
                return 73;
            }

            testExit = await RunBuildChildAsync("test", executable, [], compiler, linker, work, deadline.Token).ConfigureAwait(false);
            success = testExit == 23;
            return success ? 0 : 73;
        }
        finally
        {
            Emit("build-test", writer =>
            {
                WriteExit(writer, "compileExit", compileExit);
                WriteExit(writer, "linkExit", linkExit);
                WriteExit(writer, "testExit", testExit);
                writer.WriteBoolean("success", success);
            });
        }
    }

    private static void WriteExit(Utf8JsonWriter writer, string name, int? value)
    {
        if (value is { } exit)
        {
            writer.WriteNumber(name, exit);
        }
        else
        {
            writer.WriteNull(name);
        }
    }

    private static async Task<int> RunBuildChildAsync(string role, string executable, string[] args, string compiler, string linker, string work, CancellationToken cancellationToken)
    {
        var windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows, Environment.SpecialFolderOption.DoNotVerify);
        if (windows.Length == 0)
        {
            throw new DirectoryNotFoundException("The Windows system folder is unavailable.");
        }

        var start = new ProcessStartInfo(executable) { UseShellExecute = false, WorkingDirectory = work };
        start.Environment.Clear();
        start.Environment["SystemRoot"] = windows;
        start.Environment["TEMP"] = work;
        start.Environment["TMP"] = work;
        start.Environment["PATH"] = string.Join(Path.PathSeparator, Path.GetDirectoryName(compiler), Path.GetDirectoryName(linker), Path.Combine(windows, "System32"));
        foreach (var value in args)
        {
            start.ArgumentList.Add(value);
        }

        using var child = Process.Start(start) ?? throw new IOException("The build fixture process was not created.");
        var created = RecordChild(child, role);
        await child.WaitForExitAsync(cancellationToken).ConfigureAwait(false);
        Emit("build-child", writer => { writer.WriteString("role", role); writer.WriteNumber("childPid", child.Id); writer.WriteString("createdUtc", created); writer.WriteNumber("exitCode", child.ExitCode); });
        return child.ExitCode;
    }

    private static int RootExitChild(int durationMs, int rootDelayMs)
    {
        using var child = StartChild(durationMs);
        var created = child.StartTime.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture);
        Emit("root-exit-with-child", writer => { writer.WriteNumber("childPid", child.Id); writer.WriteString("childCreatedUtc", created); });
        if (rootDelayMs != 0)
        {
            Thread.Sleep(rootDelayMs);
        }

        // Intentionally no Kill/Wait: the external owner must prove MXC/Job
        // cleanup of a still-bounded descendant after this root exits.
        return 0;
    }

    private static int Persistence(string operation, string path)
    {
        if (operation is not ("write" or "read") || !Path.IsPathFullyQualified(path) || Path.GetPathRoot(path) is not { Length: 3 })
        {
            throw new ArgumentException("An explicit local persistence fixture file is required.");
        }

        try
        {
            if (operation == "write")
            {
                using var file = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.Read);
                file.Write(PersistenceSentinel);
                file.Flush(flushToDisk: true);
            }
            else
            {
                using var file = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
                Span<byte> buffer = stackalloc byte[PersistenceSentinel.Length + 1];
                var count = 0;
                while (count < buffer.Length)
                {
                    var read = file.Read(buffer[count..]);
                    if (read == 0)
                    {
                        break;
                    }

                    count += read;
                }

                if (!buffer[..count].SequenceEqual(PersistenceSentinel))
                {
                    Emit("persistence", writer => { writer.WriteString("operation", operation); writer.WriteBoolean("succeeded", false); writer.WriteString("reason", "sentinel-mismatch"); });
                    return 73;
                }
            }

            Emit("persistence", writer => { writer.WriteString("operation", operation); writer.WriteBoolean("succeeded", true); });
            return 0;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or System.Security.SecurityException)
        {
            Emit("persistence", writer => { writer.WriteString("operation", operation); writer.WriteBoolean("succeeded", false); WriteException(writer, exception); });
            return 73;
        }
    }

    private static int Load(int durationMs, int memoryMiB, int childCount, Action? ready = null, CancellationToken cancellationToken = default)
    {
        var watch = Stopwatch.StartNew();
        var children = new List<Process>();
        try
        {
            // Burst before readiness so an external observer can detect late
            // resource attachment. Descendants never recursively spawn.
            for (var index = 0; index < childCount; index++)
            {
                if (cancellationToken.IsCancellationRequested)
                {
                    break;
                }

                children.Add(StartChild(Math.Min(60_000, durationMs + 5000)));
            }

            var memory = GC.AllocateUninitializedArray<byte>(checked(memoryMiB * 1024 * 1024));
            for (var offset = 0; offset < memory.Length; offset += 4096)
            {
                memory[offset] = 0x5a;
            }

            Emit("load-ready", writer => { writer.WriteNumber("memoryBytesTouched", memory.Length); writer.WriteNumber("childrenCreated", children.Count); writer.WriteNumber("durationMs", durationMs); });
            ready?.Invoke();
            var checksum = 1UL;
            while (watch.ElapsedMilliseconds < durationMs && !cancellationToken.IsCancellationRequested)
            {
                for (var index = 0; index < 10_000; index++)
                {
                    checksum = unchecked(checksum * 6364136223846793005UL + 1);
                }

                Thread.SpinWait(64);
            }

            GC.KeepAlive(memory);
            Emit("load-finished", writer => { writer.WriteNumber("checksum", checksum); writer.WriteBoolean("canceled", cancellationToken.IsCancellationRequested); });
            return 0;
        }
        finally
        {
            foreach (var child in children)
            {
                child.Dispose();
            }
        }
    }

    private static async Task<int> CombinedAsync(string[] args, int durationMs, int memoryMiB, int children, int port)
    {
        // Validate every file before starting any workload. No discovery or
        // arbitrary host path is added to this explicit synthetic fixture.
        foreach (var path in args.Skip(6))
        {
            if (!Path.IsPathFullyQualified(path) || Path.GetPathRoot(path) is not { Length: 3 })
            {
                throw new ArgumentException("Only explicit local absolute fixture files are accepted.");
            }
        }

        if (!IPAddress.TryParse(args[4], out var ip) || ip.Equals(IPAddress.Any) || ip.Equals(IPAddress.IPv6Any))
        {
            throw new ArgumentException("An explicit controlled fixture IP is required.");
        }

        using var stop = new CancellationTokenSource(durationMs);
        // ConsoleAsync reaches its first bounded delay after reporting real
        // console readiness. All remaining work runs while it can process
        // resize and input; none of these observations declares a policy pass.
        var console = ConsoleAsync("raw", durationMs);
        if (console.IsCompleted)
        {
            return await console.ConfigureAwait(false);
        }

        var load = Task.CompletedTask;
        var network = Task.CompletedTask;
        try
        {
            Emit("combined-idle-ready", writer => writer.WriteNumber("durationMs", 3000));
            var idle = Task.Delay(3000, stop.Token);
            if (await Task.WhenAny(console, idle).ConfigureAwait(false) == console)
            {
                return await console.ConfigureAwait(false);
            }

            await idle.ConfigureAwait(false);
            Emit("combined-work-starting", _ => { });
            var pressureReady = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            load = Task.Run(() =>
            {
                try
                {
                    _ = Load(durationMs, memoryMiB, children, () => pressureReady.TrySetResult(), stop.Token);
                }
                catch (Exception exception)
                {
                    EmitObservationFailure("load-observation-failed", exception, stop.IsCancellationRequested);
                    pressureReady.TrySetException(exception);
                }
            }, CancellationToken.None);
            var readiness = pressureReady.Task.WaitAsync(stop.Token);
            if (await Task.WhenAny(console, readiness).ConfigureAwait(false) == console)
            {
                return await console.ConfigureAwait(false);
            }

            await readiness.ConfigureAwait(false);
            Emit("combined-pressure-ready", _ => { });
            network = ObserveCombinedNetworkAsync(args[4], port, durationMs, stop.Token);
            _ = Filesystem(["filesystem", .. args.Skip(6)]);
            Emit("combined-ready", writer => { writer.WriteNumber("durationMs", durationMs); writer.WriteNumber("memoryMiB", memoryMiB); writer.WriteNumber("children", children); });
            var result = await console.ConfigureAwait(false);
            Emit("combined-finished", writer => writer.WriteNumber("consoleExit", result));
            return result;
        }
        finally
        {
            await stop.CancelAsync().ConfigureAwait(false);
            await Task.WhenAll(load, network).ConfigureAwait(false);
            // Child handles are disposed by Load, never killed here. The
            // external run owner must prove containment and subtree cleanup.
        }
    }

    private static async Task ObserveCombinedNetworkAsync(string address, int port, int durationMs, CancellationToken cancellationToken)
    {
        try
        {
            _ = await NetworkAsync("tcp-connect", address, port, Math.Min(durationMs, 4000), cancellationToken).ConfigureAwait(false);
        }
        catch (Exception exception)
        {
            EmitObservationFailure("network-observation-failed", exception, cancellationToken.IsCancellationRequested);
        }
    }

    private static void EmitObservationFailure(string name, Exception exception, bool canceled) => Emit(name, writer =>
    {
        WriteException(writer, exception);
        writer.WriteBoolean("canceled", canceled);
    });

    private static async Task<int> CommitAsync(int maxMiB, int holdMs)
    {
        const int blockBytes = 4 * 1024 * 1024;
        var maxBytes = checked(maxMiB * 1024 * 1024);
        var pages = new List<(nint Address, int Bytes)>(64);
        var committedBytes = 0;
        var failedCode = 0;
        try
        {
            while (committedBytes < maxBytes)
            {
                var bytes = Math.Min(blockBytes, maxBytes - committedBytes);
                var page = VirtualAlloc(0, (nuint)bytes, 0x1000 | 0x2000, 0x04);
                if (page == 0)
                {
                    failedCode = Marshal.GetLastPInvokeError();
                    Emit("commit-failed", writer => { writer.WriteNumber("committedBytes", committedBytes); writer.WriteNumber("failedCode", failedCode); writer.WriteNumber("maxBytes", maxBytes); });
                    break;
                }

                pages.Add((page, bytes));
                for (var offset = 0; offset < bytes; offset += 4096)
                {
                    Marshal.WriteByte(page, offset, 0x5a);
                }

                committedBytes += bytes;
            }

            Emit("commit-ready", writer => { writer.WriteNumber("committedBytes", committedBytes); writer.WriteNumber("failedCode", failedCode); writer.WriteNumber("maxBytes", maxBytes); writer.WriteNumber("holdMs", holdMs); });
            // Keep every successful native allocation resident while the
            // independent owner samples the Job's actual memory accounting.
            await Task.Delay(holdMs).ConfigureAwait(false);
            return failedCode == 0 ? 0 : 72;
        }
        finally
        {
            var releasedBytes = 0;
            var releaseFailedCode = 0;
            foreach (var page in pages)
            {
                if (VirtualFree(page.Address, 0, 0x8000))
                {
                    releasedBytes += page.Bytes;
                }
                else
                {
                    var error = Marshal.GetLastPInvokeError();
                    if (releaseFailedCode == 0)
                    {
                        releaseFailedCode = error;
                    }
                }
            }

            Emit("commit-final", writer => { writer.WriteNumber("committedBytes", committedBytes); writer.WriteNumber("failedCode", failedCode); writer.WriteNumber("releasedBytes", releasedBytes); writer.WriteNumber("releaseFailedCode", releaseFailedCode); });
        }
    }

    private static int Filesystem(string[] args)
    {
        var roles = new[] { "writable", "readonly", "control-denied", "neighbor", "outside" };
        for (var index = 0; index < roles.Length; index++)
        {
            var path = args[index + 1];
            if (!Path.IsPathFullyQualified(path) || Path.GetPathRoot(path) is not { Length: 3 })
            {
                throw new ArgumentException("Only explicit local absolute fixture files are accepted.");
            }

            if (index == 0)
            {
                FileAttempt(roles[index], path, write: true, create: true);
                FileAttempt(roles[index], path, write: false, create: false);
            }
            else
            {
                FileAttempt(roles[index], path, write: false, create: false);
                FileAttempt(roles[index], path, write: true, create: false);
            }
        }

        return 0;
    }

    private static void FileAttempt(string role, string path, bool write, bool create)
    {
        try
        {
            using var file = new FileStream(path, create ? FileMode.OpenOrCreate : FileMode.Open, write ? FileAccess.Write : FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            var count = 0;
            var sentinel = false;
            if (write)
            {
                file.Seek(0, SeekOrigin.End);
                file.Write(FileSentinel);
                file.Flush(flushToDisk: true);
                count = FileSentinel.Length;
            }
            else
            {
                Span<byte> buffer = stackalloc byte[4096];
                count = file.Read(buffer);
                sentinel = buffer[..count].StartsWith(FileSentinel);
            }

            Emit("filesystem", writer => { writer.WriteString("role", role); writer.WriteString("operation", write ? "write" : "read"); writer.WriteBoolean("succeeded", true); writer.WriteNumber("bytes", count); writer.WriteBoolean("syntheticSentinel", sentinel); });
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or System.Security.SecurityException)
        {
            Emit("filesystem", writer => { writer.WriteString("role", role); writer.WriteString("operation", write ? "write" : "read"); writer.WriteBoolean("succeeded", false); writer.WriteString("errorType", exception.GetType().Name); writer.WriteNumber("hresult", exception.HResult); writer.WriteNumber("win32Code", exception.HResult & 0xffff); });
        }
    }

    private static async Task<int> PipeAsync(string role, string name, int durationMs)
    {
        ValidatePipeName(name);

        using var deadline = new CancellationTokenSource(durationMs);
        if (role == "server")
        {
            await using var server = new NamedPipeServerStream(name, PipeDirection.InOut, 1, PipeTransmissionMode.Byte, PipeOptions.Asynchronous, 4096, 4096);
            Emit("ipc-ready", writer => writer.WriteString("role", role));
            await server.WaitForConnectionAsync(deadline.Token).ConfigureAwait(false);
            var matched = await ExchangeAsync(server, writeFirst: false, deadline.Token).ConfigureAwait(false);
            Emit("ipc", writer => { writer.WriteString("role", role); writer.WriteBoolean("replyMatch", matched); });
            return matched ? 0 : 73;
        }

        if (role == "client")
        {
            await using var client = new NamedPipeClientStream(".", name, PipeDirection.InOut, PipeOptions.Asynchronous);
            await client.ConnectAsync(deadline.Token).ConfigureAwait(false);
            var matched = await ExchangeAsync(client, writeFirst: true, deadline.Token).ConfigureAwait(false);
            Emit("ipc", writer => { writer.WriteString("role", role); writer.WriteBoolean("replyMatch", matched); });
            return matched ? 0 : 73;
        }

        throw new ArgumentException("Unknown pipe role.");
    }

    private static void ValidatePipeName(string name)
    {
        if (!name.StartsWith("afv2-mxc-", StringComparison.Ordinal) || name.Length > 100 || name.Any(character => !char.IsAsciiLetterOrDigit(character) && character is not ('-' or '_' or '.')))
        {
            throw new ArgumentException("A synthetic local pipe name is required.");
        }
    }

    private static async Task<bool> ExchangeAsync(Stream stream, bool writeFirst, CancellationToken cancellationToken)
    {
        if (writeFirst)
        {
            await stream.WriteAsync(NetworkSentinel, cancellationToken).ConfigureAwait(false);
            await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
        }

        var buffer = new byte[NetworkSentinel.Length];
        var received = 0;
        while (received < buffer.Length)
        {
            var count = await stream.ReadAsync(buffer.AsMemory(received), cancellationToken).ConfigureAwait(false);
            if (count == 0)
            {
                return false;
            }

            received += count;
        }

        var matched = buffer.AsSpan().SequenceEqual(NetworkSentinel);
        if (!writeFirst)
        {
            await stream.WriteAsync(NetworkSentinel, cancellationToken).ConfigureAwait(false);
            await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
        }

        return matched;
    }

    private static async Task<int> NetworkAsync(string mode, string address, int port, int durationMs, CancellationToken cancellationToken = default)
    {
        if (!IPAddress.TryParse(address, out var ip) || ip.Equals(IPAddress.Any) || ip.Equals(IPAddress.IPv6Any))
        {
            throw new ArgumentException("An explicit controlled fixture IP is required.");
        }

        if (mode is not ("tcp-connect" or "tcp-listen" or "udp-send" or "udp-listen"))
        {
            throw new ArgumentException("Unknown network mode.");
        }

        Emit("network-attempt", writer => { writer.WriteString("mode", mode); writer.WriteNumber("port", port); writer.WriteString("addressSha256", Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(address)))); });
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(durationMs);
        if (mode == "tcp-connect")
        {
            using var client = new TcpClient(ip.AddressFamily);
            await client.ConnectAsync(ip, port, deadline.Token).ConfigureAwait(false);
            var matched = await ExchangeAsync(client.GetStream(), writeFirst: true, deadline.Token).ConfigureAwait(false);
            Emit("network", writer => { writer.WriteString("mode", mode); writer.WriteBoolean("replyMatch", matched); });
            return matched ? 0 : 73;
        }

        if (mode == "tcp-listen")
        {
            using var server = new TcpListener(ip, port);
            server.Start(1);
            Emit("network-ready", writer => { writer.WriteString("mode", mode); writer.WriteNumber("port", ((IPEndPoint)server.LocalEndpoint).Port); });
            using var client = await server.AcceptTcpClientAsync(deadline.Token).ConfigureAwait(false);
            Emit("network-received", writer => { writer.WriteString("mode", mode); writer.WriteBoolean("accepted", true); });
            var matched = await ExchangeAsync(client.GetStream(), writeFirst: false, deadline.Token).ConfigureAwait(false);
            Emit("network", writer => { writer.WriteString("mode", mode); writer.WriteBoolean("replyMatch", matched); });
            return matched ? 0 : 73;
        }

        if (mode is "udp-send" or "udp-listen")
        {
            using var socket = mode == "udp-listen" ? new UdpClient(new IPEndPoint(ip, port)) : new UdpClient(ip.AddressFamily);
            if (mode == "udp-send")
            {
                socket.Connect(ip, port);
                var count = await socket.SendAsync(NetworkSentinel, deadline.Token).ConfigureAwait(false);
                Emit("network-sent", writer => { writer.WriteString("mode", mode); writer.WriteNumber("bytes", count); });
            }
            else
            {
                Emit("network-ready", writer => { writer.WriteString("mode", mode); writer.WriteNumber("port", port); });
            }

            var received = await socket.ReceiveAsync(deadline.Token).ConfigureAwait(false);
            var matched = received.Buffer.AsSpan().SequenceEqual(NetworkSentinel);
            if (mode == "udp-listen")
            {
                Emit("network-received", writer => { writer.WriteString("mode", mode); writer.WriteBoolean("replyMatch", matched); writer.WriteNumber("receivedBytes", received.Buffer.Length); });
                await socket.SendAsync(NetworkSentinel, received.RemoteEndPoint, deadline.Token).ConfigureAwait(false);
            }

            Emit("network", writer => { writer.WriteString("mode", mode); writer.WriteBoolean("replyMatch", matched); writer.WriteNumber("receivedBytes", received.Buffer.Length); });
            return matched ? 0 : 73;
        }

        throw new ArgumentException("Unknown network mode.");
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct Coordinate { internal short X, Y; }
    [StructLayout(LayoutKind.Sequential)]
    private struct Rectangle { internal short Left, Top, Right, Bottom; }
    [StructLayout(LayoutKind.Sequential)]
    private struct ScreenBufferInfo { internal Coordinate Size, Cursor; internal ushort Attributes; internal Rectangle Window; internal Coordinate Maximum; }
    [StructLayout(LayoutKind.Explicit, Size = 20)]
    private struct InputRecord
    {
        [FieldOffset(0)] internal ushort EventType;
        [FieldOffset(4)] internal int KeyDown;
        [FieldOffset(8)] internal ushort RepeatCount;
        [FieldOffset(10)] internal ushort VirtualKeyCode;
        [FieldOffset(12)] internal ushort ScanCode;
        [FieldOffset(14)] internal ushort Character;
        [FieldOffset(16)] internal uint ControlKeyState;
    }

    [LibraryImport("kernel32.dll", SetLastError = true)] private static partial nint GetStdHandle(int identifier);
    [LibraryImport("kernel32.dll", SetLastError = true)] private static partial nint VirtualAlloc(nint address, nuint size, uint allocationType, uint protection);
    [LibraryImport("kernel32.dll", SetLastError = true)][return: MarshalAs(UnmanagedType.Bool)] private static partial bool VirtualFree(nint address, nuint size, uint freeType);
    [LibraryImport("kernel32.dll", SetLastError = true)][return: MarshalAs(UnmanagedType.Bool)] private static partial bool GetConsoleMode(nint handle, out uint mode);
    [LibraryImport("kernel32.dll", SetLastError = true)][return: MarshalAs(UnmanagedType.Bool)] private static partial bool SetConsoleMode(nint handle, uint mode);
    [LibraryImport("kernel32.dll", SetLastError = true)][return: MarshalAs(UnmanagedType.Bool)] private static partial bool GetConsoleScreenBufferInfo(nint handle, out ScreenBufferInfo info);
    [LibraryImport("kernel32.dll", SetLastError = true)][return: MarshalAs(UnmanagedType.Bool)] private static partial bool GetNumberOfConsoleInputEvents(nint handle, out uint count);
    [LibraryImport("kernel32.dll", EntryPoint = "ReadConsoleInputW", SetLastError = true)][return: MarshalAs(UnmanagedType.Bool)] private static partial bool ReadConsoleInput(nint handle, out InputRecord record, uint length, out uint read);
}
