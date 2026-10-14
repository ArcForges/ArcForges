// SPDX-License-Identifier: AGPL-3.0-only
using System.Globalization;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace ArcForges.Tools.Tests;

/// <summary>
/// Live descendants of one process, from the OS parent links (Linux <c>/proc/&lt;pid&gt;/stat</c>,
/// Windows Toolhelp snapshots). Processes other tests start are never counted.
/// </summary>
internal static partial class ProcessTree
{
    public static IReadOnlyList<int> Descendants(int root)
    {
        var parents = OperatingSystem.IsWindows() ? WindowsParents() : LinuxParents();
        var children = parents.GroupBy(pair => pair.Value).ToDictionary(group => group.Key, group => group.Select(pair => pair.Key).ToList());
        var result = new List<int>();
        var queue = new Queue<int>([root]);
        while (queue.Count > 0)
        {
            foreach (var child in children.GetValueOrDefault(queue.Dequeue(), []))
            {
                if (child != root && !result.Contains(child))
                {
                    result.Add(child);
                    queue.Enqueue(child);
                }
            }
        }

        return result;
    }

    private static Dictionary<int, int> LinuxParents()
    {
        var parents = new Dictionary<int, int>();
        foreach (var directory in Directory.EnumerateDirectories("/proc"))
        {
            if (!int.TryParse(Path.GetFileName(directory), NumberStyles.None, CultureInfo.InvariantCulture, out var pid))
            {
                continue;
            }

            try
            {
                // Fields after the parenthesised command name: state, ppid, ...
                var stat = File.ReadAllText(Path.Combine(directory, "stat"));
                var fields = stat[(stat.LastIndexOf(')') + 2)..].Split(' ');
                parents[pid] = int.Parse(fields[1], CultureInfo.InvariantCulture);
            }
            catch (IOException)
            {
                // The process exited while the table was read.
            }
        }

        return parents;
    }

    private static Dictionary<int, int> WindowsParents()
    {
        const uint SnapshotProcesses = 0x2;
        var parents = new Dictionary<int, int>();
        var snapshot = CreateToolhelp32Snapshot(SnapshotProcesses, 0);
        if (snapshot == -1)
        {
            throw new InvalidOperationException($"CreateToolhelp32Snapshot failed: {Marshal.GetLastPInvokeError()}");
        }

        try
        {
            var entry = new ProcessEntry { Size = (uint)Marshal.SizeOf<ProcessEntry>() };
            for (var more = Process32FirstW(snapshot, ref entry); more; more = Process32NextW(snapshot, ref entry))
            {
                parents[(int)entry.ProcessId] = (int)entry.ParentProcessId;
            }
        }
        finally
        {
            CloseHandle(snapshot);
        }

        return parents;
    }

    [LibraryImport("kernel32.dll", SetLastError = true)]
    private static partial nint CreateToolhelp32Snapshot(uint flags, uint processId);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool Process32FirstW(nint snapshot, ref ProcessEntry entry);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool Process32NextW(nint snapshot, ref ProcessEntry entry);

    [LibraryImport("kernel32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool CloseHandle(nint handle);

    /// <summary>PROCESSENTRY32W.</summary>
    [StructLayout(LayoutKind.Sequential)]
    private struct ProcessEntry
    {
        public uint Size;
        public uint Usage;
        public uint ProcessId;
        public nint DefaultHeapId;
        public uint ModuleId;
        public uint Threads;
        public uint ParentProcessId;
        public int PriorityClassBase;
        public uint Flags;
        public ExeFileName ExeFile;
    }

    [InlineArray(260)]
    private struct ExeFileName
    {
        private ushort _first;
    }
}
