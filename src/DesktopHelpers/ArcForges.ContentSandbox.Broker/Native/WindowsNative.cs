// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics.CodeAnalysis;
using System.Runtime.InteropServices;

namespace ArcForges.ContentSandbox.Broker.Native;

/// <summary>
/// The exact Windows calls the restricted launch profile needs and that the managed libraries do not expose: AppContainer
/// identity, handle-list process creation, a Job Object and token inspection. Every declaration is internal, unique in the
/// repository and covered by the closed native-binding owner test; nothing here is a public boundary.
/// </summary>
[SuppressMessage("Interoperability", "CA1401", Justification = "Declarations are internal to the launch profile.")]
[SuppressMessage("Design", "CA1060", Justification = "One owner type holds the exact closed set of bindings of the Windows profile.")]
internal static unsafe partial class WindowsNative
{
    internal const uint ExtendedStartupInfoPresent = 0x00080000;
    internal const uint CreateSuspended = 0x00000004;
    internal const uint CreateUnicodeEnvironment = 0x00000400;
    internal const uint CreateNoWindow = 0x08000000;
    internal const uint StartfUseStdHandles = 0x00000100;
    internal const uint GenericReadWrite = 0xC0000000;
    internal const uint OpenExisting = 3;
    internal const uint FileFlagOverlapped = 0x40000000;
    internal const uint SecuritySqosPresent = 0x00100000;
    internal const uint HandleFlagInherit = 0x00000001;
    internal const uint DuplicateSameAccess = 0x00000002;
    internal const uint SectionMapRead = 0x0004;
    internal const uint ProcessQueryLimitedInformation = 0x1000;

    internal const uint AttributeHandleList = 0x00020002;
    internal const uint AttributeMitigationPolicy = 0x00020007;
    internal const uint AttributeSecurityCapabilities = 0x00020009;

    internal const int JobObjectBasicUiRestrictions = 4;
    internal const int JobObjectExtendedLimitInformation = 9;
    internal const uint JobLimitProcessMemory = 0x00000100;
    internal const uint JobLimitJobMemory = 0x00000200;
    internal const uint JobLimitActiveProcess = 0x00000008;
    internal const uint JobLimitDieOnUnhandledException = 0x00000400;
    internal const uint JobLimitKillOnJobClose = 0x00002000;
    internal const uint JobUiLimitAll = 0x000000FF;

    internal const uint TokenQueryAccess = 0x0008;
    internal const int TokenIsAppContainer = 29;
    internal const int TokenCapabilities = 30;
    internal const int TokenIntegrityLevel = 25;
    internal const int TokenAppContainerSid = 31;

    internal const int ErrorAlreadyExists = unchecked((int)0x800700B7);

    [StructLayout(LayoutKind.Sequential)]
    internal struct SecurityAttributes
    {
        public uint Length;
        public nint SecurityDescriptor;
        public int InheritHandle;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct SecurityCapabilities
    {
        public nint AppContainerSid;
        public nint Capabilities;
        public uint CapabilityCount;
        public uint Reserved;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct StartupInfoW
    {
        public uint Cb;
        public nint Reserved;
        public nint Desktop;
        public nint Title;
        public uint X;
        public uint Y;
        public uint XSize;
        public uint YSize;
        public uint XCountChars;
        public uint YCountChars;
        public uint FillAttribute;
        public uint Flags;
        public ushort ShowWindow;
        public ushort CbReserved2;
        public nint Reserved2;
        public nint StdInput;
        public nint StdOutput;
        public nint StdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct StartupInfoExW
    {
        public StartupInfoW StartupInfo;
        public nint AttributeList;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct ProcessInformation
    {
        public nint Process;
        public nint Thread;
        public uint ProcessId;
        public uint ThreadId;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct JobBasicLimitInformation
    {
        public long PerProcessUserTimeLimit;
        public long PerJobUserTimeLimit;
        public uint LimitFlags;
        public nuint MinimumWorkingSetSize;
        public nuint MaximumWorkingSetSize;
        public uint ActiveProcessLimit;
        public nuint Affinity;
        public uint PriorityClass;
        public uint SchedulingClass;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct IoCounters
    {
        public ulong ReadOperationCount;
        public ulong WriteOperationCount;
        public ulong OtherOperationCount;
        public ulong ReadTransferCount;
        public ulong WriteTransferCount;
        public ulong OtherTransferCount;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct JobExtendedLimitInformation
    {
        public JobBasicLimitInformation BasicLimitInformation;
        public IoCounters IoInfo;
        public nuint ProcessMemoryLimit;
        public nuint JobMemoryLimit;
        public nuint PeakProcessMemoryUsed;
        public nuint PeakJobMemoryUsed;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct JobBasicUiRestrictions
    {
        public uint UiRestrictionsClass;
    }

    [LibraryImport("Kernel32.dll", EntryPoint = "CreateFileW", StringMarshalling = StringMarshalling.Utf16, SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    internal static partial nint CreateFileW(string fileName, uint desiredAccess, uint shareMode, ref SecurityAttributes securityAttributes, uint creationDisposition, uint flagsAndAttributes, nint templateFile);

    [LibraryImport("Kernel32.dll", EntryPoint = "InitializeProcThreadAttributeList", SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool InitializeProcThreadAttributeList(nint attributeList, uint attributeCount, uint flags, ref nuint size);

    [LibraryImport("Kernel32.dll", EntryPoint = "UpdateProcThreadAttribute", SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool UpdateProcThreadAttribute(nint attributeList, uint flags, nuint attribute, nint value, nuint size, nint previousValue, nint returnSize);

    [LibraryImport("Kernel32.dll", EntryPoint = "DeleteProcThreadAttributeList")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    internal static partial void DeleteProcThreadAttributeList(nint attributeList);

    [LibraryImport("Kernel32.dll", EntryPoint = "CreateProcessW", StringMarshalling = StringMarshalling.Utf16, SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool CreateProcessW(
        string? applicationName,
        char* commandLine,
        nint processAttributes,
        nint threadAttributes,
        [MarshalAs(UnmanagedType.Bool)] bool inheritHandles,
        uint creationFlags,
        nint environment,
        string? currentDirectory,
        ref StartupInfoExW startupInfo,
        out ProcessInformation processInformation);

    [LibraryImport("Kernel32.dll", EntryPoint = "ResumeThread", SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    internal static partial uint ResumeThread(nint thread);

    [LibraryImport("Kernel32.dll", EntryPoint = "TerminateProcess", SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool TerminateProcess(nint process, uint exitCode);

    [LibraryImport("Kernel32.dll", EntryPoint = "CloseHandle")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool CloseHandle(nint handle);

    [LibraryImport("Kernel32.dll", EntryPoint = "DuplicateHandle", SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool DuplicateHandle(
        nint sourceProcess,
        nint sourceHandle,
        nint targetProcess,
        out nint targetHandle,
        uint desiredAccess,
        [MarshalAs(UnmanagedType.Bool)] bool inheritHandle,
        uint options);

    [LibraryImport("Kernel32.dll", EntryPoint = "SetHandleInformation", SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool SetHandleInformation(nint handle, uint mask, uint flags);

    [LibraryImport("Kernel32.dll", EntryPoint = "CreateJobObjectW", SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    internal static partial nint CreateJobObjectW(nint attributes, nint name);

    [LibraryImport("Kernel32.dll", EntryPoint = "SetInformationJobObject", SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool SetInformationJobObject(nint job, int informationClass, nint information, uint informationLength);

    [LibraryImport("Kernel32.dll", EntryPoint = "AssignProcessToJobObject", SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool AssignProcessToJobObject(nint job, nint process);

    [LibraryImport("Kernel32.dll", EntryPoint = "TerminateJobObject", SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool TerminateJobObject(nint job, uint exitCode);

    [LibraryImport("Kernel32.dll", EntryPoint = "IsProcessInJob", SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool IsProcessInJob(nint process, nint job, [MarshalAs(UnmanagedType.Bool)] out bool result);

    [LibraryImport("Advapi32.dll", EntryPoint = "OpenProcessToken", SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool OpenProcessToken(nint process, uint desiredAccess, out nint token);

    [LibraryImport("Advapi32.dll", EntryPoint = "GetTokenInformation", SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool GetTokenInformation(nint token, int informationClass, nint information, uint informationLength, out uint returnLength);

    [LibraryImport("Advapi32.dll", EntryPoint = "FreeSid")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    internal static partial nint FreeSid(nint sid);

    [LibraryImport("Advapi32.dll", EntryPoint = "EqualSid")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool EqualSid(nint left, nint right);

    [LibraryImport("Userenv.dll", EntryPoint = "CreateAppContainerProfile", StringMarshalling = StringMarshalling.Utf16)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    internal static partial int CreateAppContainerProfile(string name, string displayName, string description, nint capabilities, uint capabilityCount, out nint sid);

    [LibraryImport("Userenv.dll", EntryPoint = "DeriveAppContainerSidFromAppContainerName", StringMarshalling = StringMarshalling.Utf16)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    internal static partial int DeriveAppContainerSidFromAppContainerName(string name, out nint sid);
    [LibraryImport("WinTrust.dll", EntryPoint = "WinVerifyTrust")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    internal static partial int WinVerifyTrust(nint window, Guid* action, WinTrustData* data);

    [StructLayout(LayoutKind.Sequential)]
    internal struct WinTrustFileInfo
    {
        internal uint StructSize;
        internal nint FilePath;
        internal nint FileHandle;
        internal nint KnownSubject;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct WinTrustData
    {
        internal uint StructSize;
        internal nint PolicyCallback;
        internal nint SipClient;
        internal uint UiChoice;
        internal uint RevocationChecks;
        internal uint UnionChoice;
        internal nint FileInfo;
        internal uint StateAction;
        internal nint StateData;
        internal nint UrlReference;
        internal uint ProviderFlags;
        internal uint UiContext;
        internal nint SignatureSettings;
    }

}
