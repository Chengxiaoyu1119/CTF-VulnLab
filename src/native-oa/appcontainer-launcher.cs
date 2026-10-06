using System;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;

internal static class AppContainerLauncher
{
    private const uint ExtendedStartupInfoPresent = 0x00080000;
    private const uint CreateSuspended = 0x00000004;
    private const uint StartfUseStdHandles = 0x00000100;
    private const uint TokenQuery = 0x0008;
    private const int TokenIsAppContainer = 29;
    private const uint ProcThreadAttributeSecurityCapabilities = 0x00020009;
    private const uint ProcThreadAttributeChildProcessPolicy = 0x0002000E;
    private const uint ProcessCreationChildProcessRestricted = 0x00000001;
    private const uint JobObjectLimitKillOnJobClose = 0x00002000;
    private const uint JobObjectLimitActiveProcess = 0x00000008;
    private const uint JobObjectLimitJobMemory = 0x00000200;
    private const int JobObjectExtendedLimitInformation = 9;
    private const int HResultAlreadyExists = unchecked((int)0x800700B7);
    private const int HResultFileNotFound = unchecked((int)0x80070002);
    private const string ProfileMarkerName = ".oa-appcontainer-profile";

    [StructLayout(LayoutKind.Sequential)]
    private struct SecurityCapabilities
    {
        public IntPtr AppContainerSid;
        public IntPtr Capabilities;
        public uint CapabilityCount;
        public uint Reserved;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct StartupInfo
    {
        public uint cb;
        public string lpReserved;
        public string lpDesktop;
        public string lpTitle;
        public uint dwX;
        public uint dwY;
        public uint dwXSize;
        public uint dwYSize;
        public uint dwXCountChars;
        public uint dwYCountChars;
        public uint dwFillAttribute;
        public uint dwFlags;
        public short wShowWindow;
        public short cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput;
        public IntPtr hStdOutput;
        public IntPtr hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct StartupInfoEx
    {
        public StartupInfo StartupInfo;
        public IntPtr AttributeList;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ProcessInformation
    {
        public IntPtr Process;
        public IntPtr Thread;
        public uint ProcessId;
        public uint ThreadId;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct IoCounters
    {
        public ulong ReadOperationCount;
        public ulong WriteOperationCount;
        public ulong OtherOperationCount;
        public ulong ReadTransferCount;
        public ulong WriteTransferCount;
        public ulong OtherTransferCount;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct BasicLimitInformation
    {
        public long PerProcessUserTimeLimit;
        public long PerJobUserTimeLimit;
        public uint LimitFlags;
        public UIntPtr MinimumWorkingSetSize;
        public UIntPtr MaximumWorkingSetSize;
        public uint ActiveProcessLimit;
        public UIntPtr Affinity;
        public uint PriorityClass;
        public uint SchedulingClass;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ExtendedLimitInformation
    {
        public BasicLimitInformation BasicLimitInformation;
        public IoCounters IoInfo;
        public UIntPtr ProcessMemoryLimit;
        public UIntPtr JobMemoryLimit;
        public UIntPtr PeakProcessMemoryUsed;
        public UIntPtr PeakJobMemoryUsed;
    }

    [DllImport("userenv.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern int DeriveAppContainerSidFromAppContainerName(string name, out IntPtr appContainerSid);
    [DllImport("userenv.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern int CreateAppContainerProfile(string name, string displayName, string description, IntPtr capabilities, uint capabilityCount, out IntPtr appContainerSid);
    [DllImport("userenv.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern int DeleteAppContainerProfile(string name);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool ConvertSidToStringSid(IntPtr sid, out IntPtr stringSid);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr LocalFree(IntPtr memory);
    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern IntPtr FreeSid(IntPtr sid);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool InitializeProcThreadAttributeList(IntPtr list, int count, int flags, ref IntPtr size);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool UpdateProcThreadAttribute(IntPtr list, uint flags, IntPtr attribute, IntPtr value, IntPtr size, IntPtr previous, IntPtr returnedSize);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool CreateProcessW(string applicationName, StringBuilder commandLine, IntPtr processAttributes, IntPtr threadAttributes, bool inheritHandles, uint creationFlags, byte[] environment, string currentDirectory, ref StartupInfoEx startupInfo, out ProcessInformation processInformation);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr GetStdHandle(int handle);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr CreateJobObject(IntPtr attributes, string name);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool SetInformationJobObject(IntPtr job, int informationClass, ref ExtendedLimitInformation information, uint length);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool AssignProcessToJobObject(IntPtr job, IntPtr process);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint WaitForSingleObject(IntPtr handle, uint milliseconds);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetExitCodeProcess(IntPtr process, out uint exitCode);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr handle);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool TerminateProcess(IntPtr process, uint exitCode);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint ResumeThread(IntPtr thread);
    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool OpenProcessToken(IntPtr process, uint desiredAccess, out IntPtr token);
    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool GetTokenInformation(IntPtr token, int tokenInformationClass, out int tokenInformation, uint tokenInformationLength, out uint returnLength);

    private static void Check(bool success, string action)
    {
        if (!success)
        {
            int errorCode = Marshal.GetLastWin32Error();
            throw new System.ComponentModel.Win32Exception(errorCode, string.Format("{0} (GetLastError={1}, 0x{2:X8})", action, errorCode, unchecked((uint)errorCode)));
        }
    }

    private static bool IsProcessInAppContainer(IntPtr process)
    {
        IntPtr token = IntPtr.Zero;
        Check(OpenProcessToken(process, TokenQuery, out token), "Process access token open failed");
        try
        {
            int isAppContainer;
            uint returnLength;
            Check(GetTokenInformation(token, TokenIsAppContainer, out isAppContainer, sizeof(int), out returnLength), "AppContainer token verification failed");
            return isAppContainer != 0;
        }
        finally
        {
            if (token != IntPtr.Zero) CloseHandle(token);
        }
    }

    private static IntPtr DeriveProfileSid(string name)
    {
        IntPtr sid;
        int result = DeriveAppContainerSidFromAppContainerName(name, out sid);
        if (result >= 0) return sid;
        Marshal.ThrowExceptionForHR(result);
        throw new InvalidOperationException("AppContainer SID derivation failed.");
    }

    private static IntPtr CreateOrOpenProfileSid(string name)
    {
        IntPtr sid;
        int result = CreateAppContainerProfile(name, "VulnLab OA instance", "Per-instance isolated OA API", IntPtr.Zero, 0, out sid);
        if (result == 0 && sid != IntPtr.Zero) return sid;
        if (result == HResultAlreadyExists)
        {
            if (sid != IntPtr.Zero) FreeSid(sid);
            return DeriveProfileSid(name);
        }
        Console.Error.WriteLine("OA_SANDBOX:profile:create-failed:0x" + unchecked((uint)result).ToString("X8"));
        throw new InvalidOperationException("AppContainer profile creation failed (HRESULT=0x" + unchecked((uint)result).ToString("X8") + ").");
    }

    private static void DeleteProfileIfMarked(string name, string runtimeRoot)
    {
        string marker = Path.Combine(runtimeRoot, ProfileMarkerName);
        if (!File.Exists(marker)) return;
        string markedProfile = File.ReadAllText(marker, Encoding.UTF8).Trim();
        if (!String.Equals(markedProfile, name, StringComparison.Ordinal)) throw new InvalidOperationException("OA AppContainer profile marker does not match the instance.");
        int result = DeleteAppContainerProfile(name);
        if (result < 0 && result != HResultFileNotFound)
        {
            Console.Error.WriteLine("OA_SANDBOX:profile:delete-failed:0x" + unchecked((uint)result).ToString("X8"));
            Marshal.ThrowExceptionForHR(result);
        }
        File.Delete(marker);
    }

    private static void ValidateProfileName(string name)
    {
        if (name.Length < 8 || name.Length > 64 || Array.Exists(name.ToCharArray(), value => !Char.IsLetterOrDigit(value) && value != '.' && value != '_' && value != '-'))
            throw new ArgumentException("Invalid AppContainer name");
    }

    private static int ProbeProfile(string name)
    {
        ValidateProfileName(name);
        IntPtr sid = CreateOrOpenProfileSid(name);
        try
        {
            int result = DeleteAppContainerProfile(name);
            if (result < 0 && result != HResultFileNotFound)
            {
                Console.Error.WriteLine("OA_SANDBOX:profile:delete-failed:0x" + unchecked((uint)result).ToString("X8"));
                Marshal.ThrowExceptionForHR(result);
            }
            return 0;
        }
        finally
        {
            if (sid != IntPtr.Zero) FreeSid(sid);
        }
    }

    private static string SidText(IntPtr sid)
    {
        IntPtr value;
        Check(ConvertSidToStringSid(sid, out value), "SID conversion failed");
        try { return Marshal.PtrToStringUni(value); }
        finally { LocalFree(value); }
    }

    private static void GrantTree(string path, SecurityIdentifier sid, FileSystemRights rights)
    {
        FileAttributes attributes = File.GetAttributes(path);
        if ((attributes & FileAttributes.ReparsePoint) != 0)
            throw new InvalidOperationException("拒绝向重解析点授予 OA 沙箱访问权限：" + path);
        if ((attributes & FileAttributes.Directory) != 0)
        {
            GrantDirectory(path, sid, rights);
            return;
        }
        var security = File.GetAccessControl(path, AccessControlSections.Access);
        security.AddAccessRule(new FileSystemAccessRule(sid, rights, AccessControlType.Allow));
        File.SetAccessControl(path, security);
    }

    private static bool HasExplicitSidRule(FileSystemSecurity security, SecurityIdentifier sid)
    {
        foreach (FileSystemAccessRule rule in security.GetAccessRules(true, false, typeof(SecurityIdentifier)))
            if (sid.Equals(rule.IdentityReference)) return true;
        return false;
    }

    private static void RevokeDirectory(string path, SecurityIdentifier sid)
    {
        var security = Directory.GetAccessControl(path, AccessControlSections.Access);
        if (!HasExplicitSidRule(security, sid)) return;
        security.PurgeAccessRules(sid);
        Directory.SetAccessControl(path, security);
    }

    private static void RevokeTree(string path, SecurityIdentifier sid)
    {
        if (!File.Exists(path) && !Directory.Exists(path)) return;
        FileAttributes attributes = File.GetAttributes(path);
        if ((attributes & FileAttributes.ReparsePoint) != 0) return;
        if ((attributes & FileAttributes.Directory) != 0)
        {
            RevokeDirectory(path, sid);
            return;
        }
        var fileSecurity = File.GetAccessControl(path, AccessControlSections.Access);
        if (!HasExplicitSidRule(fileSecurity, sid)) return;
        fileSecurity.PurgeAccessRules(sid);
        File.SetAccessControl(path, fileSecurity);
    }

    private static void GrantRuntimeDirectory(string path, SecurityIdentifier sid)
    {
        var directory = new DirectoryInfo(path);
        var security = directory.GetAccessControl(AccessControlSections.Access);
        security.AddAccessRule(new FileSystemAccessRule(
            sid,
            FileSystemRights.Traverse | FileSystemRights.ReadAttributes | FileSystemRights.ReadExtendedAttributes | FileSystemRights.ReadPermissions | FileSystemRights.Synchronize,
            InheritanceFlags.None,
            PropagationFlags.None,
            AccessControlType.Allow));
        directory.SetAccessControl(security);
        foreach (string file in Directory.GetFiles(path, "*", SearchOption.TopDirectoryOnly)) GrantTree(file, sid, FileSystemRights.ReadAndExecute);
    }

    private static void RevokeRuntimeDirectory(string path, SecurityIdentifier sid)
    {
        if (!Directory.Exists(path)) return;
        foreach (string file in Directory.GetFiles(path, "*", SearchOption.TopDirectoryOnly)) RevokeTree(file, sid);
        RevokeDirectory(path, sid);
    }

    private static void GrantDirectory(string path, SecurityIdentifier sid, FileSystemRights rights)
    {
        var directory = new DirectoryInfo(path);
        var security = directory.GetAccessControl(AccessControlSections.Access);
        var inheritance = InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit;
        security.AddAccessRule(new FileSystemAccessRule(sid, rights, inheritance, PropagationFlags.None, AccessControlType.Allow));
        directory.SetAccessControl(security);
    }

    private static string Quote(string value)
    {
        if (value.Length > 0 && value.IndexOfAny(new[] { ' ', '\t', '\n', '\v', '"' }) < 0) return value;
        var result = new StringBuilder("\"");
        int slashes = 0;
        foreach (char current in value)
        {
            if (current == '\\') { slashes++; continue; }
            if (current == '"') result.Append('\\', slashes * 2 + 1).Append('"');
            else result.Append('\\', slashes).Append(current);
            slashes = 0;
        }
        result.Append('\\', slashes * 2).Append('"');
        return result.ToString();
    }

    private static ProcessInformation StartAppContainer(string profile, string runtimeRoot, string uploadRoot, string nodePath, string entryPath, string moduleRoot, string[] nodeArguments)
    {
        IntPtr sid = CreateOrOpenProfileSid(profile);
        bool profileMarkerWritten = false;
        IntPtr attributes = IntPtr.Zero;
        IntPtr capabilitiesPointer = IntPtr.Zero;
        IntPtr childPolicyPointer = IntPtr.Zero;
        ProcessInformation process = new ProcessInformation();
        bool processCreated = false;
        bool processOwnershipTransferred = false;
        try
        {
            File.WriteAllText(Path.Combine(runtimeRoot, ProfileMarkerName), profile, new UTF8Encoding(false));
            profileMarkerWritten = true;
            string sidValue = SidText(sid);
            var securitySid = new SecurityIdentifier(sidValue);
            Console.Error.WriteLine("OA_SANDBOX:acl:start");
            Directory.CreateDirectory(Path.Combine(runtimeRoot, ".tmp"));
            GrantTree(runtimeRoot, securitySid, FileSystemRights.ReadAndExecute);
            Console.Error.WriteLine("OA_SANDBOX:acl:runtime-complete");
            GrantTree(uploadRoot, securitySid, FileSystemRights.Modify);
            GrantRuntimeDirectory(Path.GetDirectoryName(nodePath), securitySid);
            Console.Error.WriteLine("OA_SANDBOX:acl:node-complete");
            GrantTree(Path.GetDirectoryName(entryPath), securitySid, FileSystemRights.ReadAndExecute);
            Console.Error.WriteLine("OA_SANDBOX:acl:app-complete");
            GrantTree(moduleRoot, securitySid, FileSystemRights.ReadAndExecute);
            Console.Error.WriteLine("OA_SANDBOX:acl:modules-complete");
            GrantDirectory(Path.Combine(runtimeRoot, ".tmp"), securitySid, FileSystemRights.Modify);

            var capabilities = new SecurityCapabilities { AppContainerSid = sid, Capabilities = IntPtr.Zero, CapabilityCount = 0, Reserved = 0 };
            capabilitiesPointer = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(SecurityCapabilities)));
            Marshal.StructureToPtr(capabilities, capabilitiesPointer, false);
            childPolicyPointer = Marshal.AllocHGlobal(sizeof(uint));
            Marshal.WriteInt32(childPolicyPointer, unchecked((int)ProcessCreationChildProcessRestricted));
            IntPtr listSize = IntPtr.Zero;
            InitializeProcThreadAttributeList(IntPtr.Zero, 2, 0, ref listSize);
            attributes = Marshal.AllocHGlobal(listSize);
            Check(InitializeProcThreadAttributeList(attributes, 2, 0, ref listSize), "Process attribute list initialization failed");
            Check(UpdateProcThreadAttribute(attributes, 0, new IntPtr(ProcThreadAttributeSecurityCapabilities), capabilitiesPointer, new IntPtr(Marshal.SizeOf(typeof(SecurityCapabilities))), IntPtr.Zero, IntPtr.Zero), "AppContainer process attribute setup failed");
            Check(UpdateProcThreadAttribute(attributes, 0, new IntPtr(ProcThreadAttributeChildProcessPolicy), childPolicyPointer, new IntPtr(sizeof(uint)), IntPtr.Zero, IntPtr.Zero), "Child process policy setup failed");

            var command = new StringBuilder(Quote(nodePath));
            foreach (string argument in nodeArguments) command.Append(' ').Append(Quote(argument));
            var startup = new StartupInfoEx();
            startup.StartupInfo.cb = (uint)Marshal.SizeOf(typeof(StartupInfoEx));
            startup.StartupInfo.dwFlags = StartfUseStdHandles;
            startup.StartupInfo.hStdInput = GetStdHandle(-10);
            startup.StartupInfo.hStdOutput = GetStdHandle(-11);
            startup.StartupInfo.hStdError = GetStdHandle(-12);
            startup.AttributeList = attributes;
            Console.Error.WriteLine("OA_SANDBOX:process:create-start");
            Check(CreateProcessW(nodePath, command, IntPtr.Zero, IntPtr.Zero, true,
                ExtendedStartupInfoPresent | CreateSuspended, null,
                null, ref startup, out process), "AppContainer process launch failed");
            processCreated = true;
            if (!IsProcessInAppContainer(process.Process))
                throw new InvalidOperationException("OA API process did not enter an AppContainer.");
            Console.Error.WriteLine("OA_SANDBOX:process:create-complete");
            processOwnershipTransferred = true;
            return process;
        }
        catch
        {
            if (!profileMarkerWritten)
            {
                int result = DeleteAppContainerProfile(profile);
                if (result < 0 && result != HResultFileNotFound)
                    Console.Error.WriteLine("OA_SANDBOX:profile:delete-failed:0x" + unchecked((uint)result).ToString("X8"));
            }
            throw;
        }
        finally
        {
            if (processCreated && !processOwnershipTransferred)
            {
                TerminateProcess(process.Process, 1);
                if (process.Thread != IntPtr.Zero) CloseHandle(process.Thread);
                WaitForSingleObject(process.Process, 3000);
                CloseHandle(process.Process);
            }
            if (attributes != IntPtr.Zero) Marshal.FreeHGlobal(attributes);
            if (capabilitiesPointer != IntPtr.Zero) Marshal.FreeHGlobal(capabilitiesPointer);
            if (childPolicyPointer != IntPtr.Zero) Marshal.FreeHGlobal(childPolicyPointer);
            FreeSid(sid);
        }
    }

    private static void CleanupSandbox(string profile, string runtimeRoot, string uploadRoot, string nodePath, string entryPath, string moduleRoot)
    {
        IntPtr sid = IntPtr.Zero;
        try
        {
            int deriveResult = DeriveAppContainerSidFromAppContainerName(profile, out sid);
            if (deriveResult < 0) Marshal.ThrowExceptionForHR(deriveResult);
            var securitySid = new SecurityIdentifier(SidText(sid));
            RevokeTree(runtimeRoot, securitySid);
            RevokeTree(uploadRoot, securitySid);
            RevokeTree(Path.Combine(runtimeRoot, ".tmp"), securitySid);
            RevokeRuntimeDirectory(Path.GetDirectoryName(nodePath), securitySid);
            RevokeTree(Path.GetDirectoryName(entryPath), securitySid);
            RevokeTree(moduleRoot, securitySid);
            DeleteProfileIfMarked(profile, runtimeRoot);
        }
        finally
        {
            if (sid != IntPtr.Zero) FreeSid(sid);
        }
        Console.Error.WriteLine("OA_SANDBOX:cleanup:complete");
    }

    private static int Run(string[] args)
    {
        if (args.Length == 2 && args[0] == "check") return ProbeProfile(args[1]);
        if (args.Length == 7 && args[0] == "cleanup")
        {
            CleanupSandbox(args[1], Path.GetFullPath(args[2]), Path.GetFullPath(args[3]), Path.GetFullPath(args[4]), Path.GetFullPath(args[5]), Path.GetFullPath(args[6]));
            return 0;
        }
        if (args.Length < 7 || args[0] != "appcontainer")
        {
            Console.Error.WriteLine("usage: appcontainer <profile> <runtime-root> <upload-root> <node.exe> <entry.js> <module-root> [node args...] | cleanup <profile> <runtime-root> <upload-root> <node.exe> <entry.js> <module-root>");
            return 2;
        }
        string profile = args[1];
        ValidateProfileName(profile);
        string runtimeRoot = Path.GetFullPath(args[2]);
        string uploadRoot = Path.GetFullPath(args[3]);
        string nodePath = Path.GetFullPath(args[4]);
        string entryPath = Path.GetFullPath(args[5]);
        string moduleRoot = Path.GetFullPath(args[6]);
        IntPtr job = CreateJobObject(IntPtr.Zero, null);
        if (job == IntPtr.Zero) throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), "Job creation failed");
        ProcessInformation process = new ProcessInformation();
        bool processStarted = false;
        bool processAssigned = false;
        try
        {
            process = StartAppContainer(profile, runtimeRoot, uploadRoot, nodePath, entryPath, moduleRoot, args.Skip(7).ToArray());
            processStarted = true;
            var limits = new ExtendedLimitInformation();
            limits.BasicLimitInformation.LimitFlags = JobObjectLimitKillOnJobClose | JobObjectLimitActiveProcess | JobObjectLimitJobMemory;
            limits.BasicLimitInformation.ActiveProcessLimit = 1;
            limits.JobMemoryLimit = new UIntPtr(512UL * 1024UL * 1024UL);
            Check(SetInformationJobObject(job, JobObjectExtendedLimitInformation, ref limits, (uint)Marshal.SizeOf(typeof(ExtendedLimitInformation))), "Job limits setup failed");
            Check(AssignProcessToJobObject(job, process.Process), "AppContainer process job assignment failed");
            processAssigned = true;
            Check(ResumeThread(process.Thread) != 0xFFFFFFFF, "AppContainer process resume failed");
            CloseHandle(process.Thread);
            Console.Error.WriteLine("OA_SANDBOX:verified-appcontainer:resumed:" + process.ProcessId);
            uint waitResult = WaitForSingleObject(process.Process, 0xFFFFFFFF);
            Check(waitResult == 0, "AppContainer process wait failed");
            uint exitCode;
            Check(GetExitCodeProcess(process.Process, out exitCode), "AppContainer exit-code query failed");
            Console.Error.WriteLine("OA_SANDBOX:exit:" + exitCode);
            return unchecked((int)exitCode);
        }
        finally
        {
            CloseHandle(job);
            if (processStarted)
            {
                if (!processAssigned) TerminateProcess(process.Process, 1);
                WaitForSingleObject(process.Process, 3000);
                CloseHandle(process.Process);
            }
            CleanupSandbox(profile, runtimeRoot, uploadRoot, nodePath, entryPath, moduleRoot);
        }
    }

    private static int Main(string[] args)
    {
        Console.SetError(new StreamWriter(Console.OpenStandardError(), new UTF8Encoding(false)) { AutoFlush = true });
        try { return Run(args); }
        catch (Exception error)
        {
            Console.Error.WriteLine(error);
            return 1;
        }
    }
}
