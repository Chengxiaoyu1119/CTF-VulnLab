using System;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

internal static class Program
{
    private static readonly ManualResetEvent StopRequested = new ManualResetEvent(false);
    private static readonly ManualResetEvent ServerExited = new ManualResetEvent(false);
    private static readonly object LogLock = new object();
    private static Process Server;
    private static StreamWriter Log;
    private static IntPtr Job;

    private static int Main()
    {
        string root = AppDomain.CurrentDomain.BaseDirectory;
        string app = Path.Combine(root, "app");
        string node = Path.Combine(root, "node", "node.exe");
        string entry = Path.Combine(app, "dist", "server.js");
        string localData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        string data = Environment.GetEnvironmentVariable("VULNLAB_DATA_DIR");
        if (String.IsNullOrWhiteSpace(data)) data = Path.Combine(localData, "CTF-VulnLab", "data");
        else data = Path.GetFullPath(data);
        string logPath = Path.Combine(data, "logs", "server.log");

        if (!File.Exists(node) || !File.Exists(entry))
        {
            Console.Error.WriteLine("发行目录缺少 Node.js 或应用入口，请重新解压完整的 CTF-VulnLab.zip。");
            return 1;
        }

        try
        {
            Directory.CreateDirectory(data);
            Directory.CreateDirectory(Path.GetDirectoryName(logPath));
            Log = new StreamWriter(new FileStream(logPath, FileMode.Append, FileAccess.Write, FileShare.ReadWrite), new UTF8Encoding(false));
            Log.AutoFlush = true;

            int port = 6710;
            string url = "http://127.0.0.1:" + port + "/";
            if (IsVulnLabReady(url))
            {
                Console.WriteLine("VulnLab 已在运行，正在打开 " + url);
                OpenBrowser(url);
                return 0;
            }
            if (!CanBind(port)) port = GetAvailablePort();
            url = "http://127.0.0.1:" + port + "/";

            ProcessStartInfo start = new ProcessStartInfo();
            start.FileName = node;
            start.Arguments = "\"" + entry + "\"";
            start.WorkingDirectory = app;
            start.UseShellExecute = false;
            start.CreateNoWindow = true;
            start.RedirectStandardInput = true;
            start.RedirectStandardOutput = true;
            start.RedirectStandardError = true;
            start.EnvironmentVariables["VULNLAB_HOST"] = "127.0.0.1";
            start.EnvironmentVariables["VULNLAB_PORT"] = port.ToString();
            start.EnvironmentVariables["VULNLAB_DATA_DIR"] = data;
            start.EnvironmentVariables["VULNLAB_LAUNCHER_CONTROL"] = "1";

            Server = new Process();
            Server.StartInfo = start;
            Server.EnableRaisingEvents = true;
            Server.OutputDataReceived += OnServerOutput;
            Server.ErrorDataReceived += OnServerOutput;
            Server.Exited += delegate { ServerExited.Set(); };
            if (!Server.Start()) throw new InvalidOperationException("VulnLab 服务进程启动失败。");
            Server.BeginOutputReadLine();
            Server.BeginErrorReadLine();
            try { AttachToJob(Server); }
            catch (Exception error) { Console.WriteLine("进程组清理保护未启用：" + error.Message); }

            Console.WriteLine("正在启动 VulnLab，首次准备运行环境可能需要一些时间……");
            bool ready = false;
            for (int attempt = 0; attempt < 600; attempt++)
            {
                if (Server.HasExited) break;
                if (IsVulnLabReady(url)) { ready = true; break; }
                Thread.Sleep(250);
            }
            if (!ready)
            {
                Console.Error.WriteLine("VulnLab 未能在 150 秒内就绪，或服务进程已退出。日志：" + logPath);
                PrintRecentLog(logPath);
                return 1;
            }

            Console.WriteLine("VulnLab 已启动：" + url);
            Console.WriteLine("关闭服务：按 Enter 或 Ctrl+C。运行数据保存在：" + data);
            OpenBrowser(url);

            Console.CancelKeyPress += delegate(object sender, ConsoleCancelEventArgs args)
            {
                args.Cancel = true;
                StopRequested.Set();
            };
            Thread input = new Thread(delegate()
            {
                try { Console.ReadLine(); StopRequested.Set(); }
                catch { StopRequested.Set(); }
            });
            input.IsBackground = true;
            input.Start();
            WaitHandle.WaitAny(new WaitHandle[] { StopRequested, ServerExited });
            return 0;
        }
        catch (Exception error)
        {
            Console.Error.WriteLine("启动 VulnLab 失败：" + error.Message);
            Console.Error.WriteLine("日志：" + logPath);
            return 1;
        }
        finally
        {
            StopServer();
            if (Log != null) Log.Dispose();
            if (Job != IntPtr.Zero) CloseHandle(Job);
            if (Server != null) Server.Dispose();
        }
    }

    private static void OnServerOutput(object sender, DataReceivedEventArgs args)
    {
        if (args.Data == null || Log == null) return;
        lock (LogLock) Log.WriteLine(args.Data);
    }

    private static bool IsVulnLabReady(string url)
    {
        try
        {
            HttpWebRequest request = (HttpWebRequest)WebRequest.Create(new Uri(new Uri(url), "healthz"));
            request.Timeout = 750;
            request.ReadWriteTimeout = 750;
            using (HttpWebResponse response = (HttpWebResponse)request.GetResponse())
            using (StreamReader reader = new StreamReader(response.GetResponseStream()))
                return response.StatusCode == HttpStatusCode.OK && reader.ReadToEnd().Contains("VulnLab");
        }
        catch { return false; }
    }

    private static bool CanBind(int port)
    {
        TcpListener listener = new TcpListener(IPAddress.Loopback, port);
        try { listener.Start(); return true; }
        catch { return false; }
        finally { listener.Stop(); }
    }

    private static int GetAvailablePort()
    {
        TcpListener listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        try { return ((IPEndPoint)listener.LocalEndpoint).Port; }
        finally { listener.Stop(); }
    }

    private static void OpenBrowser(string url)
    {
        try { Process.Start(new ProcessStartInfo(url) { UseShellExecute = true }); }
        catch { Console.WriteLine("请在浏览器手动打开：" + url); }
    }

    private static void PrintRecentLog(string path)
    {
        try
        {
            string[] lines = File.ReadAllLines(path);
            int first = Math.Max(0, lines.Length - 20);
            for (int i = first; i < lines.Length; i++) Console.Error.WriteLine(lines[i]);
        }
        catch { }
    }

    private static void StopServer()
    {
        if (Server == null) return;
        try
        {
            if (!Server.HasExited)
            {
                Console.WriteLine("正在关闭 VulnLab 并回收运行资源……");
                try { Server.StandardInput.WriteLine("stop"); Server.StandardInput.Flush(); }
                catch { try { Server.StandardInput.Close(); } catch { } }
                if (!Server.WaitForExit(45000))
                {
                    Console.Error.WriteLine("服务未在 45 秒内关闭，正在结束服务进程。");
                    Server.Kill();
                    Server.WaitForExit(10000);
                }
            }
            Server.WaitForExit();
        }
        catch { }
    }

    private static void AttachToJob(Process process)
    {
        IntPtr job = CreateJobObject(IntPtr.Zero, null);
        if (job == IntPtr.Zero) throw new InvalidOperationException("CreateJobObject 失败。");
        ExtendedLimitInformation limits = new ExtendedLimitInformation();
        limits.BasicLimitInformation.LimitFlags = 0x2000;
        if (!SetInformationJobObject(job, 9, ref limits, (uint)Marshal.SizeOf(typeof(ExtendedLimitInformation))))
        {
            CloseHandle(job);
            throw new InvalidOperationException("设置进程组回收策略失败。");
        }
        if (!AssignProcessToJobObject(job, process.Handle))
        {
            CloseHandle(job);
            throw new InvalidOperationException("将服务加入进程组失败。");
        }
        Job = job;
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
    private struct ExtendedLimitInformation
    {
        public BasicLimitInformation BasicLimitInformation;
        public IoCounters IoInfo;
        public UIntPtr ProcessMemoryLimit;
        public UIntPtr JobMemoryLimit;
        public UIntPtr PeakProcessMemoryUsed;
        public UIntPtr PeakJobMemoryUsed;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr CreateJobObject(IntPtr attributes, string name);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool SetInformationJobObject(IntPtr job, int infoClass, ref ExtendedLimitInformation info, uint length);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool AssignProcessToJobObject(IntPtr job, IntPtr process);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr handle);
}
