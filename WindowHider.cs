// ============================================================
// WindowHider - 窗口隐身器
//
// 按住准星拖到任意窗口上松开，该窗口就会从截图、录屏、
// 远程桌面/监控软件的画面里"隐身"——全屏截屏里会直接透出
// 窗口后面的桌面/其他窗口，就像这个窗口不存在一样，
// 而你自己的屏幕上照常显示、照常操作。
//
// 原理：Windows 官方 API SetWindowDisplayAffinity(hwnd,
//       WDA_EXCLUDEFROMCAPTURE)，DWM 在合成层直接把该窗口
//       排除在一切软件捕获之外。和 DRM 播放器防录屏是同一招。
//
// 编译：双击 build.bat（调用 Windows 自带的 csc.exe，
//       不用装 Visual Studio，不用装任何东西）
// ============================================================

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Windows.Forms;

namespace WindowHider
{
    // ---------------- Win32 声明 ----------------
    static class Native
    {
        public const uint WDA_NONE = 0;
        public const uint WDA_EXCLUDEFROMCAPTURE = 0x11; // 17

        public const uint PROCESS_CREATE_THREAD = 0x0002;
        public const uint PROCESS_QUERY_INFORMATION = 0x0400;
        public const uint PROCESS_VM_OPERATION = 0x0008;
        public const uint PROCESS_VM_WRITE = 0x0020;
        public const uint PROCESS_VM_READ = 0x0010;
        public const uint PROCESS_ACCESS = PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION
                                          | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ;

        public const uint MEM_COMMIT = 0x1000;
        public const uint MEM_RESERVE = 0x2000;
        public const uint PAGE_EXECUTE_READWRITE = 0x40;
        public const uint MEM_RELEASE = 0x8000;

        public const uint WAIT_OBJECT_0 = 0x00000000;
        public const uint WAIT_TIMEOUT = 0x00000102;
        public const uint STILL_ACTIVE = 259; // GetExitCodeThread 返回 259 表示线程仍在运行

        public const uint TH32CS_SNAPMODULE = 0x00000008;
        public const uint TH32CS_SNAPMODULE32 = 0x00000010;
        public const uint GA_ROOT = 2;
        public const uint DSTINVERT = 0x00550009;

        [StructLayout(LayoutKind.Sequential)]
        public struct RECT { public int Left, Top, Right, Bottom; }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct MODULEENTRY32
        {
            public uint dwSize;
            public uint th32ModuleID;
            public uint th32ProcessID;
            public uint GlblcntUsage;
            public uint ProccntUsage;
            public IntPtr modBaseAddr;
            public uint modBaseSize;
            public IntPtr hModule;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
            public string szModule;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
            public string szExePath;
        }

        public delegate bool EnumWindowsProc(IntPtr hWnd, IntPtr lParam);

        [DllImport("user32.dll", SetLastError = true)]
        public static extern bool SetWindowDisplayAffinity(IntPtr hWnd, uint dwAffinity);

        [DllImport("user32.dll", SetLastError = true)]
        public static extern bool GetWindowDisplayAffinity(IntPtr hWnd, out uint pdwAffinity);

        [DllImport("user32.dll", SetLastError = true)]
        public static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint lpdwProcessId);

        [DllImport("user32.dll")]
        public static extern bool EnumWindows(EnumWindowsProc lpEnumFunc, IntPtr lParam);

        [DllImport("user32.dll")]
        public static extern bool IsWindow(IntPtr hWnd);

        [DllImport("user32.dll")]
        public static extern bool IsWindowVisible(IntPtr hWnd);

        [DllImport("user32.dll", CharSet = CharSet.Unicode)]
        public static extern int GetWindowText(IntPtr hWnd, StringBuilder lpString, int nMaxCount);

        [DllImport("user32.dll")]
        public static extern IntPtr GetAncestor(IntPtr hWnd, uint gaFlags);

        [DllImport("user32.dll")]
        public static extern IntPtr WindowFromPoint(Point point);

        [DllImport("user32.dll")]
        public static extern bool GetCursorPos(out Point lpPoint);

        [DllImport("user32.dll")]
        public static extern IntPtr GetWindowDC(IntPtr hWnd);

        [DllImport("user32.dll")]
        public static extern int ReleaseDC(IntPtr hWnd, IntPtr hDC);

        [DllImport("user32.dll")]
        public static extern bool GetWindowRect(IntPtr hWnd, out RECT lpRect);

        [DllImport("gdi32.dll")]
        public static extern bool PatBlt(IntPtr hdc, int x, int y, int w, int h, uint rop);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, uint dwProcessId);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize,
                                                   uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool VirtualFreeEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint dwFreeType);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress,
                                                     byte[] lpBuffer, uint nSize, out UIntPtr lpNumberOfBytesWritten);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes,
                                                       uint dwStackSize, IntPtr lpStartAddress,
                                                       IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool GetExitCodeThread(IntPtr hThread, out uint lpExitCode);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool IsWow64Process(IntPtr hProcess, out bool wow64Process);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr GetCurrentProcess();

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr CreateToolhelp32Snapshot(uint dwFlags, uint th32ProcessID);

        // 注意：必须显式 CharSet.Unicode，否则默认按 ANSI 绑定 Module32FirstA，
        // 与 Unicode 版 MODULEENTRY32 的 dwSize 对不上，枚举直接失败。
        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool Module32First(IntPtr hSnapshot, ref MODULEENTRY32 lpme);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool Module32Next(IntPtr hSnapshot, ref MODULEENTRY32 lpme);
    }

    // ---------------- PE 导出表解析 ----------------
    // 用途：在目标进程里算出 SetWindowDisplayAffinity 的真实地址。
    // 因为该 API 必须由"拥有窗口的进程自己"调用，外部进程调会直接被拒绝，
    // 所以我们向目标进程注入一小段机器码，让它自己调。
    // 要注入就得先知道函数在目标进程里的地址：读目标进程 user32.dll 的
    // 加载基址 + 解析磁盘上同版本 DLL 的导出表得到 RVA，两者相加即得。
    static class PeExport
    {
        public static uint GetExportRva(string dllPath, string funcName)
        {
            byte[] data;
            try { data = File.ReadAllBytes(dllPath); }
            catch { return 0; }
            if (data.Length < 0x40 || data[0] != 'M' || data[1] != 'Z') return 0;

            uint e_lfanew = BitConverter.ToUInt32(data, 0x3C);
            if (e_lfanew + 24 > (uint)data.Length) return 0;
            if (data[e_lfanew] != 'P' || data[e_lfanew + 1] != 'E') return 0;

            ushort numSections = BitConverter.ToUInt16(data, (int)e_lfanew + 6);
            ushort optSize = BitConverter.ToUInt16(data, (int)e_lfanew + 20);
            int optOff = (int)e_lfanew + 24;
            if (optOff + optSize > data.Length) return 0;

            ushort magic = BitConverter.ToUInt16(data, optOff);
            int exportDirOff; // DataDirectory[0] 偏移
            if (magic == 0x10b) exportDirOff = optOff + 96;       // PE32
            else if (magic == 0x20b) exportDirOff = optOff + 112; // PE32+
            else return 0;

            uint exportRva = BitConverter.ToUInt32(data, exportDirOff);
            int secOff = optOff + optSize;

            uint numNames = ReadU32(data, secOff, numSections, exportRva + 24);
            uint addrFuncs = ReadU32(data, secOff, numSections, exportRva + 28);
            uint addrNames = ReadU32(data, secOff, numSections, exportRva + 32);
            uint addrOrdinals = ReadU32(data, secOff, numSections, exportRva + 36);
            if (numNames == 0 || numNames == 0xFFFFFFFF) return 0;

            for (uint i = 0; i < numNames; i++)
            {
                uint nameRva = ReadU32(data, secOff, numSections, addrNames + i * 4);
                if (nameRva == 0xFFFFFFFF) continue;
                if (ReadAscii(data, secOff, numSections, nameRva) == funcName)
                {
                    ushort ord = ReadU16(data, secOff, numSections, addrOrdinals + i * 2);
                    return ReadU32(data, secOff, numSections, addrFuncs + (uint)ord * 4);
                }
            }
            return 0;
        }

        static int RvaToOffset(byte[] data, int secOff, ushort numSections, uint rva)
        {
            for (int i = 0; i < numSections; i++)
            {
                int s = secOff + i * 40;
                if (s + 40 > data.Length) break;
                uint vsize = BitConverter.ToUInt32(data, s + 8);
                uint vaddr = BitConverter.ToUInt32(data, s + 12);
                uint rawSize = BitConverter.ToUInt32(data, s + 16);
                uint rawPtr = BitConverter.ToUInt32(data, s + 20);
                uint size = Math.Max(vsize, rawSize);
                if (rva >= vaddr && rva < vaddr + size)
                    return (int)(rawPtr + (rva - vaddr));
            }
            return -1;
        }

        static uint ReadU32(byte[] data, int secOff, ushort numSections, uint rva)
        {
            int off = RvaToOffset(data, secOff, numSections, rva);
            if (off < 0 || off + 4 > data.Length) return 0xFFFFFFFF;
            return BitConverter.ToUInt32(data, off);
        }

        static ushort ReadU16(byte[] data, int secOff, ushort numSections, uint rva)
        {
            int off = RvaToOffset(data, secOff, numSections, rva);
            if (off < 0 || off + 2 > data.Length) return 0xFFFF;
            return BitConverter.ToUInt16(data, off);
        }

        static string ReadAscii(byte[] data, int secOff, ushort numSections, uint rva)
        {
            int off = RvaToOffset(data, secOff, numSections, rva);
            if (off < 0) return "";
            int end = off;
            while (end < data.Length && data[end] != 0 && end - off < 256) end++;
            return Encoding.ASCII.GetString(data, off, end - off);
        }
    }

    // ---------------- 注入器 ----------------
    static class Injector
    {
        public static string LastError = "";

        // affinity: 0x11=隐身, 0=恢复
        public static bool SetAffinity(IntPtr hwnd, uint affinity)
        {
            LastError = "";
            uint pid;
            Native.GetWindowThreadProcessId(hwnd, out pid);
            if (pid == 0) { LastError = "无法获取窗口所属进程"; return false; }

            IntPtr hProcess = Native.OpenProcess(Native.PROCESS_ACCESS, false, pid);
            if (hProcess == IntPtr.Zero)
            {
                int err = Marshal.GetLastWin32Error();
                LastError = err == 5
                    ? "拒绝访问：目标以更高权限运行，请以管理员身份运行本工具"
                    : "无法打开目标进程，错误码 " + err;
                return false;
            }

            try
            {
                // 判断目标进程是 32 位还是 64 位
                bool targetIs64;
                if (IntPtr.Size == 8)
                {
                    bool wow; Native.IsWow64Process(hProcess, out wow);
                    targetIs64 = !wow;
                }
                else
                {
                    bool selfWow; Native.IsWow64Process(Native.GetCurrentProcess(), out selfWow);
                    if (selfWow)
                    {
                        bool wow; Native.IsWow64Process(hProcess, out wow);
                        if (!wow) { LastError = "32 位工具无法注入 64 位进程，请换 64 位系统编译"; return false; }
                    }
                    targetIs64 = false;
                }

                IntPtr funcAddr = GetRemoteProcAddress(pid, targetIs64, "user32.dll", "SetWindowDisplayAffinity");
                if (funcAddr == IntPtr.Zero) { LastError = "无法定位目标进程中的 SetWindowDisplayAffinity"; return false; }

                byte[] code = targetIs64 ? Build64(hwnd, funcAddr, affinity)
                                         : Build32(hwnd, funcAddr, affinity);

                IntPtr remote = Native.VirtualAllocEx(hProcess, IntPtr.Zero, (uint)code.Length,
                    Native.MEM_COMMIT | Native.MEM_RESERVE, Native.PAGE_EXECUTE_READWRITE);
                if (remote == IntPtr.Zero) { LastError = "远程内存分配失败"; return false; }

                UIntPtr written;
                if (!Native.WriteProcessMemory(hProcess, remote, code, (uint)code.Length, out written))
                {
                    Native.VirtualFreeEx(hProcess, remote, 0, Native.MEM_RELEASE);
                    LastError = "远程内存写入失败"; return false;
                }

                IntPtr hThread = Native.CreateRemoteThread(hProcess, IntPtr.Zero, 0, remote,
                                                           IntPtr.Zero, 0, IntPtr.Zero);
                if (hThread == IntPtr.Zero)
                {
                    Native.VirtualFreeEx(hProcess, remote, 0, Native.MEM_RELEASE);
                    LastError = "创建远程线程失败，错误码 " + Marshal.GetLastWin32Error(); return false;
                }

                uint waitResult = Native.WaitForSingleObject(hThread, 5000);
                if (waitResult != Native.WAIT_OBJECT_0)
                {
                    // 超时（或等待失败）：远程线程可能还在执行 shellcode，
                    // 此时释放远程内存会把线程正在执行的代码页抽走，导致目标进程崩溃。
                    // 这块内存只有几十字节，故意不释放（泄漏），保进程不崩比省内存重要。
                    // 注意 CloseHandle 只关闭我们这边的线程句柄，不会终止远程线程本身。
                    Native.CloseHandle(hThread);
                    LastError = waitResult == Native.WAIT_TIMEOUT
                        ? "远程线程 5 秒内未结束，注入已取消（目标进程不受影响）"
                        : "等待远程线程失败，错误码 " + Marshal.GetLastWin32Error();
                    return false;
                }
                uint exitCode = 0;
                Native.GetExitCodeThread(hThread, out exitCode);
                Native.CloseHandle(hThread);
                Native.VirtualFreeEx(hProcess, remote, 0, Native.MEM_RELEASE);

                // STILL_ACTIVE(259) 表示线程仍在运行，不能当作成功（之前会漏过
                // 下面两道检查被误判为成功）；正常等待返回后不应出现，这里做防御性检查。
                if (exitCode == Native.STILL_ACTIVE)
                {
                    LastError = "远程线程仍在运行，注入结果未知";
                    return false;
                }
                if (exitCode == 0) { LastError = "目标进程内调用 API 失败"; return false; }
                if (exitCode >= 0xC0000000)
                {
                    LastError = string.Format("目标进程内执行崩溃（异常码 0x{0:X8}），请截图反馈", exitCode);
                    return false;
                }

                // 二次验证：跨进程直接读该窗口的 affinity（读是允许的）。
                // 注意 Win10 2004 以下的系统会把 0x11 当作 WDA_MONITOR(1) 生效，
                // 所以只要"非 0"就算设置成功，"0"算清除成功。
                uint actual = 0;
                if (Native.GetWindowDisplayAffinity(hwnd, out actual))
                {
                    bool expectHidden = (affinity != Native.WDA_NONE);
                    bool isHidden = (actual != Native.WDA_NONE);
                    if (expectHidden == isHidden) return true;
                    LastError = "注入调用已执行，但系统未接受该窗口的隐身设置";
                    return false;
                }
                return true;
            }
            finally { Native.CloseHandle(hProcess); }
        }

        static IntPtr GetRemoteProcAddress(uint pid, bool targetIs64, string dllName, string funcName)
        {
            // 1) 目标进程里 user32.dll 的加载基址
            IntPtr snap = Native.CreateToolhelp32Snapshot(
                Native.TH32CS_SNAPMODULE | Native.TH32CS_SNAPMODULE32, pid);
            if (snap == new IntPtr(-1)) return IntPtr.Zero;
            IntPtr baseAddr = IntPtr.Zero;
            try
            {
                var me = new Native.MODULEENTRY32();
                me.dwSize = (uint)Marshal.SizeOf(typeof(Native.MODULEENTRY32));
                if (Native.Module32First(snap, ref me))
                {
                    do
                    {
                        if (string.Equals(me.szModule, dllName, StringComparison.OrdinalIgnoreCase))
                        { baseAddr = me.modBaseAddr; break; }
                    } while (Native.Module32Next(snap, ref me));
                }
            }
            finally { Native.CloseHandle(snap); }
            if (baseAddr == IntPtr.Zero) return IntPtr.Zero;

            // 2) 磁盘上对应版本 DLL 的导出表 RVA
            string windir = Environment.GetEnvironmentVariable("windir");
            if (string.IsNullOrEmpty(windir)) windir = @"C:\Windows";
            string dllPath = (!targetIs64 && Environment.Is64BitOperatingSystem)
                ? Path.Combine(windir, @"SysWOW64\" + dllName)
                : Path.Combine(windir, @"System32\" + dllName);
            uint rva = PeExport.GetExportRva(dllPath, funcName);
            if (rva == 0) return IntPtr.Zero;

            return new IntPtr(baseAddr.ToInt64() + rva);
        }

        // x64: SetWindowDisplayAffinity(hwnd, affinity)
        // 注意：CreateRemoteThread 启动时 RSP 是 8 字节对齐（RtlUserThreadStart 经 call 进入），
        // 而 x64 ABI 要求 call 之前 RSP 必须 16 字节对齐，否则被调函数里一旦用 movaps 等对齐指令
        // 就会崩溃（0xC0000005）。所以先 sub rsp,0x28（8 字节对齐 + 32 字节影子空间），调完恢复。
        static byte[] Build64(IntPtr hwnd, IntPtr func, uint affinity)
        {
            var sc = new List<byte>();
            sc.AddRange(new byte[] { 0x48, 0x83, 0xEC, 0x28 });          // sub rsp, 0x28
            sc.AddRange(new byte[] { 0x48, 0xB9 });
            sc.AddRange(BitConverter.GetBytes(hwnd.ToInt64()));          // mov rcx, hwnd
            sc.AddRange(new byte[] { 0x48, 0xC7, 0xC2 });
            sc.AddRange(BitConverter.GetBytes(affinity));                // mov rdx, affinity
            sc.AddRange(new byte[] { 0x48, 0xB8 });
            sc.AddRange(BitConverter.GetBytes(func.ToInt64()));          // mov rax, func
            sc.AddRange(new byte[] { 0xFF, 0xD0 });                      // call rax
            sc.AddRange(new byte[] { 0x48, 0x83, 0xC4, 0x28 });          // add rsp, 0x28
            sc.Add(0xC3);                                                // ret
            return sc.ToArray();
        }

        // x86: push affinity; push hwnd; call func  (stdcall)
        static byte[] Build32(IntPtr hwnd, IntPtr func, uint affinity)
        {
            var sc = new List<byte>();
            sc.Add(0x68); sc.AddRange(BitConverter.GetBytes(affinity));  // push affinity
            sc.Add(0x68); sc.AddRange(BitConverter.GetBytes(hwnd.ToInt32())); // push hwnd
            sc.Add(0xB8); sc.AddRange(BitConverter.GetBytes(func.ToInt32()));  // mov eax, func
            sc.AddRange(new byte[] { 0xFF, 0xD0 });                      // call eax
            sc.Add(0xC3);                                                // ret
            return sc.ToArray();
        }
    }
}

namespace WindowHider
{
    // ---------------- 主界面 ----------------
    class MainForm : Form
    {
        Button btnFinder;
        Label lblTarget;
        ListView lv;
        Button btnUnprotect;
        Button btnUnprotectAll;
        CheckBox chkSelf;
        Label lblStatus;
        NotifyIcon tray;
        System.Windows.Forms.Timer autoTimer;

        bool dragging = false;
        IntPtr highlightHwnd = IntPtr.Zero;

        // 自动隐身名单：进程名（小写，不带 .exe）
        readonly HashSet<string> autoExes = new HashSet<string>();
        // 已隐身的窗口句柄
        readonly HashSet<IntPtr> hiddenHwnds = new HashSet<IntPtr>();

        // ---- 注入改异步后新增的状态（UI 线程与后台线程共享） ----
        // 保护下面四个集合的锁
        readonly object stateLock = new object();
        // 串行化所有注入调用：Injector.LastError 是静态共享的，并发调用会互相覆盖
        readonly object injectLock = new object();
        // 注入失败的退避：exe（小写）-> 下次可重试的时间
        readonly Dictionary<string, DateTime> retryAfter = new Dictionary<string, DateTime>();
        // 连续失败次数：exe（小写）-> 次数
        readonly Dictionary<string, int> failCount = new Dictionary<string, int>();
        // 后台自动补隐身进行中（避免多轮重叠）
        bool autoBusy = false;

        const int MaxAutoRetries = 5;       // 同一 exe 连续失败 5 次后停止自动重试
        const int MaxBackoffSeconds = 300;  // 退避上限 5 分钟

        public MainForm()
        {
            Text = "窗口隐身器";
            ClientSize = new Size(540, 430);
            StartPosition = FormStartPosition.CenterScreen;
            FormBorderStyle = FormBorderStyle.FixedSingle;
            MaximizeBox = false;

            var lblHelp = new Label()
            {
                Text = "按住下面的准星不放，拖到任意窗口上松开，\r\n该窗口就会从截图 / 录屏 / 远程画面里隐身（Win10 2004+ 上截屏里直接透出后面内容），\r\n你自己屏幕上照常显示。之后该程序新开的窗口会自动隐身。",
                Location = new Point(12, 10),
                Size = new Size(516, 48),
            };
            Controls.Add(lblHelp);

            btnFinder = new Button()
            {
                Text = "🎯 按住拖到目标窗口",
                Location = new Point(12, 62),
                Size = new Size(200, 40),
                Font = new Font(Font.FontFamily, 11),
            };
            btnFinder.MouseDown += FinderDown;
            btnFinder.MouseUp += FinderUp;
            btnFinder.MouseMove += FinderMove;
            Controls.Add(btnFinder);

            lblTarget = new Label()
            {
                Text = "当前目标：无",
                Location = new Point(224, 62),
                Size = new Size(304, 40),
                ForeColor = Color.Gray,
            };
            Controls.Add(lblTarget);

            lv = new ListView()
            {
                Location = new Point(12, 112),
                Size = new Size(516, 210),
                View = View.Details,
                FullRowSelect = true,
                GridLines = true,
            };
            lv.Columns.Add("程序", 140);
            lv.Columns.Add("PID", 70);
            lv.Columns.Add("窗口标题", 220);
            lv.Columns.Add("状态", 80);
            Controls.Add(lv);

            btnUnprotect = new Button()
            {
                Text = "取消所选保护",
                Location = new Point(12, 332),
                Size = new Size(120, 30),
            };
            btnUnprotect.Click += (s, e) => UnprotectSelected();
            Controls.Add(btnUnprotect);

            btnUnprotectAll = new Button()
            {
                Text = "全部还原",
                Location = new Point(142, 332),
                Size = new Size(120, 30),
            };
            btnUnprotectAll.Click += (s, e) => UnprotectAll();
            Controls.Add(btnUnprotectAll);

            chkSelf = new CheckBox()
            {
                Text = "连本工具一起隐身",
                Location = new Point(280, 337),
                Size = new Size(160, 24),
            };
            chkSelf.CheckedChanged += (s, e) =>
            {
                // 自己的窗口直接调 API 就行，不用注入
                Native.SetWindowDisplayAffinity(Handle,
                    chkSelf.Checked ? Native.WDA_EXCLUDEFROMCAPTURE : Native.WDA_NONE);
            };
            Controls.Add(chkSelf);

            lblStatus = new Label()
            {
                Text = "就绪",
                Location = new Point(12, 372),
                Size = new Size(516, 44),
                ForeColor = Color.Gray,
            };
            Controls.Add(lblStatus);

            // 最小化到托盘
            tray = new NotifyIcon()
            {
                Icon = SystemIcons.Shield,
                Text = "窗口隐身器（双击还原）",
                Visible = false,
            };
            tray.DoubleClick += (s, e) =>
            {
                Show(); WindowState = FormWindowState.Normal;
                tray.Visible = false;
            };
            Resize += (s, e) =>
            {
                if (WindowState == FormWindowState.Minimized)
                { Hide(); tray.Visible = true; }
            };

            // 每 2 秒：给自动名单里的进程新开窗口补隐身
            autoTimer = new System.Windows.Forms.Timer() { Interval = 2000 };
            autoTimer.Tick += (s, e) => AutoProtectTick();
            autoTimer.Start();

            FormClosing += (s, e) => { UnprotectAll(); tray.Visible = false; tray.Dispose(); };
        }

        // ---------- 准星拖拽（Spy++ 式） ----------
        void FinderDown(object s, MouseEventArgs e)
        {
            if (e.Button != MouseButtons.Left) return;
            dragging = true;
            btnFinder.Capture = true;
            Cursor.Current = Cursors.Cross;
            lblTarget.Text = "当前目标：拖动中…";
        }

        void FinderMove(object s, MouseEventArgs e)
        {
            if (!dragging) return;
            Point pt;
            Native.GetCursorPos(out pt);
            IntPtr w = Native.WindowFromPoint(pt);
            w = Native.GetAncestor(w, Native.GA_ROOT);
            if (w == Handle || w == IntPtr.Zero) w = IntPtr.Zero;

            if (w != highlightHwnd)
            {
                EraseHighlight();
                highlightHwnd = w;
                DrawHighlight();
            }
            lblTarget.Text = "当前目标：" + (w == IntPtr.Zero ? "（无）" : Describe(w));
        }

        void FinderUp(object s, MouseEventArgs e)
        {
            if (!dragging) return;
            dragging = false;
            btnFinder.Capture = false;
            IntPtr target = highlightHwnd; // 先取值，再擦除
            EraseHighlight();

            if (target == IntPtr.Zero) { lblTarget.Text = "当前目标：无"; return; }
            ProtectWindowPick(target);
        }

        string Describe(IntPtr hwnd)
        {
            uint pid; Native.GetWindowThreadProcessId(hwnd, out pid);
            string exe = ExeNameOf(pid);
            var sb = new StringBuilder(256);
            Native.GetWindowText(hwnd, sb, sb.Capacity);
            string title = sb.ToString();
            if (title.Length > 24) title = title.Substring(0, 24) + "…";
            return exe + (string.IsNullOrEmpty(title) ? "" : " - " + title);
        }

        void DrawHighlight()
        {
            if (highlightHwnd == IntPtr.Zero) return;
            Native.RECT rc;
            if (!Native.GetWindowRect(highlightHwnd, out rc)) return;
            IntPtr hdc = Native.GetWindowDC(highlightHwnd);
            if (hdc == IntPtr.Zero) return;
            int w = rc.Right - rc.Left, h = rc.Bottom - rc.Top, t = 5;
            Native.PatBlt(hdc, 0, 0, w, t, Native.DSTINVERT);
            Native.PatBlt(hdc, 0, h - t, w, t, Native.DSTINVERT);
            Native.PatBlt(hdc, 0, 0, t, h, Native.DSTINVERT);
            Native.PatBlt(hdc, w - t, 0, t, h, Native.DSTINVERT);
            Native.ReleaseDC(highlightHwnd, hdc);
        }

        void EraseHighlight()
        {
            // 反色再画一次即擦除
            DrawHighlight();
            highlightHwnd = IntPtr.Zero;
        }

        // ---------- 保护逻辑 ----------
        void ProtectWindowPick(IntPtr hwnd)
        {
            uint pid; Native.GetWindowThreadProcessId(hwnd, out pid);
            string exe = ExeNameOf(pid);
            if (string.IsNullOrEmpty(exe)) { SetStatus("无法识别目标进程"); return; }

            lock (stateLock) { autoExes.Add(exe.ToLower()); }
            IntPtr selfHandle = Handle;
            SetStatus(exe + " 正在隐身…");
            // 注入放后台线程：同步注入最长 5 秒/窗口，直接放 UI 线程会卡界面
            ThreadPool.QueueUserWorkItem(_ =>
            {
                int ok = 0, fail = 0;
                string err = "";
                foreach (var w in TopWindowsOf(pid, selfHandle))
                {
                    lock (stateLock) { if (hiddenHwnds.Contains(w)) { ok++; continue; } }
                    bool done;
                    lock (injectLock)
                    {
                        done = Injector.SetAffinity(w, Native.WDA_EXCLUDEFROMCAPTURE);
                        if (!done) err = Injector.LastError;
                    }
                    if (done) { lock (stateLock) { hiddenHwnds.Add(w); } ok++; }
                    else fail++;
                }
                SafeBeginInvoke(() =>
                {
                    RefreshList();
                    if (fail > 0 && ok == 0)
                        SetStatus("失败：" + err);
                    else
                        SetStatus(string.Format("{0} 已隐身（{1} 个窗口），之后新开的窗口会自动隐身", exe, ok)
                                  + (fail > 0 ? string.Format("，{0} 个失败", fail) : ""));
                });
            });
        }

        void AutoProtectTick()
        {
            List<string> exes;
            lock (stateLock)
            {
                if (autoExes.Count == 0) return;
                if (autoBusy) return; // 上一轮后台补隐身还没跑完，等下一轮
                autoBusy = true;
                exes = new List<string>(autoExes);
            }
            IntPtr selfHandle = Handle;
            // 注入放后台线程：WinForms Timer 回调跑在 UI 线程，同步注入会卡界面
            ThreadPool.QueueUserWorkItem(_ =>
            {
                try
                {
                    bool changed = false;
                    // 清掉已关闭的窗口
                    var dead = new List<IntPtr>();
                    lock (stateLock)
                    {
                        foreach (var h in hiddenHwnds)
                            if (!Native.IsWindow(h)) dead.Add(h);
                        foreach (var h in dead) { hiddenHwnds.Remove(h); changed = true; }
                    }

                    int selfPid;
                    using (Process self = Process.GetCurrentProcess()) { selfPid = self.Id; }

                    var gaveUp = new List<string>();
                    foreach (string exe in exes)
                    {
                        // 退避中：跳过，等下一轮
                        lock (stateLock)
                        {
                            DateTime t;
                            if (retryAfter.TryGetValue(exe, out t) && DateTime.Now < t) continue;
                        }
                        Process[] ps;
                        try { ps = Process.GetProcessesByName(exe); }
                        catch { continue; }
                        int attempted = 0, ok = 0;
                        foreach (var p in ps)
                        {
                            uint pid = (uint)p.Id;
                            if (pid == (uint)selfPid) { p.Dispose(); continue; }
                            foreach (var w in TopWindowsOf(pid, selfHandle))
                            {
                                lock (stateLock) { if (hiddenHwnds.Contains(w)) continue; }
                                attempted++;
                                bool done;
                                lock (injectLock)
                                {
                                    done = Injector.SetAffinity(w, Native.WDA_EXCLUDEFROMCAPTURE);
                                }
                                if (done)
                                {
                                    lock (stateLock) { hiddenHwnds.Add(w); }
                                    ok++; changed = true;
                                }
                            }
                            p.Dispose();
                        }
                        // 失败退避与重试上限：指数退避 10s/20s/40s/80s（上限 5 分钟），
                        // 连续 5 次失败后停止自动重试（用户重新拖准星可再试）
                        lock (stateLock)
                        {
                            if (attempted > 0 && ok == 0)
                            {
                                int n = 0;
                                failCount.TryGetValue(exe, out n);
                                n++;
                                failCount[exe] = n;
                                if (n >= MaxAutoRetries)
                                {
                                    autoExes.Remove(exe);
                                    failCount.Remove(exe);
                                    retryAfter.Remove(exe);
                                    gaveUp.Add(exe);
                                }
                                else
                                {
                                    int delay = Math.Min(10 << (n - 1), MaxBackoffSeconds);
                                    retryAfter[exe] = DateTime.Now.AddSeconds(delay);
                                }
                            }
                            else if (ok > 0)
                            {
                                failCount.Remove(exe);
                                retryAfter.Remove(exe);
                            }
                        }
                    }

                    if (changed || gaveUp.Count > 0)
                    {
                        SafeBeginInvoke(() =>
                        {
                            if (changed) RefreshList();
                            if (gaveUp.Count > 0)
                                SetStatus(string.Join("、", gaveUp.ToArray())
                                    + " 连续 " + MaxAutoRetries + " 次注入失败，已停止自动重试（重新拖准星可再试）");
                        });
                    }
                }
                finally
                {
                    lock (stateLock) { autoBusy = false; }
                }
            });
        }

        // selfHandle 由调用方在 UI 线程传入，避免后台线程访问控件 Handle
        List<IntPtr> TopWindowsOf(uint pid, IntPtr selfHandle)
        {
            var list = new List<IntPtr>();
            IntPtr self = selfHandle;
            Native.EnumWindows((h, l) =>
            {
                uint wpid; Native.GetWindowThreadProcessId(h, out wpid);
                if (wpid != pid) return true;
                if (h == self) return true;
                if (!Native.IsWindowVisible(h)) return true;
                if (Native.GetAncestor(h, Native.GA_ROOT) != h) return true;
                list.Add(h);
                return true;
            }, IntPtr.Zero);
            return list;
        }

        string ExeNameOf(uint pid)
        {
            try
            {
                // Process 对象持有进程句柄，必须 Dispose；准星拖动时每鼠标移动
                // 都会调一次，不释放就是每移动漏一个句柄。
                using (Process p = Process.GetProcessById((int)pid))
                {
                    return p.ProcessName;
                }
            }
            catch { return ""; }
        }

        void UnprotectSelected()
        {
            if (lv.SelectedItems.Count == 0) return;
            var item = lv.SelectedItems[0];
            string exe = item.SubItems[0].Text.ToLower();
            uint pid = uint.Parse(item.SubItems[1].Text);
            foreach (var w in TopWindowsOf(pid, Handle))
            {
                Injector.SetAffinity(w, Native.WDA_NONE);
                lock (stateLock) { hiddenHwnds.Remove(w); }
            }
            lock (stateLock) { autoExes.Remove(exe); }
            RefreshList();
            SetStatus(exe + " 已还原");
        }

        void UnprotectAll()
        {
            // 关闭窗口时调用，保持同步（后台还原可能赶不上进程退出），
            // 关闭时短暂卡顿可接受
            List<IntPtr> snapshot;
            lock (stateLock)
            {
                snapshot = new List<IntPtr>(hiddenHwnds);
                hiddenHwnds.Clear();
                autoExes.Clear();
                failCount.Clear();
                retryAfter.Clear();
            }
            foreach (var h in snapshot)
                if (Native.IsWindow(h)) Injector.SetAffinity(h, Native.WDA_NONE);
            RefreshList();
        }

        void RefreshList()
        {
            // 后台线程也会改 hiddenHwnds，先快照再枚举，避免"集合已修改"异常
            List<IntPtr> snapshot;
            lock (stateLock) { snapshot = new List<IntPtr>(hiddenHwnds); }
            lv.Items.Clear();
            foreach (var h in snapshot)
            {
                if (!Native.IsWindow(h)) continue;
                uint pid; Native.GetWindowThreadProcessId(h, out pid);
                var sb = new StringBuilder(256);
                Native.GetWindowText(h, sb, sb.Capacity);
                string title = sb.ToString();
                if (title == "") title = "(无标题)";
                var item = new ListViewItem(new string[]
                {
                    ExeNameOf(pid), pid.ToString(), title, "隐身中"
                });
                lv.Items.Add(item);
            }
        }

        void SetStatus(string s) { lblStatus.Text = s; }

        // 后台线程回 UI 线程的安全封装：窗口已关闭时 BeginInvoke 会抛异常，直接忽略
        void SafeBeginInvoke(MethodInvoker action)
        {
            try
            {
                if (!IsDisposed && IsHandleCreated) BeginInvoke(action);
            }
            catch { /* 窗口已关闭 */ }
        }
    }

    // ---------------- 入口 ----------------
    static class Program
    {
        [STAThread]
        static void Main()
        {
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            Application.Run(new MainForm());
        }
    }
}
