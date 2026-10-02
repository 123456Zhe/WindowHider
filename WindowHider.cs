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

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool Module32First(IntPtr hSnapshot, ref MODULEENTRY32 lpme);

        [DllImport("kernel32.dll", SetLastError = true)]
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

                Native.WaitForSingleObject(hThread, 5000);
                uint exitCode = 0;
                Native.GetExitCodeThread(hThread, out exitCode);
                Native.CloseHandle(hThread);
                Native.VirtualFreeEx(hProcess, remote, 0, Native.MEM_RELEASE);

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

            autoExes.Add(exe.ToLower());
            int ok = 0, fail = 0;
            foreach (var w in TopWindowsOf(pid))
            {
                if (hiddenHwnds.Contains(w)) { ok++; continue; }
                if (Injector.SetAffinity(w, Native.WDA_EXCLUDEFROMCAPTURE))
                { hiddenHwnds.Add(w); ok++; }
                else fail++;
            }
            RefreshList();
            if (fail > 0 && ok == 0)
                SetStatus("失败：" + Injector.LastError);
            else
                SetStatus(string.Format("{0} 已隐身（{1} 个窗口），之后新开的窗口会自动隐身", exe, ok)
                          + (fail > 0 ? string.Format("，{0} 个失败", fail) : ""));
        }

        void AutoProtectTick()
        {
            if (autoExes.Count == 0) return;
            bool changed = false;
            // 清掉已关闭的窗口
            var dead = new List<IntPtr>();
            foreach (var h in hiddenHwnds)
                if (!Native.IsWindow(h)) dead.Add(h);
            foreach (var h in dead) { hiddenHwnds.Remove(h); changed = true; }

            foreach (string exe in autoExes)
            {
                Process[] ps;
                try { ps = Process.GetProcessesByName(exe); }
                catch { continue; }
                foreach (var p in ps)
                {
                    uint pid = (uint)p.Id;
                    if (pid == (uint)Process.GetCurrentProcess().Id) continue;
                    foreach (var w in TopWindowsOf(pid))
                    {
                        if (hiddenHwnds.Contains(w)) continue;
                        if (Injector.SetAffinity(w, Native.WDA_EXCLUDEFROMCAPTURE))
                        { hiddenHwnds.Add(w); changed = true; }
                    }
                    p.Dispose();
                }
            }
            if (changed) RefreshList();
        }

        List<IntPtr> TopWindowsOf(uint pid)
        {
            var list = new List<IntPtr>();
            IntPtr self = Handle;
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
            try { return Process.GetProcessById((int)pid).ProcessName; }
            catch { return ""; }
        }

        void UnprotectSelected()
        {
            if (lv.SelectedItems.Count == 0) return;
            var item = lv.SelectedItems[0];
            string exe = item.SubItems[0].Text.ToLower();
            uint pid = uint.Parse(item.SubItems[1].Text);
            foreach (var w in TopWindowsOf(pid))
            {
                Injector.SetAffinity(w, Native.WDA_NONE);
                hiddenHwnds.Remove(w);
            }
            autoExes.Remove(exe);
            RefreshList();
            SetStatus(exe + " 已还原");
        }

        void UnprotectAll()
        {
            foreach (var h in new List<IntPtr>(hiddenHwnds))
                if (Native.IsWindow(h)) Injector.SetAffinity(h, Native.WDA_NONE);
            hiddenHwnds.Clear();
            autoExes.Clear();
            RefreshList();
        }

        void RefreshList()
        {
            lv.Items.Clear();
            foreach (var h in hiddenHwnds)
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
