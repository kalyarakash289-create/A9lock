using System.Runtime.InteropServices;

namespace A9SecurityLock.Services;

/// <summary>
/// Thin, documented wrappers over the Win32 APIs used by A9 Security Lock.
/// Every P/Invoke here is a public, well-documented Windows API (see MSDN).
/// Nothing in this class hides, injects into, or manipulates other processes.
/// </summary>
internal static class NativeMethods
{
    // ---------- Window / foreground queries (user32.dll) ----------

    [DllImport("user32.dll", SetLastError = false)]
    public static extern IntPtr GetForegroundWindow();

    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool GetWindowThreadProcessId(IntPtr hWnd, out uint lpdwProcessId);

    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool IsWindowVisible(IntPtr hWnd);

    [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern int GetWindowTextW(IntPtr hWnd, System.Text.StringBuilder lpString, int nMaxCount);

    [DllImport("user32.dll", SetLastError = true)]
    public static extern int GetWindowTextLengthW(IntPtr hWnd);

    // ---------- Idle time (GetLastInputInfo) ----------

    [StructLayout(LayoutKind.Sequential)]
    public struct LASTINPUTINFO
    {
        public uint cbSize;
        public uint dwTime;
    }

    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool GetLastInputInfo(ref LASTINPUTINFO plii);

    /// <summary>Returns seconds since the last user input event on this session, or 0 if unavailable.</summary>
    public static double GetIdleSeconds()
    {
        try
        {
            var lii = new LASTINPUTINFO { cbSize = (uint)Marshal.SizeOf<LASTINPUTINFO>() };
            if (!GetLastInputInfo(ref lii)) return 0;
            // Environment.TickCount wraps ~49.7 days; unchecked subtraction still yields correct deltas.
            uint delta = unchecked((uint)Environment.TickCount - lii.dwTime);
            return delta / 1000.0;
        }
        catch
        {
            return 0;
        }
    }

    // ---------- Process toolhelp snapshot (kernel32.dll) ----------

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct PROCESSENTRY32W
    {
        public uint dwSize;
        public uint cntUsage;
        public uint th32ProcessID;
        public IntPtr th32DefaultHeapID;
        public uint th32ModuleID;
        public uint cntThreads;
        public uint th32ParentProcessID;
        public long pcPriClassBase;
        public uint dwFlags;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
        public string szExeFile;
    }

    public const uint TH32CS_SNAPPROCESS = 0x00000002;
    public const uint INVALID_HANDLE_VALUE32 = 0xFFFFFFFFU;

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern IntPtr CreateToolhelp32Snapshot(uint dwFlags, uint th32ProcessID);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool Process32First(IntPtr hSnapshot, ref PROCESSENTRY32W lppe);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool Process32Next(IntPtr hSnapshot, ref PROCESSENTRY32W lppe);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool CloseHandle(IntPtr hObject);

    /// <summary>
    /// Returns the base exe file names (lower-cased) of all running processes whose PID equals
    /// <paramref name="processId"/> — via a read-only process snapshot. Used to match a rule's
    /// executable against the process owning the current foreground window.
    /// </summary>
    public static string? GetProcessExeName(uint processId)
    {
        IntPtr snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        // CreateToolhelp32Snapshot returns INVALID_HANDLE_VALUE (-1) on failure.
        if (snap.ToInt64() == -1) return null;

        try
        {
            var entry = new PROCESSENTRY32W { dwSize = (uint)Marshal.SizeOf<PROCESSENTRY32W>() };
            if (!Process32First(snap, ref entry)) return null;
            do
            {
                if (entry.th32ProcessID == processId)
                    return entry.szExeFile?.ToLowerInvariant();
            }
            while (Process32Next(snap, ref entry));
            return null;
        }
        finally
        {
            CloseHandle(snap);
        }
    }

    // ---------- WTS session register notification (wtsapi32.dll) ----------

    public const int WM_WTSSESSION_CHANGE = 0x02B1;
    public const int WTS_SESSION_LOCK = 7;
    public const int WTS_SESSION_UNLOCK = 8;
    public const int NOTIFY_FOR_ALL_SESSIONS = 1;

    [DllImport("wtsapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool WTSRegisterSessionNotification(IntPtr hWnd, int dwFlags);

    [DllImport("wtsapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool WTSUnRegisterSessionNotification(IntPtr hWnd);

    // ---------- ShowWindow helpers for target windows ----------

    public const int SW_MINIMIZE = 6;

    [DllImport("user32.dll", SetLastError = true, ShowLastError = false)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool ShowWindowAsync(IntPtr hWnd, int nCmdShow);
}
