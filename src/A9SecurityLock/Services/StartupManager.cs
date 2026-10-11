using System.Runtime.InteropServices;
using Microsoft.Win32;

namespace A9SecurityLock.Services;

/// <summary>
/// Manages the per-user "start with Windows" Run key. Only ever called after the user
/// explicitly consents in the Security Settings page (HKCU — no administrator rights needed).
/// </summary>
public sealed class StartupManager
{
    private const string RunKeyPath = @"Software\Microsoft\Windows\CurrentVersion\Run";
    private const string ValueName = "A9SecurityLock";

    public static bool IsSupported => OperatingSystem.IsWindows();

    public bool IsEnabled()
    {
        if (!IsSupported) return false;
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(RunKeyPath);
            return key?.GetValue(ValueName) != null;
        }
        catch (Exception ex) when (ex is SecurityException or IOException or UnauthorizedAccessException)
        {
            return false;
        }
    }

    /// <summary>Sets/clears the HKCU Run value pointing at the current executable.</summary>
    public bool SetEnabled(bool enabled, out string error)
    {
        error = "";
        if (!IsSupported)
        {
            error = "Startup registration is only available on Windows.";
            return false;
        }

        try
        {
            using var key = Registry.CurrentUser.CreateSubKey(RunKeyPath);
            if (key == null)
            {
                error = "Could not open the Windows startup registry key.";
                return false;
            }

            if (enabled)
            {
                string exe = Environment.ProcessPath ?? Application.ExecutablePath;
                key.SetValue(ValueName, $"\"{exe}\"");
            }
            else
            {
                if (key.GetValue(ValueName) != null) key.DeleteValue(ValueName, throwOnMissingValue: false);
            }
            return true;
        }
        catch (Exception ex) when (ex is SecurityException or IOException or UnauthorizedAccessException)
        {
            error = "Registry access failed: " + ex.Message;
            return false;
        }
    }
}
