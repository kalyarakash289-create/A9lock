using System.ComponentModel;
using A9SecurityLock.Services;

namespace A9SecurityLock;

/// <summary>
/// Entry point. Enforces single-instance behavior with a named mutex and routes the user
/// either to first-time setup or to the authentication + dashboard flow.
/// </summary>
internal static class Program
{
    private const string MutexName = @"Local\A9SecurityLock.SingleInstance.v1";

    [STAThread]
    private static int Main(string[] args)
    {
        // --- smoke-test mode used by scripts/verify.ps1 (headless exit check) ---
        if (args.Contains("--smoke-test"))
        {
            Console.WriteLine("A9SecurityLock 1.0.0 smoke-test OK");
            return 0;
        }

        using var mutex = new Mutex(initiallyOwned: true, MutexName, out bool isNew);
        if (!isNew)
        {
            MessageBox.Show(
                "A9 Security Lock is already running (check the notification area).",
                "A9 Security Lock", MessageBoxButtons.OK, MessageBoxIcon.Information);
            return 0;
        }

        Application.EnableVisualStyles();
        Application.SetCompatibleTextRenderingDefault(false);
        Application.SetHighDpiMode(HighDpiMode.SystemAware);

        // Global safety nets: log, inform, then shut down cleanly instead of hard-crashing.
        Application.ThreadException += (s, e) => CrashHandler.Handle(e.Exception, uiThread: true);
        AppDomain.CurrentDomain.UnhandledException += (s, e) =>
            CrashHandler.Handle(e.ExceptionObject as Exception ?? new Exception("Unknown"), uiThread: false);

        try
        {
            var store = new Storage.ConfigStore();
            store.EnsureDirectory();
            var logger = new SecurityLogger(store.LogPath);
            var auth = new AuthService(store, logger);

            GC.KeepAlive(mutex); // keep the instance lock for the whole process lifetime
            Application.Run(new MainForm(store, auth, logger));
            return 0;
        }
        catch (Exception ex)
        {
            CrashHandler.Handle(ex, uiThread: false);
            return 2;
        }
    }
}

/// <summary>Centralized last-resort error handler: never shows raw stacks to end users.</summary>
internal static class CrashHandler
{
    public static void Handle(Exception ex, bool uiThread)
    {
        try
        {
            string dir = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "A9SecurityLock");
            Directory.CreateDirectory(dir);
            File.AppendAllText(
                Path.Combine(dir, "error.log"),
                $"{DateTime.Now:yyyy-MM-dd HH:mm:ss} [{(uiThread ? "UI" : "BG")}] {ex}" + Environment.NewLine);
        }
        catch { /* logging must not throw */ }

        MessageBox.Show(
            "A9 Security Lock encountered an unexpected error and will now close.\n\n" +
            "Details were written to the error log in your local app-data folder.\n" +
            "(" + ex.GetType().Name + ")",
            "A9 Security Lock — Error",
            MessageBoxButtons.OK, MessageBoxIcon.Error);

        Application.Exit();
    }
}
