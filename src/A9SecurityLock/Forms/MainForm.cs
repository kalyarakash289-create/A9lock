using System.Runtime.InteropServices;
using A9SecurityLock.Models;
using A9SecurityLock.Security;
using A9SecurityLock.Services;
using A9SecurityLock.Storage;

namespace A9SecurityLock.Forms;

/// <summary>
/// Application shell: dark sidebar navigation hosting the eight pages, tray icon,
/// lock orchestration (monitor -> overlay), session-change handling and single owner
/// of all services. All dashboard values come from live service state — nothing is faked.
/// </summary>
public sealed class MainForm : Form
{
    [DllImport("user32.dll")] private static extern bool SetForegroundWindow(IntPtr hWnd);

    private readonly ConfigStore _store;
    private readonly AuthService _auth;
    private readonly SecurityLogger _logger;
    private readonly RuleManager _rules;
    private readonly LockMonitor _monitor;
    private readonly StartupManager _startup = new();

    private readonly NotifyIcon _tray;
    private readonly Dictionary<string, UserControl> _pages = new();
    private readonly List<Button> _navButtons = new();
    private Label _statusLabel = new();
    private string? _currentPageKey;
    private bool _reallyExit;
    private bool _lockScreenActive;

    public MainForm(ConfigStore store, AuthService auth, SecurityLogger logger)
    {
        _store = store;
        _auth = auth;
        _logger = logger;
        _rules = new RuleManager(auth, logger);
        _monitor = new LockMonitor(_rules, auth, logger); // captures UI SynchronizationContext here

        Text = "A9 Security Lock";
        ClientSize = new Size(1000, 640);
        MinimumSize = new Size(860, 560);
        StartPosition = FormStartPosition.CenterScreen;
        BackColor = Theme.BgDark;
        DoubleBuffered = true;
        Font = Theme.FontBody;
        try { Icon = Icon.FromHandle(((Bitmap)Theme.RenderLogoBitmap(32).GetHicon()).GetHicon() /* leak-free below */); }
        catch { }
        ApplyAppIcon();

        // ---------- first run / authentication gate ----------
        if (_auth.IsFirstRun)
        {
            using var setup = new WelcomeSetupForm(_auth);
            if (setup.ShowDialog(this) != DialogResult.OK)
            {
                _logger.Info("First-time setup cancelled; application will exit.");
                Environment.Exit(0); // explicit, safe exit before any monitoring exists
                return;
            }
        }
        else
        {
            using var login = new AuthenticationForm(_auth, requirePassword: true,
                title: "Unlock A9 Security Lock", showSkip: true);
            var res = login.ShowDialog(this);
            if (res == DialogResult.Abort)
            {
                // Corrupt-config path chosen by user: reset and restart setup.
                ResetConfiguration(silentConfirm: true);
                return;
            }
            if (res != DialogResult.OK)
            {
                Environment.Exit(0);
                return;
            }
        }

        BuildShell();
        BuildPages();
        Navigate("dashboard");

        // ---------- tray ----------
        _tray = new NotifyIcon
        {
            Text = "A9 Security Lock",
            Icon = AppIco(),
            Visible = true,
        };
        var trayMenu = new ContextMenuStrip { BackColor = Theme.BgPanel, ForeColor = Theme.TextMain };
        AddTrayItem(trayMenu, "Open A9 Security Lock", () => { Show(); WindowState = FormWindowState.Normal; Activate(); });
        AddTrayItem(trayMenu, "Lock now", () => TriggerLockAll("manual (tray)"));
        AddTrayItem(trayMenu, "Pause / Resume monitoring", ToggleMonitoring);
        trayMenu.Items.Add(new ToolStripSeparator());
        AddTrayItem(trayMenu, "Exit", ExitApplication);
        _tray.ContextMenuStrip = trayMenu;
        _tray.DoubleClick += (_, _) => { Show(); WindowState = FormWindowState.Normal; Activate(); };

        // ---------- monitor wiring ----------
        _monitor.LockRequired += rule => ShowRuleLock(rule, foregroundOnly: true);
        _monitor.IdleElapsed += () => TriggerLockAll("idle timeout");
        _monitor.StateChanged += UpdateStatusBar;
        _rules.RulesChanged += OnRulesChanged;

        if (!_auth.Config.Settings.MonitoringPaused && _rules.EnabledCount > 0)
            _monitor.Start();
        else
            _logger.Info("Monitoring not started (paused or no enabled rules).");

        _logger.Info("A9 Security Lock started.");
        UpdateStatusBar();
    }

    // ==================== shell ====================

    private void BuildShell()
    {
        var sidebar = new Panel { Dock = DockStyle.Left, Width = 210, BackColor = Theme.BgSidebar };
        Controls.Add(sidebar);

        var logo = new PictureBox
        {
            Image = Theme.RenderLogoBitmap(56),
            SizeMode = PictureBoxSizeMode.AutoSize,
            Location = new Point(24, 18),
        };
        sidebar.Controls.Add(logo);

        var brand = new Label
        {
            Text = "A9 Security Lock",
            Font = new Font("Segoe UI", 11.5f, FontStyle.Bold),
            ForeColor = Theme.TextMain,
            Location = new Point(86, 30),
            AutoSize = true,
        };
        sidebar.Controls.Add(brand);
        var tagline = new Label
        {
            Text = "v1.0.0 · local-only",
            Font = Theme.FontBody,
            ForeColor = Theme.TextDim,
            Location = new Point(87, 52),
            AutoSize = true,
        };
        sidebar.Controls.Add(tagline);

        string[,] items =
        {
            { "dashboard",  "📊  Dashboard" },
            { "manager",    "🛡️  App Lock Manager" },
            { "locked",     "🔒  Locked Applications" },
            { "settings",   "⚙️  Security Settings" },
            { "log",        "📝  Activity Log" },
            { "about",      "ℹ️  About" },
        };

        int y = 96;
        for (int i = 0; i < items.GetLength(0); i++)
        {
            var btn = MakeNavButton(items[i, 1]);
            string key = items[i, 0];
            btn.Tag = key;
            btn.Location = new Point(12, y);
            btn.Click += (_, _) => Navigate((string)((Button)sender!).Tag!);
            _navButtons.Add(btn);
            sidebar.Controls.Add(btn);
            y += 44;
        }

        var bottomLine = new Panel { Dock = DockStyle.Bottom, Height = 1, BackColor = Theme.BorderSoft };
        sidebar.Controls.Add(bottomLine);

        _statusLabel = new Label
        {
            Dock = DockStyle.Bottom,
            Height = 34,
            ForeColor = Theme.TextDim,
            Font = Theme.FontBody,
            TextAlign = ContentAlignment.MiddleLeft,
            Padding = new Padding(14, 0, 0, 0),
        };
        sidebar.Controls.Add(_statusLabel);
        _statusLabel.BringToFront();

        var host = new Panel { Name = "PageHost", Dock = DockStyle.Fill, BackColor = Theme.BgDark, Padding = new Padding(18) };
        Controls.Add(host);
        host.BringToFront();
    }

    private static Button MakeNavButton(string text)
    {
        var b = new Button
        {
            Text = text,
            Size = new Size(186, 38),
            FlatStyle = FlatStyle.Flat,
            BackColor = Theme.BgSidebar,
            ForeColor = Theme.TextMain,
            TextAlign = ContentAlignment.MiddleLeft,
            Font = Theme.FontBody,
            TabStop = true,
        };
        b.FlatAppearance.BorderSize = 0;
        b.FlatAppearance.MouseOverBackColor = Color.FromArgb(34, 40, 50);
        return b;
    }

    private void Navigate(string key)
    {
        if (!_pages.TryGetValue(key, out var page)) return;
        var host = Controls["PageHost"];

        if (_currentPageKey != null && _pages.TryGetValue(_currentPageKey, out var old))
            old.Visible = false;

        if (!host.Controls.Contains(page))
        {
            page.Dock = DockStyle.Fill;
            host.Controls.Add(page);
        }
        page.Visible = true;
        page.BringToFront();
        _currentPageKey = key;

        foreach (var nb in _navButtons)
        {
            bool active = (string)nb.Tag! == key;
            nb.BackColor = active ? Color.FromArgb(38, 52, 74) : Theme.BgSidebar;
            nb.ForeColor = active ? Theme.AccentCyan : Theme.TextMain;
        }

        if (page is IDynamicRefresh r) r.RefreshData();
    }

    private void BuildPages()
    {
        _pages["dashboard"] = new DashboardPage(this, _auth, _rules, _monitor, Navigate);
        _pages["manager"] = new AppLockManagerPage(_auth, _rules, _logger, TestRule);
        _pages["locked"] = new LockedApplicationsPage(_rules, _monitor);
        _pages["settings"] = new SecuritySettingsPage(this, _store, _auth, _rules, _logger, _startup, _monitor, TriggerLockAll, ExitApplication);
        _pages["log"] = new ActivityLogPage(_logger);
        _pages["about"] = new AboutPage();
    }

    // ==================== locking ====================

    /// <summary>Shows the password overlay over the foreground window of a matched rule.</summary>
    private void ShowRuleLock(AppLockRule rule, bool foregroundOnly)
    {
        if (_lockScreenActive || IsDisposed) return;
        if (!rule.Enabled) return;

        IntPtr fg = NativeMethods.GetForegroundWindow();
        Rectangle bounds = Screen.PrimaryScreen?.Bounds ?? Bounds;
        uint pid = 0;
        string? exeLower = null;

        if (fg != IntPtr.Zero && NativeMethods.GetWindowThreadProcessId(fg, out pid) && pid != 0)
        {
            exeLower = NativeMethods.GetProcessExeName(pid);
            if (GetWindowRect(fg, out var wr)) bounds = wr;
        }

        // If the foreground app isn't a locked exe, fall back to full-screen lock on our own window area.
        bool fgIsTarget = exeLower != null &&
            string.Equals(exeLower, Path.GetFileName(rule.ExecutablePath), StringComparison.OrdinalIgnoreCase);
        if (!fgIsTarget) bounds = Screen.PrimaryScreen?.Bounds ?? bounds;

        _lockScreenActive = true;
        var screen = new LockScreenForm(_auth, bounds, rule, exeLower,
            onUnlocked: (info) =>
            {
                _lockScreenActive = false;
                if (info.exe != null) _monitor.SuppressFor(info.exe, 15);
                _logger.Log(SecurityEventCategory.Unlock, $"Unlocked \"{rule.DisplayName}\".");
                UpdateStatusBar();
            },
            onCancelled: () =>
            {
                _lockScreenActive = false;
                // Safe recovery: keep enforcing — re-show after short grace so user can retry.
                _logger.Log(SecurityEventCategory.Warning, $"Lock for \"{rule.DisplayName}\" dismissed without unlocking; re-arming.");
                BeginInvoke(new Action(() =>
                {
                    if (!_lockScreenActive && rule.Enabled && !_auth.Config.Settings.MonitoringPaused)
                        ShowRuleLock(rule, foregroundOnly: true);
                }));
            });
        screen.Show(this);
        SetForegroundWindow(screen.Handle);
    }

    /// <summary>Locks every enabled rule at once (manual "Lock now", idle, or session unlock).</summary>
    public void TriggerLockAll(string reason)
    {
        if (_lockScreenActive) return;
        if (_rules.EnabledCount == 0)
        {
            MessageBox.Show(this,
                "No enabled lock rules are configured yet.\nAdd an application in App Lock Manager first.",
                "Nothing to lock", MessageBoxButtons.OK, MessageBoxIcon.Information);
            return;
        }
        _monitor.TriggerManualLockAll(reason);
        // Show one consolidated session lock instead of stacking N overlays.
        ShowSessionLock(reason);
    }

    private void ShowSessionLock(string reason)
    {
        if (_lockScreenActive) return;
        _lockScreenActive = true;
        var bounds = Screen.PrimaryScreen?.Bounds ?? Bounds;
        var names = string.Join(", ", _rules.EnabledRules.Select(r => r.DisplayName).Take(6));
        var screen = new LockScreenForm(_auth, bounds, rule: null, exeNameLower: null,
            onUnlocked: info =>
            {
                _lockScreenActive = false;
                _logger.Log(SecurityEventCategory.Unlock, $"Session unlocked ({reason}). Rules released: {names}");
                foreach (var r in _rules.EnabledRules)
                    _monitor.SuppressFor(Path.GetFileName(r.ExecutablePath).ToLowerInvariant(), 15);
                UpdateStatusBar();
            },
            onCancelled: () =>
            {
                _lockScreenActive = false;
                _logger.Log(SecurityEventCategory.Warning, $"Session lock dismissed without unlocking ({reason}); re-arming.");
                BeginInvoke(new Action(() => { if (!_lockScreenActive) ShowSessionLock(reason); }));
            });
        screen.Show(this);
        SetForegroundWindow(screen.Handle);
    }

    /// <summary>"Test rule" flow used by the manager page: requires auth, then shows a demo overlay for 5 s.</summary>
    public bool TestRule(AppLockRule rule)
    {
        using var ask = new AuthenticationForm(_auth, requirePassword: true,
            title: $"Authenticate to test rule \"{rule.DisplayName}\"", showSkip: false);
        if (ask.ShowDialog(this) != DialogResult.OK) return false;

        var bounds = Rectangle.Inflate(Bounds, -60, -60);
        var demo = new LockScreenForm(_auth, bounds, rule, exeNameLower: null,
            onUnlocked: info => { _lockScreenActive = false; _logger.Log(SecurityEventCategory.Unlock, $"Test overlay for \"{rule.DisplayName}\" completed."); },
            onCancelled: () => _lockScreenActive = false);
        _lockScreenActive = true;
        demo.Show(this);
        SetForegroundWindow(demo.Handle);
        _logger.Log(SecurityEventCategory.Info, $"Test overlay shown for rule \"{rule.DisplayName}\".");
        return true;
    }

    // ==================== misc ====================

    /// <summary>Prompts for the master password (used to resume monitoring, etc.). Returns true on success.</summary>
    public bool AuthenticateOut(string purpose)
    {
        using var f = new AuthenticationForm(_auth, requirePassword: true, title: purpose, showSkip: false);
        return f.ShowDialog(this) == DialogResult.OK;
    }

    public void ToggleMonitoring()
    {
        var s = _auth.Config.Settings;
        if (s.MonitoringPaused)
        {
            if (!AuthenticateOut("Authenticate to resume monitoring")) return;
            s.MonitoringPaused = false;
            _auth.SaveConfig();
            _monitor.Start();
            _logger.Log(SecurityEventCategory.Monitoring, "Monitoring resumed after authentication.");
        }
        else
        {
            s.MonitoringPaused = true;
            _auth.SaveConfig();
            _monitor.Stop();
            _logger.Log(SecurityEventCategory.Monitoring, "Monitoring paused by user.");
        }
        UpdateStatusBar();
    }

    internal void UpdateStatusBar()
    {
        if (_statusLabel.InvokeRequired) { _statusLabel.BeginInvoke(UpdateStatusBar); return; }
        var snap = _monitor.GetSnapshot();
        _statusLabel.Text = snap.Paused || !snap.Running
            ? "● Monitoring: PAUSED"
            : $"● Monitoring: ACTIVE ({snap.EnabledRules} rule{(snap.EnabledRules == 1 ? "" : "s")})";
        _statusLabel.ForeColor = snap.Paused || !snap.Running ? Theme.DangerRed : Theme.SuccessGrn;
    }

    private void OnRulesChanged()
    {
        UpdateStatusBar();
        // Keep timer period in sync with settings; start/stop as needed.
        if (!_auth.Config.Settings.MonitoringPaused && _rules.EnabledCount > 0 && !_monitor.IsRunning)
            _monitor.Start();
    }

    public void ResetConfiguration(bool silentConfirm)
    {
        if (!silentConfirm)
        {
            var r = MessageBox.Show(this,
                "This deletes ALL A9 Security Lock configuration:\n" +
                "• master password credential\n• lock rules\n• settings\n\n" +
                "Your applications and files are NOT touched.\n\n" +
                "Type the app's protection back only via Windows re-setup.\nReset now?",
                "Reset configuration?", MessageBoxButtons.YesNo, MessageBoxIcon.Warning,
                MessageBoxDefaultButton.Button2);
            if (r != DialogResult.Yes) return;
            if (!AuthenticateOut("Authenticate to reset configuration")) return;
        }

        _monitor.Dispose();
        _store.DeleteAll();
        _logger.Log(SecurityEventCategory.Warning, "Configuration was reset by the user.");
        _reallyExit = true;

        // Relaunch ourselves so first-run setup starts cleanly.
        try
        {
            if (Environment.ProcessPath is string p && File.Exists(p))
                System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(p) { UseShellExecute = true });
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, "Restart failed (" + ex.Message + "). Please start A9 Security Lock again manually.",
                "Reset complete", MessageBoxButtons.OK, MessageBoxIcon.Information);
        }
        ExitApplication();
    }

    public void OpenConfigFolder()
    {
        try
        {
            _store.EnsureDirectory();
            System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo("explorer.exe", $"\"{_store.Directory}\"") { UseShellExecute = true });
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, "Could not open the folder: " + ex.Message, "Error",
                MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
    }

    private void AddTrayItem(ContextMenuStrip menu, string text, Action act)
    {
        var item = new ToolStripMenuItem(text);
        item.Click += (_, _) => act();
        menu.Items.Add(item);
    }

    private void ApplyAppIcon()
    {
        try
        {
            using var bmp = Theme.RenderLogoBitmap(32);
            IntPtr hicon = bmp.GetHicon();
            Icon = Icon.FromHandle(hicon);
            // We intentionally keep the handle for the form lifetime; process exit releases it.
        }
        catch { }
    }

    private Icon AppIco()
    {
        using var bmp = Theme.RenderLogoBitmap(32);
        return Icon.FromHandle(bmp.GetHicon());
    }

    [DllImport("user32.dll")] private static extern bool GetWindowRect(IntPtr hWnd, out RECT lpRect);
    [StructLayout(LayoutKind.Sequential)] private struct RECT { public int Left, Top, Right, Bottom; }
    private static bool GetWindowRect(IntPtr h, out Rectangle r)
    {
        bool ok = GetWindowRect(h, out RECT rc);
        r = new Rectangle(rc.Left, rc.Top, Math.Max(1, rc.Right - rc.Left), Math.Max(1, rc.Bottom - rc.Top));
        return ok;
    }

    // ---------------- window / tray behaviour ----------------

    protected override void OnFormClosing(FormClosingEventArgs e)
    {
        bool minimizeToTray = _auth.Config.Settings.MinimizeToTrayOnClose && !_reallyExit;

        if (!_reallyExit && e.CloseReason == CloseReason.UserClosing)
        {
            if (minimizeToTray)
            {
                e.Cancel = true;
                Hide();
                _tray.ShowBalloonTip(1500, "A9 Security Lock",
                    "Still running in the notification area. Monitoring continues.", ToolTipIcon.Info);
                return;
            }
            // Not minimizing: closing the UI stops enforcement entirely (documented behavior).
            var ans = MessageBox.Show(this,
                "Close A9 Security Lock?\n\nWhile closed, application locks are NOT enforced.\n" +
                "(You can enable \"Minimize to tray\" in Security Settings.)",
                "Close A9 Security Lock", MessageBoxButtons.YesNo, MessageBoxIcon.Question);
            if (ans != DialogResult.Yes) { e.Cancel = true; return; }
            _reallyExit = true;
        }

        if (_reallyExit)
        {
            // Safe shutdown order: stop timers/events first, then dispose resources.
            _monitor.LockRequired -= null!; // no-op guard against accidental double wiring patterns
        }

        base.OnFormClosing(e);
    }

    protected override void OnFormClosed(FormClosedEventArgs e)
    {
        _tray.Visible = false;
        _tray.Dispose();
        _monitor.Dispose();
        base.OnFormClosed(e);
        _logger.Info("A9 Security Lock stopped.");
    }

    public void ExitApplication()
    {
        _reallyExit = true;
        Close();
    }

    protected override void SetVisibleCore(bool value)
    {
        // Ensure shell is built before first paint when launched hidden.
        base.SetVisibleCore(value);
    }

    // Session change notifications (WM_WTSSESSION_CHANGE) handled via native sink below.
    protected override void WndProc(ref Message m)
    {
        if (m.Msg == NativeMethods.WM_WTSSESSION_CHANGE)
        {
            int evt = m.WParam.ToInt32();
            if (evt == NativeMethods.WTS_SESSION_UNLOCK &&
                _auth.Config.Settings.LockOnSessionUnlock &&
                !_auth.Config.Settings.MonitoringPaused)
            {
                _logger.Log(SecurityEventCategory.Monitoring, "Workstation unlocked — applying configured locks.");
                TriggerLockAll("session unlock");
            }
            else if (evt == NativeMethods.WTS_SESSION_LOCK)
            {
                _logger.Log(SecurityEventCategory.Monitoring, "Workstation locked (Windows did its job).");
            }
        }
        base.WndProc(ref m);
    }

    protected override void OnHandleCreated(EventArgs e)
    {
        base.OnHandleCreated(e);
        try { NativeMethods.WTSRegisterSessionNotification(Handle, NativeMethods.NOTIFY_FOR_ALL_SESSIONS); }
        catch { /* non-Windows dev box */ }
    }

    protected override void OnHandleDestroyed(EventArgs e)
    {
        try { NativeMethods.WTSUnRegisterSessionNotification(Handle); } catch { }
        base.OnHandleDestroyed(e);
    }
}

/// <summary>Pages that want fresh data each time they're opened implement this.</summary>
public interface IDynamicRefresh { void RefreshData(); }
