using A9SecurityLock.Models;

namespace A9SecurityLock.Services;

/// <summary>Read-only view of monitoring state for the UI (dashboard status, etc.).</summary>
public sealed record MonitorSnapshot(
    bool Running,
    bool Paused,
    int EnabledRules,
    double IdleSeconds,
    DateTime? LastTriggerUtc,
    string? LastTriggerRuleName);

/// <summary>
/// Lightweight foreground-application monitor.
/// - Single System.Threading.Timer on the UI thread (no extra threads, no busy loops).
/// - Samples GetForegroundWindow -> PID -> exe name via documented Win32 APIs.
/// - Fires LockRequired when an enabled rule matches the foreground app.
/// - Tracks idle time via GetLastInputInfo and fires IdleElapsed once per idle period.
/// The owner (MainForm) is responsible for showing the lock overlay and for calling
/// SuppressFor() after a successful unlock so the same window isn't re-locked instantly.
/// </summary>
public sealed class LockMonitor : IDisposable
{
    private readonly RuleManager _rules;
    private readonly AuthService _auth;
    private readonly SecurityLogger _logger;

    private Timer? _timer;                 // runs on thread-pool; callbacks marshalled via SynchronizationContext
    private readonly SynchronizationContext? _ui;
    private bool _idleFired;
    private bool _disposed;

    /// <summary>Raised on the UI context when an enabled rule matches the foreground application.</summary>
    public event Action<AppLockRule>? LockRequired;

    /// <summary>Raised on the UI context when the configured idle timeout elapses.</summary>
    public event Action? IdleElapsed;

    /// <summary>Raised when monitoring starts/stops so the dashboard can update.</summary>
    public event Action? StateChanged;

    public DateTime? LastTriggerUtc { get; private set; }
    public string? LastTriggerRuleName { get; private set; }

    private DateTime? _suppressUntilUtc;
    private string? _suppressedExeLower;

    public bool IsRunning => _timer != null;
    public bool IsPaused => _auth.Config.Settings.MonitoringPaused;

    public LockMonitor(RuleManager rules, AuthService auth, SecurityLogger logger)
    {
        _rules = rules;
        _auth = auth;
        _logger = logger;
        _ui = SynchronizationContext.Current; // captured on the UI thread in Program/MainForm ctor
    }

    public void Start()
    {
        ThrowIfDisposed();
        if (_timer != null) return; // idempotent — never creates duplicate timers
        int ms = Math.Max(250, _auth.Config.Settings.PollIntervalMs);
        _timer = new Timer(Tick, state: null, dueTime: ms, period: ms);
        _logger.Log(SecurityEventCategory.Monitoring, "Foreground monitoring started.");
        StateChanged?.Invoke();
    }

    public void Stop()
    {
        if (_timer == null) return;
        var t = _timer;
        _timer = null;
        t.Dispose(); // disposes timer; no callback will run afterwards (see Timer docs caveat below)
        _logger.Log(SecurityEventCategory.Monitoring, "Foreground monitoring stopped.");
        StateChanged?.Invoke();
    }

    /// <summary>After unlocking, ignore this exe for <paramref name="seconds"/> so we don't loop-lock.</summary>
    public void SuppressFor(string exeFileNameLower, double seconds)
    {
        _suppressedExeLower = exeFileNameLower;
        _suppressUntilUtc = DateTime.UtcNow.AddSeconds(seconds);
    }

    /// <summary>Immediately lock all enabled rules (manual/idle trigger).</summary>
    public void TriggerManualLockAll(string reason)
    {
        foreach (var rule in _rules.EnabledRules.ToList())
        {
            LastTriggerUtc = DateTime.UtcNow;
            LastTriggerRuleName = rule.DisplayName;
            _logger.Log(SecurityEventCategory.LockApplied, $"Lock applied: {rule.DisplayName} ({reason})");
            RaiseOnUi(() => LockRequired?.Invoke(rule));
        }
    }

    private void Tick(object? _)
    {
        if (_disposed || _timer == null) return;
        try
        {
            var settings = _auth.Config.Settings;
            if (settings.MonitoringPaused) return;

            // ---- idle check ----
            if (settings.IdleTimeoutSeconds > 0)
            {
                double idle = NativeMethods.GetIdleSeconds();
                if (idle >= settings.IdleTimeoutSeconds && !_idleFired)
                {
                    _idleFired = true;
                    RaiseOnUi(() => IdleElapsed?.Invoke());
                }
                else if (idle < settings.IdleTimeoutSeconds)
                {
                    _idleFired = false;
                }
            }

            // ---- foreground match ----
            IntPtr fg = NativeMethods.GetForegroundWindow();
            if (fg == IntPtr.Zero) return;
            if (!NativeMethods.GetWindowThreadProcessId(fg, out uint pid) || pid == 0) return;

            string? exeName = NativeMethods.GetProcessExeName(pid);
            if (string.IsNullOrEmpty(exeName)) return;

            if (_suppressedExeLower == exeName && _suppressUntilUtc.HasValue &&
                DateTime.UtcNow < _suppressUntilUtc.Value)
                return;

            var rule = _rules.FindEnabledByExeName(exeName);
            if (rule == null) return;

            // Never lock our own windows even if misconfigured.
            if (exeName.Equals("a9securitylock.exe", StringComparison.OrdinalIgnoreCase)) return;

            LastTriggerUtc = DateTime.UtcNow;
            LastTriggerRuleName = rule.DisplayName;
            _logger.Log(SecurityEventCategory.LockApplied,
                $"Locked \"{rule.DisplayName}\" (foreground match: {exeName})");
            RaiseOnUi(() => LockRequired?.Invoke(rule));
        }
        catch (Exception ex)
        {
            // Monitoring must never crash the app; log and continue next tick.
            _logger.Log(SecurityEventCategory.Error, "Monitoring tick failed: " + ex.Message);
        }
    }

    private void RaiseOnUi(Action a)
    {
        if (_ui != null && _ui != SynchronizationContext.Current)
            _ui.Post(_ => a(), null);
        else
            a();
    }

    public MonitorSnapshot GetSnapshot() => new(
        Running: IsRunning,
        Paused: IsPaused,
        EnabledRules: _rules.EnabledCount,
        IdleSeconds: NativeMethods.GetIdleSeconds(),
        LastTriggerUtc: LastTriggerUtc,
        LastTriggerRuleName: LastTriggerRuleName);

    private void ThrowIfDisposed()
    {
        if (_disposed) throw new ObjectDisposedException(nameof(LockMonitor));
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        Stop();
    }
}
