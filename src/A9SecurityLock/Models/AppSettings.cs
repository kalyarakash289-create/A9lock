namespace A9SecurityLock.Models;

/// <summary>Persisted, user-configurable settings for A9 Security Lock.</summary>
public sealed class AppSettings
{
    /// <summary>Schema version of the settings file. Bump when migrating.</summary>
    public int SchemaVersion { get; set; } = CurrentSchemaVersion;

    public const int CurrentSchemaVersion = 1;

    /// <summary>Idle seconds before enabled rules are locked. 0 disables idle locking.</summary>
    public int IdleTimeoutSeconds { get; set; } = 300;

    /// <summary>After this many consecutive failed unlock attempts, a cooldown is enforced.</summary>
    public int MaxFailedAttemptsBeforeDelay { get; set; } = 5;

    /// <summary>Cooldown length (seconds) applied once MaxFailedAttemptsBeforeDelay is reached. Grows per extra failure.</summary>
    public int FailedAttemptDelaySeconds { get; set; } = 30;

    /// <summary>Hard cap for the escalating lockout delay.</summary>
    public int MaxFailedAttemptDelaySeconds { get; set; } = 600;

    /// <summary>Master-password minimum length.</summary>
    public int MinPasswordLength { get; set; } = 8;

    /// <summary>Run at Windows start (HKCU Run key). Only settable after explicit consent in the UI.</summary>
    public bool StartWithWindows { get; set; }

    /// <summary>Hide to notification area instead of exiting when the main window is closed.</summary>
    public bool MinimizeToTrayOnClose { get; set; } = true;

    /// <summary>Lock all enabled-rule applications when the workstation unlocks (session unlock).</summary>
    public bool LockOnSessionUnlock { get; set; }

    /// <summary>Monitoring master switch. Changing it from false->true requires authentication in the UI.</summary>
    public bool MonitoringPaused { get; set; }

    /// <summary>Milliseconds between foreground-window samples when monitoring is active.</summary>
    public int PollIntervalMs { get; set; } = 750;

    public AppSettings Clone() => new()
    {
        SchemaVersion = SchemaVersion,
        IdleTimeoutSeconds = IdleTimeoutSeconds,
        MaxFailedAttemptsBeforeDelay = MaxFailedAttemptsBeforeDelay,
        FailedAttemptDelaySeconds = FailedAttemptDelaySeconds,
        MaxFailedAttemptDelaySeconds = MaxFailedAttemptDelaySeconds,
        MinPasswordLength = MinPasswordLength,
        StartWithWindows = StartWithWindows,
        MinimizeToTrayOnClose = MinimizeToTrayOnClose,
        LockOnSessionUnlock = LockOnSessionUnlock,
        MonitoringPaused = MonitoringPaused,
        PollIntervalMs = PollIntervalMs,
    };

    /// <summary>Clamps every value into its safe range. Used on load and on save.</summary>
    public void Normalize()
    {
        SchemaVersion = CurrentSchemaVersion;
        IdleTimeoutSeconds = Clamp(IdleTimeoutSeconds, 0, 24 * 60 * 60);
        MaxFailedAttemptsBeforeDelay = Clamp(MaxFailedAttemptsBeforeDelay, 3, 20);
        FailedAttemptDelaySeconds = Clamp(FailedAttemptDelaySeconds, 5, 600);
        MaxFailedAttemptDelaySeconds = Clamp(MaxFailedAttemptDelaySeconds, 30, 3600);
        MinPasswordLength = Clamp(MinPasswordLength, 6, 64);
        PollIntervalMs = Clamp(PollIntervalMs, 250, 10_000);
    }

    private static int Clamp(int v, int lo, int hi) => v < lo ? lo : (v > hi ? hi : v);
}
