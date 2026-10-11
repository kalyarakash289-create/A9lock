namespace A9SecurityLock.Models;

public enum SecurityEventCategory
{
    Info,
    AuthSuccess,
    AuthFailure,
    LockApplied,
    Unlock,
    RuleChange,
    SettingsChange,
    Monitoring,
    Warning,
    Error,
}

/// <summary>A single structured security-log entry. Never contains passwords or hashes.</summary>
public sealed class SecurityLogEntry
{
    public DateTime TimestampUtc { get; set; } = DateTime.UtcNow;
    public SecurityEventCategory Category { get; set; } = SecurityEventCategory.Info;
    public string Message { get; set; } = "";

    public string FormattedLine =>
        $"{TimestampUtc.ToLocalTime():yyyy-MM-dd HH:mm:ss}  [{Category,-13}]  {Message}";
}
