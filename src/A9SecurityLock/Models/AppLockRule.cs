namespace A9SecurityLock.Models;

/// <summary>One application-lock rule managed by the App Lock Manager.</summary>
public sealed class AppLockRule
{
    /// <summary>Stable identifier (GUID string). Used for manual lock/unlock and testing.</summary>
    public string Id { get; set; } = Guid.NewGuid().ToString("N");

    /// <summary>Display name shown in lists and on the lock screen.</summary>
    public string DisplayName { get; set; } = "";

    /// <summary>Full path to the target executable (e.g. C:\Windows\System32\notepad.exe).</summary>
    public string ExecutablePath { get; set; } = "";

    /// <summary>When false the rule is configured but not enforced.</summary>
    public bool Enabled { get; set; } = true;

    /// <summary>Date/time (local) when the rule was created.</summary>
    public DateTime CreatedAtUtc { get; set; } = DateTime.UtcNow;

    public AppLockRule Clone() => new()
    {
        Id = Id,
        DisplayName = DisplayName,
        ExecutablePath = ExecutablePath,
        Enabled = Enabled,
        CreatedAtUtc = CreatedAtUtc,
    };
}
