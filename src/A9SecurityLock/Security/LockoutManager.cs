using A9SecurityLock.Models;

namespace A9SecurityLock.Security;

/// <summary>
/// Tracks failed unlock attempts and computes escalating cooldowns.
/// Pure logic — no UI, no storage — so it can be unit-tested deterministically.
/// </summary>
public sealed class LockoutManager
{
    private int _consecutiveFailures;
    private DateTime? _lockoutUntilUtc;

    public int ConsecutiveFailures => _consecutiveFailures;
    public DateTime? LockoutUntilUtc => _lockoutUntilUtc;

    /// <summary>Resets failure state (e.g. after a successful authentication).</summary>
    public void Reset()
    {
        _consecutiveFailures = 0;
        _lockoutUntilUtc = null;
    }

    /// <summary>
    /// Registers one failed attempt. Once the configured threshold is reached, a delay is applied:
    /// baseDelay * (failures - threshold + 1), capped at maxDelay.
    /// </summary>
    /// <returns>The lockout duration that was applied, or TimeSpan.Zero if still below threshold.</returns>
    public TimeSpan RegisterFailure(AppSettings settings, TimeProvider? time = null)
    {
        time ??= TimeProvider.System;
        _consecutiveFailures++;

        if (_consecutiveFailures < settings.MaxFailedAttemptsBeforeDelay)
            return TimeSpan.Zero;

        int steps = _consecutiveFailures - settings.MaxFailedAttemptsBeforeDelay + 1;
        double seconds = Math.Min(
            (double)settings.FailedAttemptDelaySeconds * steps,
            settings.MaxFailedAttemptDelaySeconds);

        var delay = TimeSpan.FromSeconds(seconds);
        _lockoutUntilUtc = time.GetUtcNow().UtcDateTime.Add(delay);
        return delay;
    }

    /// <summary>True while a cooldown is in force (evaluated against <paramref name="now"/>).</summary>
    public bool IsLockedOut(DateTime? nowUtc = null)
    {
        DateTime now = nowUtc ?? (TimeProvider.System.GetUtcNow().UtcDateTime);
        return _lockoutUntilUtc.HasValue && now < _lockoutUntilUtc.Value;
    }

    /// <summary>Remaining cooldown, or TimeSpan.Zero.</summary>
    public TimeSpan RemainingLockout(DateTime? nowUtc = null)
    {
        if (!_lockoutUntilUtc.HasValue) return TimeSpan.Zero;
        DateTime now = nowUtc ?? TimeProvider.System.GetUtcNow().UtcDateTime;
        var remaining = _lockoutUntilUtc.Value - now;
        return remaining > TimeSpan.Zero ? remaining : TimeSpan.Zero;
    }
}
