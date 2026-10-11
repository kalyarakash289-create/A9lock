using System.Security.Cryptography;
using A9SecurityLock.Models;
using A9SecurityLock.Security;
using A9SecurityLock.Storage;

namespace A9SecurityLock.Services;

/// <summary>
/// Central authentication state machine: master-password setup, verification, change,
/// lockout enforcement. All password material lives only in memory transiently and is
/// cleared as soon as possible; nothing sensitive is ever logged.
/// </summary>
public sealed class AuthService
{
    private readonly ConfigStore _store;
    private readonly SecurityLogger _logger;
    private readonly LockoutManager _lockout = new();

    public SecurityConfig Config { get; private set; }

    public event Action? ConfigChanged;

    public AuthService(ConfigStore store, SecurityLogger logger)
    {
        _store = store;
        _logger = logger;

        try
        {
            Config = store.Load() ?? new SecurityConfig();
        }
        catch (Exception ex) when (ex is InvalidDataException or JsonException or IOException
                                   or UnauthorizedAccessException or CryptographicException)
        {
            // Corrupted configuration recovery: keep a backup of the broken file, start fresh.
            TryPreserveCorruptFile();
            _logger.Log(SecurityEventCategory.Error,
                "Configuration could not be read (" + ex.GetType().Name + "). A backup was kept and defaults were loaded.");
            Config = new SecurityConfig();
        }
    }

    public bool IsFirstRun => !Config.HasMasterPassword;
    public bool IsLockedOut => _lockout.IsLockedOut();
    public TimeSpan RemainingLockout => _lockout.RemainingLockout();
    public int ConsecutiveFailures => _lockout.ConsecutiveFailures;

    /// <summary>Wall-clock time of the most recent successful verification, if any (dashboard only).</summary>
    public DateTime? LastSuccessfulUnlockUtc { get; private set; }

    /// <summary>Records a successful unlock timestamp (called by the lock screen after verification).</summary>
    public void MarkUnlocked() => LastSuccessfulUnlockUtc = DateTime.Now;

    /// <summary>First-run: create the master password (validated by caller-provided strength rules).</summary>
    public bool SetupMasterPassword(string password, out string error)
    {
        error = "";
        if (Config.HasMasterPassword)
        {
            error = "A master password already exists. Use Change Password instead.";
            return false;
        }

        var (ok, hint) = PasswordHasher.CheckStrength(password, Config.Settings.MinPasswordLength);
        if (!ok) { error = hint; return false; }

        byte[] salt = PasswordHasher.GenerateSalt();
        byte[] hash = PasswordHasher.DeriveHash(password, salt, PasswordHasher.DefaultIterations);

        Config.Pbkdf2Iterations = PasswordHasher.DefaultIterations;
        Config.PasswordSaltBase64 = Convert.ToBase64String(salt);
        Config.PasswordHashBase64 = Convert.ToBase64String(hash);

        SaveConfig();
        _logger.Log(SecurityEventCategory.AuthSuccess, "Master password created during initial setup.");
        return true;
    }

    /// <summary>Verifies the master password, honoring lockout delays. Never logs the password.</summary>
    public bool VerifyMasterPassword(string password, out string error)
    {
        error = "";

        if (!Config.HasMasterPassword)
        {
            error = "No master password has been configured yet.";
            return false;
        }

        if (_lockout.IsLockedOut())
        {
            var rem = _lockout.RemainingLockout();
            error = $"Too many failed attempts. Try again in {(int)Math.Ceiling(rem.TotalSeconds)} second(s).";
            return false;
        }

        byte[] salt, expected;
        int iters;
        try
        {
            salt = Convert.FromBase64String(Config.PasswordSaltBase64);
            expected = Convert.FromBase64String(Config.PasswordHashBase64);
            iters = Math.Max(Config.Pbkdf2Iterations, 10_000);
        }
        catch (FormatException)
        {
            error = "Stored credential data is malformed. Use Reset Configuration if needed.";
            _logger.Log(SecurityEventCategory.Error, "Stored credential data malformed.");
            return false;
        }

        bool ok = PasswordHasher.Verify(password, salt, expected, iters);
        if (ok)
        {
            _lockout.Reset();
            _logger.Log(SecurityEventCategory.AuthSuccess, "Master password verified successfully.");
            return true;
        }

        TimeSpan delay = _lockout.RegisterFailure(Config.Settings);
        _logger.Log(SecurityEventCategory.AuthFailure,
            delay > TimeSpan.Zero
                ? $"Failed unlock attempt #{_lockout.ConsecutiveFailures}. Cooldown applied: {(int)delay.TotalSeconds}s."
                : $"Failed unlock attempt #{_lockout.ConsecutiveFailures}.");

        error = delay > TimeSpan.Zero
            ? $"Incorrect password. Locked for another {(int)delay.TotalSeconds} second(s) after this attempt."
            : "Incorrect password.";
        return false;
    }

    /// <summary>Secure change-password flow: requires the current password.</summary>
    public bool ChangeMasterPassword(string current, string @new, out string error)
    {
        if (!VerifyMasterPassword(current, out error))
            return false;

        var (ok, hint) = PasswordHasher.CheckStrength(@new, Config.Settings.MinPasswordLength);
        if (!ok) { error = hint; return false; }

        byte[] salt = PasswordHasher.GenerateSalt();
        byte[] hash = PasswordHasher.DeriveHash(@new, salt, PasswordHasher.DefaultIterations);

        Config.Pbkdf2Iterations = PasswordHasher.DefaultIterations;
        Config.PasswordSaltBase64 = Convert.ToBase64String(salt);
        Config.PasswordHashBase64 = Convert.ToBase64String(hash);

        SaveConfig();
        _logger.Log(SecurityEventCategory.AuthSuccess, "Master password changed.");
        return true;
    }

    public void SaveConfig()
    {
        _store.Save(Config);
        ConfigChanged?.Invoke();
    }

    private void TryPreserveCorruptFile()
    {
        try
        {
            if (File.Exists(_store.ConfigPath))
            {
                string bak = _store.ConfigPath + ".corrupt-" + DateTime.Now.ToString("yyyyMMddHHmmss");
                File.Copy(_store.ConfigPath, bak, overwrite: true);
            }
        }
        catch { /* best effort */ }
    }
}
