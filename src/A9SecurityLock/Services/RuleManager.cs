using A9SecurityLock.Models;
using A9SecurityLock.Storage;

namespace A9SecurityLock.Services;

/// <summary>Outcome of an add/edit validation attempt.</summary>
public enum RuleAddResult { Added, Duplicate, InvalidPath, NotFound, NotExecutable }

/// <summary>
/// CRUD + validation for application-lock rules. All queries are case-insensitive on
/// normalized full paths so duplicates and renamed/moved files are detected reliably.
/// </summary>
public sealed class RuleManager
{
    private readonly AuthService _auth;
    private readonly SecurityLogger _logger;

    public event Action? RulesChanged;

    public RuleManager(AuthService auth, SecurityLogger logger)
    {
        _auth = auth;
        _logger = logger;
    }

    public IReadOnlyList<AppLockRule> Rules => _auth.Config.Rules;

    public IEnumerable<AppLockRule> EnabledRules => Rules.Where(r => r.Enabled);

    public int TotalCount => Rules.Count;
    public int EnabledCount => Rules.Count(r => r.Enabled);

    public static bool IsExecutableFile(string path) =>
        path.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) ||
        path.EndsWith(".com", StringComparison.OrdinalIgnoreCase);

    /// <summary>Validates a candidate rule. Returns a result plus a user-facing message.</summary>
    public (RuleAddResult Result, string Message) ValidateNew(string displayName, string exePath, string? editingId = null)
    {
        if (string.IsNullOrWhiteSpace(exePath))
            return (RuleAddResult.InvalidPath, "Executable path must not be empty.");

        string full;
        try { full = Path.GetFullPath(exePath); }
        catch (Exception ex) when (ex is ArgumentException or UnsupportedFilenameException or PathTooLongException)
        {
            return (RuleAddResult.InvalidPath, "The path is not a valid Windows file path.");
        }

        if (!File.Exists(full))
            return (RuleAddResult.NotFound, "The executable could not be found at that location.");

        if (!IsExecutableFile(full))
            return (RuleAddResult.NotExecutable, "Only .exe or .com files can be locked.");

        string norm = ConfigStore.NormalizePath(full);
        var dup = Rules.FirstOrDefault(r =>
            r.Id != editingId && ConfigStore.NormalizePath(r.ExecutablePath) == norm);
        if (dup != null)
            return (RuleAddResult.Duplicate, $"A rule for this executable already exists (\"{dup.DisplayName}\").");

        return (RuleAddResult.Added, "OK");
    }

    public AppLockRule? Add(string displayName, string exePath, out string error)
    {
        var (res, msg) = ValidateNew(displayName, exePath);
        if (res != RuleAddResult.Added) { error = msg; return null; }

        string full = Path.GetFullPath(exePath);
        var rule = new AppLockRule
        {
            DisplayName = string.IsNullOrWhiteSpace(displayName)
                ? Path.GetFileNameWithoutExtension(full)
                : displayName.Trim(),
            ExecutablePath = full,
            Enabled = true,
        };

        _auth.Config.Rules.Add(rule);
        _auth.SaveConfig();
        _logger.Log(SecurityEventCategory.RuleChange, $"Rule added: {rule.DisplayName} ({full})");
        RulesChanged?.Invoke();
        error = "";
        return rule;
    }

    public bool Update(string id, string displayName, string exePath, bool enabled, out string error)
    {
        var rule = Rules.FirstOrDefault(r => r.Id == id);
        if (rule is null) { error = "Rule not found."; return false; }

        var (res, msg) = ValidateNew(displayName, exePath, editingId: id);
        if (res != RuleAddResult.Added) { error = msg; return false; }

        rule.DisplayName = string.IsNullOrWhiteSpace(displayName)
            ? Path.GetFileNameWithoutExtension(exePath)
            : displayName.Trim();
        rule.ExecutablePath = Path.GetFullPath(exePath);
        rule.Enabled = enabled;

        _auth.SaveConfig();
        _logger.Log(SecurityEventCategory.RuleChange, $"Rule updated: {rule.DisplayName}");
        RulesChanged?.Invoke();
        error = "";
        return true;
    }

    public bool SetEnabled(string id, bool enabled)
    {
        var rule = Rules.FirstOrDefault(r => r.Id == id);
        if (rule is null) return false;
        rule.Enabled = enabled;
        _auth.SaveConfig();
        _logger.Log(SecurityEventCategory.RuleChange,
            $"Rule {(enabled ? "enabled" : "disabled")}: {rule.DisplayName}");
        RulesChanged?.Invoke();
        return true;
    }

    public bool Remove(string id)
    {
        var rule = Rules.FirstOrDefault(r => r.Id == id);
        if (rule is null) return false;
        _auth.Config.Rules.Remove(rule);
        _auth.SaveConfig();
        _logger.Log(SecurityEventCategory.RuleChange, $"Rule removed: {rule.DisplayName}");
        RulesChanged?.Invoke();
        return true;
    }

    /// <summary>True when the given running-process exe name matches an ENABLED rule.</summary>
    public AppLockRule? FindEnabledByExeName(string exeFileNameLower)
    {
        foreach (var r in EnabledRules)
        {
            if (string.Equals(Path.GetFileName(r.ExecutablePath), exeFileNameLower,
                    StringComparison.OrdinalIgnoreCase))
                return r;
        }
        return null;
    }

    /// <summary>True when the given running-process exe name matches ANY configured rule.</summary>
    public AppLockRule? FindByExeName(string exeFileNameLower)
    {
        foreach (var r in Rules)
        {
            if (string.Equals(Path.GetFileName(r.ExecutablePath), exeFileNameLower,
                    StringComparison.OrdinalIgnoreCase))
                return r;
        }
        return null;
    }

    public AppLockRule? FindById(string id) => Rules.FirstOrDefault(r => r.Id == id);

    /// <summary>Reports whether a rule's target still exists (for status display / graceful handling).</summary>
    public bool TargetExists(AppLockRule rule) => File.Exists(rule.ExecutablePath);
}
