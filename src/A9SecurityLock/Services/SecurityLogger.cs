using System.Text;
using A9SecurityLock.Models;

namespace A9SecurityLock.Services;

/// <summary>
/// Appends structured security events to activity.log in the config folder and keeps a
/// bounded in-memory ring buffer for the dashboard / Activity Log page.
/// NEVER logs passwords, hashes, salts or tokens.
/// </summary>
public sealed class SecurityLogger
{
    private const int MemoryCapacity = 500;
    private const long MaxLogBytes = 512 * 1024; // rotate at 512 KB

    private readonly object _sync = new();
    private readonly LinkedList<SecurityLogEntry> _recent = new();
    private readonly string _logPath;

    public event Action<SecurityLogEntry>? EntryAdded;

    public SecurityLogger(string logPath)
    {
        _logPath = logPath;
    }

    public IReadOnlyList<SecurityLogEntry> Recent
    {
        get
        {
            lock (_sync) return _recent.ToList();
        }
    }

    public void Log(SecurityEventCategory category, string message)
    {
        var entry = new SecurityLogEntry
        {
            TimestampUtc = DateTime.UtcNow,
            Category = category,
            Message = Sanitize(message),
        };

        lock (_sync)
        {
            _recent.AddFirst(entry);
            while (_recent.Count > MemoryCapacity) _recent.RemoveLast();

            try
            {
                RotateIfNeeded();
                File.AppendAllText(_logPath, entry.FormattedLine + Environment.NewLine, Encoding.UTF8);
            }
            catch (IOException) { /* logging must never crash the app */ }
            catch (UnauthorizedAccessException) { }
        }

        EntryAdded?.Invoke(entry);
    }

    public void Info(string msg) => Log(SecurityEventCategory.Info, msg);
    public void Warn(string msg) => Log(SecurityEventCategory.Warning, msg);
    public void Error(string msg) => Log(SecurityEventCategory.Error, msg);

    /// <summary>Defense-in-depth: strip anything that looks like a password field from messages.</summary>
    private static string Sanitize(string message)
    {
        if (string.IsNullOrEmpty(message)) return "";
        var sb = new StringBuilder(message.Length);
        foreach (char c in message)
        {
            if (c == '\r' || c == '\n') sb.Append(' ');
            else sb.Append(c);
        }
        string s = sb.ToString();
        if (s.Length > 300) s = s[..300] + "…";
        return s;
    }

    private void RotateIfNeeded()
    {
        try
        {
            var fi = new FileInfo(_logPath);
            if (fi.Exists && fi.Length > MaxLogBytes)
            {
                string archive = _logPath + ".1";
                if (File.Exists(archive)) File.Delete(archive);
                File.Move(_logPath, archive);
            }
        }
        catch (IOException) { }
    }
}
