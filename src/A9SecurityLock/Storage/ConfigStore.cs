using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using A9SecurityLock.Models;

namespace A9SecurityLock.Storage;

/// <summary>
/// Loads and saves the security configuration (config.a9c).
/// The JSON payload is encrypted with AES-256-GCM. The 256-bit key is random, stored in
/// key.bin protected by Windows DPAPI (CurrentUser scope) on Windows, with DACLs restricted
/// to the current user where practical. The master password itself is NEVER written to disk —
/// only its PBKDF2-SHA256 salt + hash inside the encrypted payload.
/// </summary>
public sealed class ConfigStore
{
    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };

    private const int KeySize = 32; // AES-256

    public string Directory { get; }
    public string ConfigPath => Path.Combine(Directory, "config.a9c");
    public string KeyPath => Path.Combine(Directory, "key.bin");
    public string LogPath => Path.Combine(Directory, "activity.log");

    public ConfigStore(string? directory = null)
    {
        Directory = directory ?? Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "A9SecurityLock");
    }

    public void EnsureDirectory()
    {
        if (!System.IO.Directory.Exists(Directory))
            System.IO.Directory.CreateDirectory(Directory);
        RestrictToCurrentUser(Directory);
        if (!File.Exists(LogPath))
            File.WriteAllText(LogPath, "");
        RestrictToCurrentUser(LogPath);
    }

    /// <summary>Returns null when no configuration exists yet (first run).</summary>
    public SecurityConfig? Load()
    {
        if (!File.Exists(ConfigPath)) return null;

        byte[] ciphertext = File.ReadAllBytes(ConfigPath);
        byte[] key = GetOrCreateKey();

        byte[] json = UnprotectAesGcm(ciphertext, key);
        var cfg = JsonSerializer.Deserialize<SecurityConfig>(json, JsonOpts)
                  ?? throw new InvalidDataException("Configuration deserialized to null.");

        // Migration / normalization: clamp values, stamp current schema version.
        // (Future releases: switch on cfg.SchemaVersion and migrate field-by-field here.)
        cfg.Settings.Normalize();
        cfg.SchemaVersion = AppSettings.CurrentSchemaVersion;

        Save(cfg); // re-write normalized copy so on-disk state matches in-memory state
        return cfg;
    }

    public void Save(SecurityConfig config)
    {
        ArgumentNullException.ThrowIfNull(config);
        EnsureDirectory();
        config.SchemaVersion = AppSettings.CurrentSchemaVersion;
        config.Settings.Normalize();

        byte[] key = GetOrCreateKey();
        byte[] json = JsonSerializer.SerializeToUtf8Bytes(config, JsonOpts);
        byte[] payload = ProtectAesGcm(json, key);

        WriteAtomic(ConfigPath, payload);
        RestrictToCurrentUser(ConfigPath);
    }

    /// <summary>Exports settings + rules WITHOUT any password material (salt/hash omitted).</summary>
    public string ExportPortableJson(SecurityConfig config)
    {
        ArgumentNullException.ThrowIfNull(config);
        var export = new
        {
            app = "A9SecurityLock",
            exportVersion = 1,
            exportedAtUtc = DateTime.UtcNow,
            containsSecrets = false,
            settings = config.Settings,
            rules = config.Rules.Select(r => new
            {
                r.Id,
                r.DisplayName,
                r.ExecutablePath,
                r.Enabled,
                r.CreatedAtUtc,
            }).ToArray(),
        };
        return JsonSerializer.Serialize(export, new JsonSerializerOptions { WriteIndented = true });
    }

    /// <summary>
    /// Validates an imported file produced by <see cref="ExportPortableJson"/>.
    /// Returns (settings, rules) or throws InvalidDataException / JsonException with a clear message.
    /// </summary>
    public (AppSettings Settings, List<AppLockRule> Rules) ValidateImport(string json)
    {
        using var doc = JsonDocument.Parse(json); // throws JsonException on corrupt input
        if (!doc.RootElement.TryGetProperty("app", out var appEl) ||
            appEl.GetString() != "A9SecurityLock")
            throw new InvalidDataException("This file is not an A9 Security Lock export.");

        if (!doc.RootElement.TryGetProperty("containsSecrets", out var secEl) || secEl.GetBoolean())
            throw new InvalidDataException("Refusing to import a file that claims to contain secrets.");

        var settings = doc.RootElement.TryGetProperty("settings", out var sEl)
            ? sEl.Deserialize<AppSettings>(JsonOpts) ?? new AppSettings()
            : new AppSettings();
        settings.Normalize();

        var rules = new List<AppLockRule>();
        if (doc.RootElement.TryGetProperty("rules", out var rEl) && rEl.ValueKind == JsonValueKind.Array)
        {
            foreach (var item in rEl.EnumerateArray())
            {
                var rule = item.Deserialize<AppLockRule>(JsonOpts);
                if (rule is null || string.IsNullOrWhiteSpace(rule.ExecutablePath)) continue;
                rule.Id = string.IsNullOrWhiteSpace(rule.Id) ? Guid.NewGuid().ToString("N") : rule.Id;
                rules.Add(rule);
            }
        }

        // Reject duplicate executable paths inside the import itself.
        var dupGroup = rules.GroupBy(r => NormalizePath(r.ExecutablePath))
                            .FirstOrDefault(g => g.Count() > 1);
        if (dupGroup != null)
            throw new InvalidDataException($"Import contains duplicate rule for: {dupGroup.Key}");

        return (settings, rules);
    }

    /// <summary>Deletes all persisted configuration (used only by explicit, confirmed reset).</summary>
    public void DeleteAll()
    {
        foreach (var p in new[] { ConfigPath, KeyPath })
        {
            try { if (File.Exists(p)) File.Delete(p); }
            catch (IOException) { /* best effort */ }
        }
    }

    // ---------------- internal crypto helpers (visible to the test project) ----------------

    internal static string NormalizePath(string path) =>
        Path.GetFullPath(path).TrimEnd('\\').ToUpperInvariant();

    internal static byte[] ProtectAesGcm(byte[] plaintext, byte[] key)
    {
        byte[] nonce = RandomNumberGenerator.GetBytes(12);
        byte[] cipher = new byte[plaintext.Length];
        byte[] tag = new byte[16];
        using var aes = new AesGcm(key, 16);
        aes.Encrypt(nonce, plaintext, cipher, tag);

        // Layout: [magic 'A9C1'][nonce 12][tag 16][cipher N]
        using var ms = new MemoryStream();
        ms.Write("A9C1"u8);
        ms.Write(nonce);
        ms.Write(tag);
        ms.Write(cipher);
        return ms.ToArray();
    }

    internal static byte[] UnprotectAesGcm(byte[] payload, byte[] key)
    {
        if (payload.Length < 4 + 12 + 16)
            throw new InvalidDataException("Configuration file is truncated or corrupt.");
        if (payload[0] != 'A' || payload[1] != '9' || payload[2] != 'C' || payload[3] != '1')
            throw new InvalidDataException("Configuration file has an unrecognized format (possible corruption).");

        byte[] nonce = payload[4..16];
        byte[] tag = payload[16..32];
        byte[] cipher = payload[32..];
        byte[] plain = new byte[cipher.Length];
        using var aes = new AesGcm(key, 16);
        try
        {
            aes.Decrypt(nonce, cipher, tag, plain);
        }
        catch (CryptographicException ex)
        {
            throw new InvalidDataException(
                "Configuration failed integrity verification. The file may be corrupted.", ex);
        }
        return plain;
    }

    private byte[] GetOrCreateKey()
    {
        if (File.Exists(KeyPath))
        {
            byte[] blob = File.ReadAllBytes(KeyPath);
            return UnprotectKey(blob);
        }

        byte[] key = RandomNumberGenerator.GetBytes(KeySize);
        byte[] blob = ProtectKey(key);
        WriteAtomic(KeyPath, blob);
        RestrictToCurrentUser(KeyPath);
        return key;
    }

    private static byte[] ProtectKey(byte[] key)
    {
        if (OperatingSystem.IsWindows())
            return ProtectedData.Protect(key, optionalEntropy: null, DataProtectionScope.CurrentUser);

        // Non-Windows development fallback ONLY (so unit tests can run on Linux/macOS CI).
        // On Windows this branch is never taken; DPAPI is always used.
        // Format: [magic 14 bytes][key 32 bytes] — clearly marked, NOT secure, dev-only.
        return "A9DEVKEYONLY!!"u8.ToArray().Concat(key).ToArray();
    }

    private static byte[] UnprotectKey(byte[] blob)
    {
        if (OperatingSystem.IsWindows())
            return ProtectedData.Unprotect(blob, optionalEntropy: null, DataProtectionScope.CurrentUser);

        ReadOnlySpan<byte> magic = "A9DEVKEYONLY!!"u8;
        if (blob.Length != magic.Length + KeySize || !blob[..magic.Length].AsSpan().SequenceEqual(magic))
            throw new InvalidDataException("Key file is corrupt or was created on a different platform.");
        return blob[magic.Length..];
    }

    private static void WriteAtomic(string path, byte[] content)
    {
        string tmp = path + ".tmp";
        File.WriteAllBytes(tmp, content);
        if (File.Exists(path)) File.Replace(tmp, path, destinationBackupFileName: null);
        else File.Move(tmp, path);
    }

    private static void RestrictToCurrentUser(string path)
    {
        if (!OperatingSystem.IsWindows()) return;
        try
        {
            var sec = new System.Security.AccessControl.FileSecurity();
            sec.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
            string user = Environment.UserDomainName + "\\" + Environment.UserName;
            sec.AddAccessRule(new System.Security.AccessControl.FileSystemAccessRule(
                user,
                System.Security.AccessControl.FileSystemRights.FullControl,
                System.Security.AccessControl.InheritanceFlags.None,
                System.Security.AccessControl.PropagationFlags.None,
                System.Security.AccessControl.AccessControlType.Allow));
            File.SetAccessControl(path, sec);
        }
        catch (UnauthorizedAccessException)
        {
            // Non-NTFS volumes don't support ACLs; keep DPAPI protection at least.
        }
        catch (PlatformNotSupportedException)
        {
        }
    }
}
