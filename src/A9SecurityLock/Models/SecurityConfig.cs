namespace A9SecurityLock.Models;

/// <summary>Top-level container that is serialized (then AES-256-GCM encrypted) to config.a9c.</summary>
public sealed class SecurityConfig
{
    public int SchemaVersion { get; set; } = AppSettings.CurrentSchemaVersion;

    /// <summary>PBKDF2-SHA256 iteration count used for the master password hash.</summary>
    public int Pbkdf2Iterations { get; set; } = 200_000;

    /// <summary>Base64 CSPRNG salt for the master password hash. Never contains the password itself.</summary>
    public string PasswordSaltBase64 { get; set; } = "";

    /// <summary>Base64 PBKDF2-SHA256 derived key. Never contains the password itself.</summary>
    public string PasswordHashBase64 { get; set; } = "";

    public AppSettings Settings { get; set; } = new();

    public List<AppLockRule> Rules { get; set; } = new();

    /// <summary>True once a master password has been created (first-run setup complete).</summary>
    [System.Text.Json.Serialization.JsonIgnore]
    public bool HasMasterPassword =>
        !string.IsNullOrEmpty(PasswordSaltBase64) && !string.IsNullOrEmpty(PasswordHashBase64);
}
