using System.Security.Cryptography;

namespace A9SecurityLock.Security;

/// <summary>
/// Master-password hashing using PBKDF2 (Rfc2898DeriveBytes) with SHA-256.
/// The password itself is never stored, logged, or exported anywhere.
/// </summary>
public static class PasswordHasher
{
    public const int SaltSize = 16;      // 128-bit CSPRNG salt
    public const int HashSize = 32;      // 256-bit derived key
    public const int DefaultIterations = 200_000;

    /// <summary>Generates a cryptographically random salt.</summary>
    public static byte[] GenerateSalt() => RandomNumberGenerator.GetBytes(SaltSize);

    /// <summary>Derives the PBKDF2-SHA256 hash for <paramref name="password"/>.</summary>
    public static byte[] DeriveHash(string password, byte[] salt, int iterations)
    {
        ArgumentNullException.ThrowIfNull(password);
        ArgumentNullException.ThrowIfNull(salt);
        if (salt.Length == 0) throw new ArgumentException("Salt must not be empty.", nameof(salt));
        if (iterations < 10_000)
            throw new ArgumentOutOfRangeException(nameof(iterations), "Iteration count too low.");

        return Rfc2898DeriveBytes.Pbkdf2(
            password: password.AsSpan(),
            salt: salt.AsSpan(),
            iterations: iterations,
            hashAlgorithm: HashAlgorithmName.SHA256,
            outputLength: HashSize);
    }

    /// <summary>Verifies a candidate password against a stored hash in constant time.</summary>
    public static bool Verify(string password, byte[] salt, byte[] expectedHash, int iterations)
    {
        if (string.IsNullOrEmpty(password) || salt.Length == 0 || expectedHash.Length == 0)
            return false;

        try
        {
            byte[] actual = DeriveHash(password, salt, iterations);
            return CryptographicOperations.FixedTimeEquals(actual, expectedHash);
        }
        catch (CryptographicException)
        {
            return false;
        }
    }

    /// <summary>Basic strength guidance used by the setup UI (not a hard entropy guarantee).</summary>
    public static (bool Ok, string Hint) CheckStrength(string password, int minLength)
    {
        if (string.IsNullOrEmpty(password))
            return (false, "Password must not be empty.");
        if (password.Length < minLength)
            return (false, $"Password must be at least {minLength} characters long.");
        if (password.All(char.IsDigit))
            return (false, "Do not use an all-digit password.");
        if (password.All(char.IsLetter))
            return (false, "Mix letters with digits or symbols for better protection.");
        return (true, "Looks good.");
    }
}
