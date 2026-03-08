namespace Antrapol.Kaz.Kem;

/// <summary>
/// KAZ-KEM security levels corresponding to NIST post-quantum security categories.
/// </summary>
public enum SecurityLevel
{
    /// <summary>
    /// 128-bit security (NIST Level 1) - Equivalent to AES-128
    /// </summary>
    Level128 = 128,

    /// <summary>
    /// 192-bit security (NIST Level 3) - Equivalent to AES-192
    /// </summary>
    Level192 = 192,

    /// <summary>
    /// 256-bit security (NIST Level 5) - Equivalent to AES-256
    /// </summary>
    Level256 = 256
}
