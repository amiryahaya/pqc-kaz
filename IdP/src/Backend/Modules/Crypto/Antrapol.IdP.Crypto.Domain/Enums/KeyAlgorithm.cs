namespace Antrapol.IdP.Crypto.Domain.Enums;

/// <summary>
/// Default algorithm configuration for the National Digital ID system.
/// These algorithms are fixed and cannot be changed by users.
/// </summary>
public static class DefaultAlgorithms
{
    /// <summary>
    /// Default signature algorithm: KAZ-SIGN-256 (Security Level 5).
    /// This is the only signature algorithm used for National Digital ID.
    /// </summary>
    public const KeyAlgorithm Signature = KeyAlgorithm.KazSign256;

    /// <summary>
    /// Default key encapsulation algorithm: KAZ-KEM-256 (Security Level 5).
    /// This is the only KEM algorithm used for secure key exchange.
    /// </summary>
    public const KeyAlgorithm KeyEncapsulation = KeyAlgorithm.KazKem256;

    /// <summary>
    /// Security level for all cryptographic operations.
    /// Level 5 provides maximum quantum-resistant security (~AES-256 equivalent).
    /// </summary>
    public const int SecurityLevel = 5;
}

/// <summary>
/// Represents the cryptographic algorithm for keys.
/// </summary>
public enum KeyAlgorithm
{
    // ============================================
    // FIPS 204 - ML-DSA (Dilithium-based Signatures)
    // ============================================

    /// <summary>
    /// ML-DSA-65 (FIPS 204) - Post-Quantum Digital Signature Algorithm.
    /// Security Level 3 (~AES-192 equivalent).
    /// </summary>
    MlDsa65 = 0,

    /// <summary>
    /// ML-DSA-87 (FIPS 204) - Post-Quantum Digital Signature Algorithm.
    /// Security Level 5 (~AES-256 equivalent).
    /// </summary>
    MlDsa87 = 1,

    // ============================================
    // FIPS 203 - ML-KEM (Kyber-based Key Encapsulation)
    // ============================================

    /// <summary>
    /// ML-KEM-768 (FIPS 203) - Post-Quantum Key Encapsulation Mechanism.
    /// Security Level 3 (~AES-192 equivalent).
    /// </summary>
    MlKem768 = 2,

    /// <summary>
    /// ML-KEM-1024 (FIPS 203) - Post-Quantum Key Encapsulation Mechanism.
    /// Security Level 5 (~AES-256 equivalent).
    /// </summary>
    MlKem1024 = 3,

    // ============================================
    // KAZ-SIGN - Malaysian National PQC Signature Standard
    // (Comparable to NIST ML-DSA)
    // ============================================

    /// <summary>
    /// KAZ-SIGN-128 - Malaysian National Post-Quantum Signature Algorithm.
    /// Security Level 1 (comparable to ML-DSA-44).
    /// </summary>
    KazSign128 = 20,

    /// <summary>
    /// KAZ-SIGN-192 - Malaysian National Post-Quantum Signature Algorithm.
    /// Security Level 3 (comparable to ML-DSA-65).
    /// </summary>
    KazSign192 = 21,

    /// <summary>
    /// KAZ-SIGN-256 - Malaysian National Post-Quantum Signature Algorithm.
    /// Security Level 5 (comparable to ML-DSA-87).
    /// </summary>
    KazSign256 = 22,

    // ============================================
    // KAZ-KEM - Malaysian National PQC Key Encapsulation Standard
    // (Comparable to NIST ML-KEM)
    // ============================================

    /// <summary>
    /// KAZ-KEM-128 - Malaysian National Post-Quantum Key Encapsulation Mechanism.
    /// Security Level 1 (comparable to ML-KEM-512).
    /// </summary>
    KazKem128 = 30,

    /// <summary>
    /// KAZ-KEM-192 - Malaysian National Post-Quantum Key Encapsulation Mechanism.
    /// Security Level 3 (comparable to ML-KEM-768).
    /// </summary>
    KazKem192 = 31,

    /// <summary>
    /// KAZ-KEM-256 - Malaysian National Post-Quantum Key Encapsulation Mechanism.
    /// Security Level 5 (comparable to ML-KEM-1024).
    /// </summary>
    KazKem256 = 32,

    // ============================================
    // Classical Algorithms (for hybrid/backward compatibility)
    // ============================================

    /// <summary>
    /// ECDSA P-256 (Classical) - For hybrid signatures.
    /// </summary>
    EcdsaP256 = 100,

    /// <summary>
    /// ECDSA P-384 (Classical) - For hybrid signatures.
    /// </summary>
    EcdsaP384 = 101,

    /// <summary>
    /// ECDH P-256 (Classical) - For hybrid key exchange.
    /// </summary>
    EcdhP256 = 102,

    /// <summary>
    /// ECDH P-384 (Classical) - For hybrid key exchange.
    /// </summary>
    EcdhP384 = 103
}

/// <summary>
/// Represents the purpose of a cryptographic key.
/// </summary>
public enum KeyPurpose
{
    /// <summary>
    /// Key is used for digital signatures.
    /// </summary>
    Signing = 0,

    /// <summary>
    /// Key is used for key encapsulation/exchange.
    /// </summary>
    KeyEncapsulation = 1,

    /// <summary>
    /// Key is used for both signing and key encapsulation.
    /// </summary>
    DualUse = 2
}

/// <summary>
/// Represents the status of a cryptographic key.
/// </summary>
public enum KeyStatus
{
    /// <summary>
    /// Key is active and can be used.
    /// </summary>
    Active = 0,

    /// <summary>
    /// Key is disabled (cannot be used but not destroyed).
    /// </summary>
    Disabled = 1,

    /// <summary>
    /// Key is compromised and should not be trusted.
    /// </summary>
    Compromised = 2,

    /// <summary>
    /// Key has been securely destroyed.
    /// </summary>
    Destroyed = 3
}

/// <summary>
/// Represents where the key is stored.
/// </summary>
public enum KeyStorageType
{
    /// <summary>
    /// Key is stored in software (encrypted in database).
    /// </summary>
    Software = 0,

    /// <summary>
    /// Key is stored in HSM (PKCS#11).
    /// </summary>
    Hsm = 1,

    /// <summary>
    /// Key is stored in cloud KMS.
    /// </summary>
    CloudKms = 2
}
