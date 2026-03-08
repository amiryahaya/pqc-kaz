namespace Antrapol.IdP.Certificate.Domain.Enums;

/// <summary>
/// Default certificate algorithm configuration for the National Digital ID system.
/// </summary>
public static class DefaultCertificateAlgorithms
{
    /// <summary>
    /// Default signature algorithm for certificates: KAZ-SIGN-256 (Security Level 5).
    /// </summary>
    public const SignatureAlgorithm Signature = SignatureAlgorithm.KazSign256;

    /// <summary>
    /// Security level for all certificate operations.
    /// </summary>
    public const int SecurityLevel = 5;
}

/// <summary>
/// Represents the status of a certificate.
/// </summary>
public enum CertificateStatus
{
    /// <summary>
    /// Certificate is pending issuance.
    /// </summary>
    Pending = 0,

    /// <summary>
    /// Certificate is active and valid.
    /// </summary>
    Active = 1,

    /// <summary>
    /// Certificate has been revoked.
    /// </summary>
    Revoked = 2,

    /// <summary>
    /// Certificate has expired.
    /// </summary>
    Expired = 3,

    /// <summary>
    /// Certificate has been suspended (temporary).
    /// </summary>
    Suspended = 4
}

/// <summary>
/// Represents the type of certificate.
/// </summary>
public enum CertificateType
{
    /// <summary>
    /// Root CA certificate.
    /// </summary>
    RootCa = 0,

    /// <summary>
    /// Intermediate CA certificate.
    /// </summary>
    IntermediateCa = 1,

    /// <summary>
    /// End-entity certificate for signing.
    /// </summary>
    EndEntitySigning = 2,

    /// <summary>
    /// End-entity certificate for encryption/key exchange.
    /// </summary>
    EndEntityEncryption = 3
}

/// <summary>
/// Represents the algorithm used for the certificate.
/// </summary>
public enum SignatureAlgorithm
{
    // ============================================
    // FIPS 204 - ML-DSA (Dilithium-based)
    // ============================================

    /// <summary>
    /// ML-DSA-65 (FIPS 204) - Post-Quantum Digital Signature.
    /// Security Level 3 (AES-192 equivalent).
    /// </summary>
    MlDsa65 = 0,

    /// <summary>
    /// ML-DSA-87 (FIPS 204) - Post-Quantum Digital Signature (higher security).
    /// Security Level 5 (AES-256 equivalent).
    /// </summary>
    MlDsa87 = 1,

    // ============================================
    // KAZ-SIGN - Malaysian National PQC Signature Standard
    // (Comparable to NIST ML-DSA)
    // ============================================

    /// <summary>
    /// KAZ-SIGN-128 - Malaysian National Post-Quantum Signature Algorithm.
    /// Security Level 1 (comparable to ML-DSA-44).
    /// </summary>
    KazSign128 = 10,

    /// <summary>
    /// KAZ-SIGN-192 - Malaysian National Post-Quantum Signature Algorithm.
    /// Security Level 3 (comparable to ML-DSA-65).
    /// </summary>
    KazSign192 = 11,

    /// <summary>
    /// KAZ-SIGN-256 - Malaysian National Post-Quantum Signature Algorithm.
    /// Security Level 5 (comparable to ML-DSA-87).
    /// </summary>
    KazSign256 = 12,

    // ============================================
    // Hybrid Algorithms (PQC + Classical)
    // ============================================

    /// <summary>
    /// Hybrid: ML-DSA-65 + ECDSA P-256.
    /// </summary>
    HybridMlDsa65EcdsaP256 = 20,

    /// <summary>
    /// Hybrid: ML-DSA-87 + ECDSA P-384.
    /// </summary>
    HybridMlDsa87EcdsaP384 = 21,

    /// <summary>
    /// Hybrid: KAZ-SIGN-128 + ECDSA P-256.
    /// </summary>
    HybridKazSign128EcdsaP256 = 22,

    /// <summary>
    /// Hybrid: KAZ-SIGN-192 + ECDSA P-384.
    /// </summary>
    HybridKazSign192EcdsaP384 = 23,

    /// <summary>
    /// Hybrid: KAZ-SIGN-256 + ECDSA P-384.
    /// </summary>
    HybridKazSign256EcdsaP384 = 24,

    // ============================================
    // Classical Algorithms (for backward compatibility)
    // ============================================

    /// <summary>
    /// ECDSA with P-256 curve (classical, for backward compatibility).
    /// </summary>
    EcdsaP256 = 100,

    /// <summary>
    /// ECDSA with P-384 curve (classical, for backward compatibility).
    /// </summary>
    EcdsaP384 = 101
}

/// <summary>
/// Represents the reason for certificate revocation.
/// </summary>
public enum RevocationReason
{
    Unspecified = 0,
    KeyCompromise = 1,
    CaCompromise = 2,
    AffiliationChanged = 3,
    Superseded = 4,
    CessationOfOperation = 5,
    CertificateHold = 6,
    PrivilegeWithdrawn = 9,
    AaCompromise = 10
}
