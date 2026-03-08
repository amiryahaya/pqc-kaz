import Foundation
import CKazKem
import Security

/// KAZ-KEM Post-Quantum Key Encapsulation Mechanism.
///
/// Thread-safe wrapper for the native KAZ-KEM library providing
/// post-quantum secure key encapsulation.
///
/// ## Usage
/// ```swift
/// // Initialize with security level
/// try KazKem.initialize(level: .level128)
///
/// // Generate key pair
/// let keyPair = try KazKem.generateKeyPair()
///
/// // Encapsulate shared secret
/// let result = try KazKem.encapsulate(publicKey: keyPair.getPublicKey())
///
/// // Decapsulate on recipient side
/// let sharedSecret = try KazKem.decapsulate(ciphertext: result.ciphertext, privateKey: keyPair.privateKey)
/// ```
public final class KazKem: @unchecked Sendable {

    // MARK: - Private Properties

    private static let lock = NSLock()
    private static var _current: KazKem?

    private let _securityLevel: SecurityLevel
    private let _publicKeySize: Int
    private let _privateKeySize: Int
    private let _ciphertextSize: Int
    private let _sharedSecretSize: Int

    // MARK: - Public Properties

    /// Current security level
    public var securityLevel: SecurityLevel { _securityLevel }

    /// Public key size in bytes
    public var publicKeySize: Int { _publicKeySize }

    /// Private key size in bytes
    public var privateKeySize: Int { _privateKeySize }

    /// Ciphertext size in bytes
    public var ciphertextSize: Int { _ciphertextSize }

    /// Shared secret size in bytes
    public var sharedSecretSize: Int { _sharedSecretSize }

    /// Library version string
    public static var version: String {
        guard let ptr = kaz_kem_version() else { return "unknown" }
        return String(cString: ptr)
    }

    /// Check if KAZ-KEM is initialized
    public static var isInitialized: Bool {
        lock.lock()
        defer { lock.unlock() }
        return _current != nil && kaz_kem_is_initialized() != 0
    }

    /// Get the current initialized instance
    public static var current: KazKem {
        get throws {
            lock.lock()
            defer { lock.unlock() }

            guard let instance = _current else {
                throw KazKemError.notInitialized
            }
            return instance
        }
    }

    // MARK: - Initialization

    private init(level: SecurityLevel) {
        self._securityLevel = level
        self._publicKeySize = Int(kaz_kem_publickey_bytes())
        self._privateKeySize = Int(kaz_kem_privatekey_bytes())
        self._ciphertextSize = Int(kaz_kem_ciphertext_bytes())
        self._sharedSecretSize = Int(kaz_kem_shared_secret_bytes())
    }

    /// Initialize KAZ-KEM with the specified security level.
    ///
    /// - Parameter level: Security level (128, 192, or 256 bits)
    /// - Returns: Initialized KAZ-KEM instance
    /// - Throws: `KazKemError` if initialization fails
    @discardableResult
    public static func initialize(level: SecurityLevel = .level128) throws -> KazKem {
        lock.lock()
        defer { lock.unlock() }

        // If already initialized with same level, return existing
        if let current = _current, current._securityLevel == level {
            return current
        }

        // Cleanup previous instance
        if _current != nil {
            kaz_kem_cleanup()
            _current = nil
        }

        let result = kaz_kem_init(Int32(level.rawValue))
        if result != 0 {
            throw KazKemError.from(code: result, operation: "initialize")
        }

        let instance = KazKem(level: level)
        _current = instance
        return instance
    }

    /// Cleanup and release resources.
    public static func cleanup() {
        lock.lock()
        defer { lock.unlock() }

        if _current != nil {
            kaz_kem_cleanup()
            _current = nil
        }
    }

    // MARK: - Key Generation

    /// Generate a new key pair.
    ///
    /// - Returns: A new key pair containing public and private keys
    /// - Throws: `KazKemError` if key generation fails
    public func generateKeyPair() throws -> KazKemKeyPair {
        try ensureInitialized()

        var publicKey = [UInt8](repeating: 0, count: publicKeySize)
        var privateKey = [UInt8](repeating: 0, count: privateKeySize)

        let result = kaz_kem_keypair(&publicKey, &privateKey)
        if result != 0 {
            // Clear partial data
            secureZero(&privateKey)
            throw KazKemError.from(code: result, operation: "generateKeyPair")
        }

        return KazKemKeyPair(
            publicKey: Data(publicKey),
            privateKey: Data(privateKey),
            securityLevel: securityLevel
        )
    }

    /// Static convenience method to generate a key pair.
    public static func generateKeyPair() throws -> KazKemKeyPair {
        return try current.generateKeyPair()
    }

    // MARK: - Encapsulation

    /// Encapsulate a shared secret using the recipient's public key.
    ///
    /// - Parameter publicKey: Recipient's public key
    /// - Returns: Encapsulation result containing ciphertext and shared secret
    /// - Throws: `KazKemError` if encapsulation fails
    public func encapsulate(publicKey: KazKemPublicKey) throws -> KazKemEncapsulationResult {
        return try encapsulate(publicKey: publicKey.data)
    }

    /// Encapsulate a shared secret using the recipient's public key bytes.
    ///
    /// - Parameter publicKey: Recipient's public key as Data
    /// - Returns: Encapsulation result containing ciphertext and shared secret
    /// - Throws: `KazKemError` if encapsulation fails
    public func encapsulate(publicKey: Data) throws -> KazKemEncapsulationResult {
        try ensureInitialized()

        guard publicKey.count == publicKeySize else {
            throw KazKemError.invalidParameter(
                "Public key must be \(publicKeySize) bytes, got \(publicKey.count)"
            )
        }

        // Generate random shared secret
        var sharedSecret = [UInt8](repeating: 0, count: sharedSecretSize)
        let status = SecRandomCopyBytes(kSecRandomDefault, sharedSecretSize, &sharedSecret)
        guard status == errSecSuccess else {
            throw KazKemError.randomGenerationFailed
        }

        // Ensure message < N by clearing high bits based on security level
        sharedSecret[0] &= securityLevel.randomMask

        var ciphertext = [UInt8](repeating: 0, count: ciphertextSize)
        var ctLen: UInt64 = 0

        let result = publicKey.withUnsafeBytes { pkPtr -> Int32 in
            return kaz_kem_encapsulate(
                &ciphertext,
                &ctLen,
                sharedSecret,
                UInt64(sharedSecret.count),
                pkPtr.baseAddress?.assumingMemoryBound(to: UInt8.self)
            )
        }

        if result != 0 {
            secureZero(&sharedSecret)
            throw KazKemError.from(code: result, operation: "encapsulate")
        }

        return KazKemEncapsulationResult(
            ciphertext: Data(ciphertext.prefix(Int(ctLen))),
            sharedSecret: Data(sharedSecret)
        )
    }

    /// Static convenience method to encapsulate.
    public static func encapsulate(publicKey: KazKemPublicKey) throws -> KazKemEncapsulationResult {
        return try current.encapsulate(publicKey: publicKey)
    }

    /// Static convenience method to encapsulate.
    public static func encapsulate(publicKey: Data) throws -> KazKemEncapsulationResult {
        return try current.encapsulate(publicKey: publicKey)
    }

    // MARK: - Decapsulation

    /// Decapsulate a shared secret using the private key.
    ///
    /// - Parameters:
    ///   - ciphertext: Ciphertext from encapsulation
    ///   - keyPair: Key pair containing the private key
    /// - Returns: The shared secret
    /// - Throws: `KazKemError` if decapsulation fails
    public func decapsulate(ciphertext: Data, keyPair: KazKemKeyPair) throws -> Data {
        return try decapsulate(ciphertext: ciphertext, privateKey: keyPair.privateKey)
    }

    /// Decapsulate a shared secret using the private key bytes.
    ///
    /// - Parameters:
    ///   - ciphertext: Ciphertext from encapsulation
    ///   - privateKey: Private key as Data
    /// - Returns: The shared secret
    /// - Throws: `KazKemError` if decapsulation fails
    public func decapsulate(ciphertext: Data, privateKey: Data) throws -> Data {
        try ensureInitialized()

        guard privateKey.count == privateKeySize else {
            throw KazKemError.invalidParameter(
                "Private key must be \(privateKeySize) bytes, got \(privateKey.count)"
            )
        }

        guard ciphertext.count > 0 && ciphertext.count <= ciphertextSize else {
            throw KazKemError.invalidParameter(
                "Ciphertext must be 1-\(ciphertextSize) bytes, got \(ciphertext.count)"
            )
        }

        var sharedSecret = [UInt8](repeating: 0, count: sharedSecretSize)
        var ssLen: UInt64 = 0

        let result = ciphertext.withUnsafeBytes { ctPtr -> Int32 in
            privateKey.withUnsafeBytes { skPtr -> Int32 in
                return kaz_kem_decapsulate(
                    &sharedSecret,
                    &ssLen,
                    ctPtr.baseAddress?.assumingMemoryBound(to: UInt8.self),
                    UInt64(ciphertext.count),
                    skPtr.baseAddress?.assumingMemoryBound(to: UInt8.self)
                )
            }
        }

        if result != 0 {
            secureZero(&sharedSecret)
            throw KazKemError.from(code: result, operation: "decapsulate")
        }

        return Data(sharedSecret.prefix(Int(ssLen)))
    }

    /// Static convenience method to decapsulate.
    public static func decapsulate(ciphertext: Data, keyPair: KazKemKeyPair) throws -> Data {
        return try current.decapsulate(ciphertext: ciphertext, keyPair: keyPair)
    }

    /// Static convenience method to decapsulate.
    public static func decapsulate(ciphertext: Data, privateKey: Data) throws -> Data {
        return try current.decapsulate(ciphertext: ciphertext, privateKey: privateKey)
    }

    // MARK: - Private Helpers

    private func ensureInitialized() throws {
        guard kaz_kem_is_initialized() != 0 else {
            throw KazKemError.notInitialized
        }
    }
}

// MARK: - Extensions

extension Data {
    /// Convert to hexadecimal string
    public var hexString: String {
        return map { String(format: "%02x", $0) }.joined()
    }

    /// Initialize from hexadecimal string
    public init?(hexString: String) {
        let hex = hexString.lowercased()
        guard hex.count % 2 == 0 else { return nil }

        var data = Data()
        var index = hex.startIndex
        while index < hex.endIndex {
            let nextIndex = hex.index(index, offsetBy: 2)
            guard let byte = UInt8(hex[index..<nextIndex], radix: 16) else { return nil }
            data.append(byte)
            index = nextIndex
        }
        self = data
    }
}
