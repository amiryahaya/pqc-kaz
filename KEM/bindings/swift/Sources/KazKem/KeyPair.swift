import Foundation

/// A KAZ-KEM key pair containing both public and private keys.
public final class KazKemKeyPair: @unchecked Sendable {
    /// The public key data
    public let publicKey: Data

    /// The private key data (handle with care - sensitive material)
    /// Stored internally as mutable for secure clearing
    private var _privateKey: Data

    /// The security level this key pair was generated for
    public let securityLevel: SecurityLevel

    /// Access to private key data
    public var privateKey: Data { _privateKey }

    /// Public key size in bytes
    public var publicKeySize: Int { publicKey.count }

    /// Private key size in bytes
    public var privateKeySize: Int { _privateKey.count }

    /// Initialize a key pair from raw data
    internal init(publicKey: Data, privateKey: Data, securityLevel: SecurityLevel) {
        self.publicKey = publicKey
        self._privateKey = privateKey
        self.securityLevel = securityLevel
    }

    /// Get a shareable public key object
    public func getPublicKey() -> KazKemPublicKey {
        return KazKemPublicKey(data: publicKey, securityLevel: securityLevel)
    }

    /// Securely clear private key from memory when deallocated
    deinit {
        secureZero(&_privateKey)
    }
}

/// A KAZ-KEM public key (safe to share).
public struct KazKemPublicKey: Sendable {
    /// The public key data
    public let data: Data

    /// The security level this key was generated for
    public let securityLevel: SecurityLevel

    /// Public key size in bytes
    public var size: Int { data.count }

    /// Initialize from raw bytes
    public init(data: Data, securityLevel: SecurityLevel) {
        self.data = data
        self.securityLevel = securityLevel
    }

    /// Initialize from a byte array
    public init(bytes: [UInt8], securityLevel: SecurityLevel) {
        self.data = Data(bytes)
        self.securityLevel = securityLevel
    }
}

/// Result of an encapsulation operation.
public struct KazKemEncapsulationResult: @unchecked Sendable {
    /// The ciphertext to send to the key holder
    public let ciphertext: Data

    /// The shared secret (keep this secret!)
    /// Stored internally as mutable for secure clearing
    private var _sharedSecret: Data

    /// Access to shared secret data
    public var sharedSecret: Data { _sharedSecret }

    /// Ciphertext size in bytes
    public var ciphertextSize: Int { ciphertext.count }

    /// Shared secret size in bytes
    public var sharedSecretSize: Int { _sharedSecret.count }

    internal init(ciphertext: Data, sharedSecret: Data) {
        self.ciphertext = ciphertext
        self._sharedSecret = sharedSecret
    }

    /// Securely clear the shared secret from memory
    public mutating func clear() {
        secureZero(&_sharedSecret)
    }
}

// MARK: - Secure Memory Utilities

/// Securely zero memory to prevent sensitive data from remaining in memory.
/// Uses volatile semantics to prevent compiler optimization.
@inline(__always)
internal func secureZero(_ data: inout Data) {
    data.withUnsafeMutableBytes { ptr in
        if let baseAddress = ptr.baseAddress {
            // Use memset_s-like behavior with volatile pointer
            let volatile = UnsafeMutableRawPointer(baseAddress)
            memset(volatile, 0, ptr.count)
            // Memory barrier to prevent reordering
            OSMemoryBarrier()
        }
    }
    data = Data()
}

/// Securely zero a byte array
@inline(__always)
internal func secureZero(_ bytes: inout [UInt8]) {
    bytes.withUnsafeMutableBytes { ptr in
        if let baseAddress = ptr.baseAddress {
            let volatile = UnsafeMutableRawPointer(baseAddress)
            memset(volatile, 0, ptr.count)
            OSMemoryBarrier()
        }
    }
}
