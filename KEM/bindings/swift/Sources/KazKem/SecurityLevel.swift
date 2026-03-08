import Foundation

/// KAZ-KEM security levels corresponding to NIST post-quantum security categories.
public enum SecurityLevel: Int, Sendable, CaseIterable {
    /// 128-bit security (NIST Level 1) - Equivalent to AES-128
    case level128 = 128

    /// 192-bit security (NIST Level 3) - Equivalent to AES-192
    case level192 = 192

    /// 256-bit security (NIST Level 5) - Equivalent to AES-256
    case level256 = 256

    /// Human-readable description
    public var description: String {
        switch self {
        case .level128: return "128-bit (NIST Level 1)"
        case .level192: return "192-bit (NIST Level 3)"
        case .level256: return "256-bit (NIST Level 5)"
        }
    }

    /// Bit mask for generating random values smaller than modulus N
    internal var randomMask: UInt8 {
        switch self {
        case .level128: return 0x7F  // Clear 1 bit
        case .level192: return 0x1F  // Clear 3 bits
        case .level256: return 0x1F  // Clear 3 bits
        }
    }
}
