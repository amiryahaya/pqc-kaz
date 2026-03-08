import Foundation

/// Errors that can occur during KAZ-KEM operations.
public enum KazKemError: Error, LocalizedError, Sendable {
    /// Invalid parameter passed to function
    case invalidParameter(String)

    /// Memory allocation failed
    case memoryAllocation

    /// Random number generation failed
    case randomGenerationFailed

    /// OpenSSL operation failed
    case cryptographicError

    /// Message value exceeds modulus
    case messageTooLarge

    /// KAZ-KEM not initialized
    case notInitialized

    /// Invalid security level
    case invalidSecurityLevel(Int)

    /// Unknown error with native error code
    case unknown(Int32)

    /// Create error from native error code
    internal static func from(code: Int32, operation: String = "") -> KazKemError {
        switch code {
        case -1: return .invalidParameter(operation)
        case -2: return .memoryAllocation
        case -3: return .randomGenerationFailed
        case -4: return .cryptographicError
        case -5: return .messageTooLarge
        case -6: return .notInitialized
        case -7: return .invalidSecurityLevel(0)
        default: return .unknown(code)
        }
    }

    public var errorDescription: String? {
        switch self {
        case .invalidParameter(let operation):
            return "Invalid parameter\(operation.isEmpty ? "" : " in \(operation)")"
        case .memoryAllocation:
            return "Memory allocation failed"
        case .randomGenerationFailed:
            return "Random number generation failed"
        case .cryptographicError:
            return "Cryptographic operation failed"
        case .messageTooLarge:
            return "Message value exceeds modulus"
        case .notInitialized:
            return "KAZ-KEM is not initialized. Call KazKem.initialize() first."
        case .invalidSecurityLevel(let level):
            return "Invalid security level: \(level). Valid levels are 128, 192, or 256."
        case .unknown(let code):
            return "Unknown error (code: \(code))"
        }
    }
}
