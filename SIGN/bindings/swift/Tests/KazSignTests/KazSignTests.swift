/*
 * KAZ-SIGN Swift Unit Tests
 * Version 4.0.0
 *
 * Comprehensive test suite covering all security levels and functionality.
 */

import XCTest
@testable import KazSign

final class KazSignTests: XCTestCase {

    // MARK: - Version Tests

    func testVersion() {
        XCTAssertEqual(KazSigner.version, "4.0.0")
        XCTAssertEqual(KazSigner.versionNumber, 40000)
    }

    // MARK: - Security Level Tests

    func testSecurityLevelParameters() {
        // Level 128
        XCTAssertEqual(SecurityLevel.level128.secretKeyBytes, 32)
        XCTAssertEqual(SecurityLevel.level128.publicKeyBytes, 54)
        XCTAssertEqual(SecurityLevel.level128.signatureOverhead, 162)
        XCTAssertEqual(SecurityLevel.level128.hashBytes, 32)
        XCTAssertEqual(SecurityLevel.level128.algorithmName, "KAZ-SIGN-128")

        // Level 192
        XCTAssertEqual(SecurityLevel.level192.secretKeyBytes, 50)
        XCTAssertEqual(SecurityLevel.level192.publicKeyBytes, 88)
        XCTAssertEqual(SecurityLevel.level192.signatureOverhead, 264)
        XCTAssertEqual(SecurityLevel.level192.hashBytes, 48)
        XCTAssertEqual(SecurityLevel.level192.algorithmName, "KAZ-SIGN-192")

        // Level 256
        XCTAssertEqual(SecurityLevel.level256.secretKeyBytes, 64)
        XCTAssertEqual(SecurityLevel.level256.publicKeyBytes, 118)
        XCTAssertEqual(SecurityLevel.level256.signatureOverhead, 354)
        XCTAssertEqual(SecurityLevel.level256.hashBytes, 64)
        XCTAssertEqual(SecurityLevel.level256.algorithmName, "KAZ-SIGN-256")
    }

    func testAllSecurityLevels() {
        XCTAssertEqual(SecurityLevel.allCases.count, 3)
        XCTAssertTrue(SecurityLevel.allCases.contains(.level128))
        XCTAssertTrue(SecurityLevel.allCases.contains(.level192))
        XCTAssertTrue(SecurityLevel.allCases.contains(.level256))
    }

    func testSecurityLevelRawValues() {
        XCTAssertEqual(SecurityLevel.level128.rawValue, 128)
        XCTAssertEqual(SecurityLevel.level192.rawValue, 192)
        XCTAssertEqual(SecurityLevel.level256.rawValue, 256)
    }

    // MARK: - Key Generation Tests (Level 128)

    func testKeyGeneration128() throws {
        let signer = try KazSigner(level: .level128)
        let keyPair = try signer.generateKeyPair()

        XCTAssertEqual(keyPair.publicKey.count, SecurityLevel.level128.publicKeyBytes)
        XCTAssertEqual(keyPair.secretKey.count, SecurityLevel.level128.secretKeyBytes)
        XCTAssertEqual(keyPair.level, .level128)
    }

    func testKeyGenerationUnique128() throws {
        let signer = try KazSigner(level: .level128)
        let keyPair1 = try signer.generateKeyPair()
        let keyPair2 = try signer.generateKeyPair()

        XCTAssertNotEqual(keyPair1.publicKey, keyPair2.publicKey)
        XCTAssertNotEqual(keyPair1.secretKey, keyPair2.secretKey)
    }

    func testKeyGenerationNonZero128() throws {
        let signer = try KazSigner(level: .level128)
        let keyPair = try signer.generateKeyPair()

        XCTAssertFalse(keyPair.publicKey.allSatisfy { $0 == 0 })
        XCTAssertFalse(keyPair.secretKey.allSatisfy { $0 == 0 })
    }

    // MARK: - Key Generation Tests (Level 192)

    func testKeyGeneration192() throws {
        let signer = try KazSigner(level: .level192)
        let keyPair = try signer.generateKeyPair()

        XCTAssertEqual(keyPair.publicKey.count, SecurityLevel.level192.publicKeyBytes)
        XCTAssertEqual(keyPair.secretKey.count, SecurityLevel.level192.secretKeyBytes)
        XCTAssertEqual(keyPair.level, .level192)
    }

    func testKeyGenerationUnique192() throws {
        let signer = try KazSigner(level: .level192)
        let keyPair1 = try signer.generateKeyPair()
        let keyPair2 = try signer.generateKeyPair()

        XCTAssertNotEqual(keyPair1.publicKey, keyPair2.publicKey)
        XCTAssertNotEqual(keyPair1.secretKey, keyPair2.secretKey)
    }

    // MARK: - Key Generation Tests (Level 256)

    func testKeyGeneration256() throws {
        let signer = try KazSigner(level: .level256)
        let keyPair = try signer.generateKeyPair()

        XCTAssertEqual(keyPair.publicKey.count, SecurityLevel.level256.publicKeyBytes)
        XCTAssertEqual(keyPair.secretKey.count, SecurityLevel.level256.secretKeyBytes)
        XCTAssertEqual(keyPair.level, .level256)
    }

    func testKeyGenerationUnique256() throws {
        let signer = try KazSigner(level: .level256)
        let keyPair1 = try signer.generateKeyPair()
        let keyPair2 = try signer.generateKeyPair()

        XCTAssertNotEqual(keyPair1.publicKey, keyPair2.publicKey)
        XCTAssertNotEqual(keyPair1.secretKey, keyPair2.secretKey)
    }

    // MARK: - Signing Tests (Level 128)

    func testSigning128() throws {
        let signer = try KazSigner(level: .level128)
        let keyPair = try signer.generateKeyPair()
        let message = "Hello, World!".data(using: .utf8)!

        let result = try signer.sign(message: message, secretKey: keyPair.secretKey)

        XCTAssertEqual(result.message, message)
        XCTAssertEqual(result.level, .level128)
        XCTAssertEqual(result.signature.count, SecurityLevel.level128.signatureOverhead + message.count)
        XCTAssertEqual(result.overhead, SecurityLevel.level128.signatureOverhead)
    }

    func testSigningString128() throws {
        let signer = try KazSigner(level: .level128)
        let keyPair = try signer.generateKeyPair()
        let message = "Test message"

        let result = try signer.sign(message: message, secretKey: keyPair.secretKey)

        XCTAssertEqual(result.message, message.data(using: .utf8))
    }

    // MARK: - Signing Tests (Level 192)

    func testSigning192() throws {
        let signer = try KazSigner(level: .level192)
        let keyPair = try signer.generateKeyPair()
        let message = "Hello, Level 192!".data(using: .utf8)!

        let result = try signer.sign(message: message, secretKey: keyPair.secretKey)

        XCTAssertEqual(result.message, message)
        XCTAssertEqual(result.level, .level192)
        XCTAssertEqual(result.signature.count, SecurityLevel.level192.signatureOverhead + message.count)
    }

    // MARK: - Signing Tests (Level 256)

    func testSigning256() throws {
        let signer = try KazSigner(level: .level256)
        let keyPair = try signer.generateKeyPair()
        let message = "Hello, Level 256!".data(using: .utf8)!

        let result = try signer.sign(message: message, secretKey: keyPair.secretKey)

        XCTAssertEqual(result.message, message)
        XCTAssertEqual(result.level, .level256)
        XCTAssertEqual(result.signature.count, SecurityLevel.level256.signatureOverhead + message.count)
    }

    // MARK: - Verification Tests (Level 128)

    func testVerification128() throws {
        let signer = try KazSigner(level: .level128)
        let keyPair = try signer.generateKeyPair()
        let message = "Hello, World!".data(using: .utf8)!

        let signResult = try signer.sign(message: message, secretKey: keyPair.secretKey)
        let verifyResult = try signer.verify(signature: signResult.signature, publicKey: keyPair.publicKey)

        XCTAssertTrue(verifyResult.isValid)
        XCTAssertEqual(verifyResult.message, message)
        XCTAssertEqual(verifyResult.level, .level128)
    }

    func testVerificationString128() throws {
        let signer = try KazSigner(level: .level128)
        let keyPair = try signer.generateKeyPair()
        let message = "Test message"

        let signResult = try signer.sign(message: message, secretKey: keyPair.secretKey)
        let (isValid, recovered) = try signer.verifyString(signature: signResult.signature, publicKey: keyPair.publicKey)

        XCTAssertTrue(isValid)
        XCTAssertEqual(recovered, message)
    }

    func testVerificationTamperedSignature128() throws {
        let signer = try KazSigner(level: .level128)
        let keyPair = try signer.generateKeyPair()
        let message = "Hello, World!".data(using: .utf8)!

        let signResult = try signer.sign(message: message, secretKey: keyPair.secretKey)

        // Tamper with signature
        var tamperedSignature = signResult.signature
        tamperedSignature[0] ^= 0xFF

        let verifyResult = try signer.verify(signature: tamperedSignature, publicKey: keyPair.publicKey)

        XCTAssertFalse(verifyResult.isValid)
        XCTAssertNil(verifyResult.message)
    }

    func testVerificationWrongKey128() throws {
        let signer = try KazSigner(level: .level128)
        let keyPair1 = try signer.generateKeyPair()
        let keyPair2 = try signer.generateKeyPair()
        let message = "Hello, World!".data(using: .utf8)!

        let signResult = try signer.sign(message: message, secretKey: keyPair1.secretKey)
        let verifyResult = try signer.verify(signature: signResult.signature, publicKey: keyPair2.publicKey)

        XCTAssertFalse(verifyResult.isValid)
    }

    // MARK: - Verification Tests (Level 192)

    func testVerification192() throws {
        let signer = try KazSigner(level: .level192)
        let keyPair = try signer.generateKeyPair()
        let message = "Test Level 192".data(using: .utf8)!

        let signResult = try signer.sign(message: message, secretKey: keyPair.secretKey)
        let verifyResult = try signer.verify(signature: signResult.signature, publicKey: keyPair.publicKey)

        XCTAssertTrue(verifyResult.isValid)
        XCTAssertEqual(verifyResult.message, message)
    }

    func testVerificationTamperedSignature192() throws {
        let signer = try KazSigner(level: .level192)
        let keyPair = try signer.generateKeyPair()
        let message = "Test Level 192".data(using: .utf8)!

        let signResult = try signer.sign(message: message, secretKey: keyPair.secretKey)
        var tamperedSignature = signResult.signature
        tamperedSignature[0] ^= 0xFF

        let verifyResult = try signer.verify(signature: tamperedSignature, publicKey: keyPair.publicKey)
        XCTAssertFalse(verifyResult.isValid)
    }

    // MARK: - Verification Tests (Level 256)

    func testVerification256() throws {
        let signer = try KazSigner(level: .level256)
        let keyPair = try signer.generateKeyPair()
        let message = "Test Level 256".data(using: .utf8)!

        let signResult = try signer.sign(message: message, secretKey: keyPair.secretKey)
        let verifyResult = try signer.verify(signature: signResult.signature, publicKey: keyPair.publicKey)

        XCTAssertTrue(verifyResult.isValid)
        XCTAssertEqual(verifyResult.message, message)
    }

    func testVerificationTamperedSignature256() throws {
        let signer = try KazSigner(level: .level256)
        let keyPair = try signer.generateKeyPair()
        let message = "Test Level 256".data(using: .utf8)!

        let signResult = try signer.sign(message: message, secretKey: keyPair.secretKey)
        var tamperedSignature = signResult.signature
        tamperedSignature[0] ^= 0xFF

        let verifyResult = try signer.verify(signature: tamperedSignature, publicKey: keyPair.publicKey)
        XCTAssertFalse(verifyResult.isValid)
    }

    // MARK: - Round Trip Tests (All Levels)

    func testRoundTrip128() throws {
        try performRoundTripTest(level: .level128)
    }

    func testRoundTrip192() throws {
        try performRoundTripTest(level: .level192)
    }

    func testRoundTrip256() throws {
        try performRoundTripTest(level: .level256)
    }

    private func performRoundTripTest(level: SecurityLevel) throws {
        let signer = try KazSigner(level: level)
        let keyPair = try signer.generateKeyPair()
        let message = "Round trip test for \(level.algorithmName)".data(using: .utf8)!

        let signResult = try signer.sign(message: message, secretKey: keyPair.secretKey)
        let verifyResult = try signer.verify(signature: signResult.signature, publicKey: keyPair.publicKey)

        XCTAssertTrue(verifyResult.isValid, "Verification should succeed for \(level)")
        XCTAssertEqual(verifyResult.message, message, "Recovered message should match for \(level)")
    }

    // MARK: - Cross-Level Tests

    func testCrossLevelKeyMismatch() throws {
        // Keys from different levels should not be interchangeable
        let signer128 = try KazSigner(level: .level128)
        let signer192 = try KazSigner(level: .level192)

        let keyPair128 = try signer128.generateKeyPair()
        let message = "Test message".data(using: .utf8)!
        let signResult = try signer128.sign(message: message, secretKey: keyPair128.secretKey)

        // Trying to verify with a different level's signer should fail
        // (key sizes are different so this should throw or return invalid)
        XCTAssertThrowsError(try signer192.verify(signature: signResult.signature, publicKey: keyPair128.publicKey))
    }

    func testMultipleLevelsConcurrently() throws {
        // Test that multiple signers at different levels can coexist
        let signer128 = try KazSigner(level: .level128)
        let signer192 = try KazSigner(level: .level192)
        let signer256 = try KazSigner(level: .level256)

        let keyPair128 = try signer128.generateKeyPair()
        let keyPair192 = try signer192.generateKeyPair()
        let keyPair256 = try signer256.generateKeyPair()

        let message = "Multi-level test".data(using: .utf8)!

        // Sign with each level
        let sig128 = try signer128.sign(message: message, secretKey: keyPair128.secretKey)
        let sig192 = try signer192.sign(message: message, secretKey: keyPair192.secretKey)
        let sig256 = try signer256.sign(message: message, secretKey: keyPair256.secretKey)

        // Verify each
        XCTAssertTrue(try signer128.verify(signature: sig128.signature, publicKey: keyPair128.publicKey).isValid)
        XCTAssertTrue(try signer192.verify(signature: sig192.signature, publicKey: keyPair192.publicKey).isValid)
        XCTAssertTrue(try signer256.verify(signature: sig256.signature, publicKey: keyPair256.publicKey).isValid)
    }

    // MARK: - Edge Cases

    func testEmptyMessage() throws {
        let signer = try KazSigner(level: .level128)
        let keyPair = try signer.generateKeyPair()
        let message = Data()

        let signResult = try signer.sign(message: message, secretKey: keyPair.secretKey)
        let verifyResult = try signer.verify(signature: signResult.signature, publicKey: keyPair.publicKey)

        XCTAssertTrue(verifyResult.isValid)
        XCTAssertEqual(verifyResult.message, message)
    }

    func testEmptyMessage192() throws {
        let signer = try KazSigner(level: .level192)
        let keyPair = try signer.generateKeyPair()
        let message = Data()

        let signResult = try signer.sign(message: message, secretKey: keyPair.secretKey)
        let verifyResult = try signer.verify(signature: signResult.signature, publicKey: keyPair.publicKey)

        XCTAssertTrue(verifyResult.isValid)
    }

    func testEmptyMessage256() throws {
        let signer = try KazSigner(level: .level256)
        let keyPair = try signer.generateKeyPair()
        let message = Data()

        let signResult = try signer.sign(message: message, secretKey: keyPair.secretKey)
        let verifyResult = try signer.verify(signature: signResult.signature, publicKey: keyPair.publicKey)

        XCTAssertTrue(verifyResult.isValid)
    }

    func testLargeMessage() throws {
        let signer = try KazSigner(level: .level128)
        let keyPair = try signer.generateKeyPair()
        let message = Data(repeating: 0x42, count: 10000)

        let signResult = try signer.sign(message: message, secretKey: keyPair.secretKey)
        let verifyResult = try signer.verify(signature: signResult.signature, publicKey: keyPair.publicKey)

        XCTAssertTrue(verifyResult.isValid)
        XCTAssertEqual(verifyResult.message, message)
    }

    func testVeryLargeMessage() throws {
        let signer = try KazSigner(level: .level128)
        let keyPair = try signer.generateKeyPair()
        let message = Data(repeating: 0xAB, count: 100000)  // 100KB

        let signResult = try signer.sign(message: message, secretKey: keyPair.secretKey)
        let verifyResult = try signer.verify(signature: signResult.signature, publicKey: keyPair.publicKey)

        XCTAssertTrue(verifyResult.isValid)
        XCTAssertEqual(verifyResult.message?.count, message.count)
    }

    func testBinaryMessage() throws {
        let signer = try KazSigner(level: .level128)
        let keyPair = try signer.generateKeyPair()
        var message = Data()
        for i: UInt8 in 0...255 {
            message.append(i)
        }

        let signResult = try signer.sign(message: message, secretKey: keyPair.secretKey)
        let verifyResult = try signer.verify(signature: signResult.signature, publicKey: keyPair.publicKey)

        XCTAssertTrue(verifyResult.isValid)
        XCTAssertEqual(verifyResult.message, message)
    }

    func testSingleByteMessage() throws {
        let signer = try KazSigner(level: .level128)
        let keyPair = try signer.generateKeyPair()
        let message = Data([0x42])

        let signResult = try signer.sign(message: message, secretKey: keyPair.secretKey)
        let verifyResult = try signer.verify(signature: signResult.signature, publicKey: keyPair.publicKey)

        XCTAssertTrue(verifyResult.isValid)
        XCTAssertEqual(verifyResult.message, message)
    }

    func testUnicodeMessage() throws {
        let signer = try KazSigner(level: .level128)
        let keyPair = try signer.generateKeyPair()
        let message = "Hello 世界! 🌍🔐".data(using: .utf8)!

        let signResult = try signer.sign(message: message, secretKey: keyPair.secretKey)
        let verifyResult = try signer.verify(signature: signResult.signature, publicKey: keyPair.publicKey)

        XCTAssertTrue(verifyResult.isValid)
        XCTAssertEqual(verifyResult.message, message)
    }

    // MARK: - Error Handling

    func testInvalidSecretKeySize() throws {
        let signer = try KazSigner(level: .level128)
        let message = "Test".data(using: .utf8)!
        let invalidSecretKey = Data(repeating: 0, count: 16) // Wrong size

        XCTAssertThrowsError(try signer.sign(message: message, secretKey: invalidSecretKey)) { error in
            XCTAssertEqual(error as? KazSignError, .invalidKeySize)
        }
    }

    func testInvalidPublicKeySize() throws {
        let signer = try KazSigner(level: .level128)
        let keyPair = try signer.generateKeyPair()
        let message = "Test".data(using: .utf8)!
        let signResult = try signer.sign(message: message, secretKey: keyPair.secretKey)
        let invalidPublicKey = Data(repeating: 0, count: 16) // Wrong size

        XCTAssertThrowsError(try signer.verify(signature: signResult.signature, publicKey: invalidPublicKey)) { error in
            XCTAssertEqual(error as? KazSignError, .invalidKeySize)
        }
    }

    func testTruncatedSignature() throws {
        let signer = try KazSigner(level: .level128)
        let keyPair = try signer.generateKeyPair()
        let truncatedSignature = Data(repeating: 0, count: 10) // Too short

        let verifyResult = try signer.verify(signature: truncatedSignature, publicKey: keyPair.publicKey)

        XCTAssertFalse(verifyResult.isValid)
    }

    func testEmptySignature() throws {
        let signer = try KazSigner(level: .level128)
        let keyPair = try signer.generateKeyPair()

        let verifyResult = try signer.verify(signature: Data(), publicKey: keyPair.publicKey)

        XCTAssertFalse(verifyResult.isValid)
    }

    // MARK: - Hash Tests

    func testHash128() throws {
        let signer = try KazSigner(level: .level128)
        let message = "Hello, World!".data(using: .utf8)!

        let hash = try signer.hash(message: message)

        XCTAssertEqual(hash.count, SecurityLevel.level128.hashBytes)
    }

    func testHash192() throws {
        let signer = try KazSigner(level: .level192)
        let message = "Hello, World!".data(using: .utf8)!

        let hash = try signer.hash(message: message)

        XCTAssertEqual(hash.count, SecurityLevel.level192.hashBytes)
    }

    func testHash256() throws {
        let signer = try KazSigner(level: .level256)
        let message = "Hello, World!".data(using: .utf8)!

        let hash = try signer.hash(message: message)

        XCTAssertEqual(hash.count, SecurityLevel.level256.hashBytes)
    }

    func testHashDeterministic() throws {
        let signer = try KazSigner(level: .level128)
        let message = "Test message".data(using: .utf8)!

        let hash1 = try signer.hash(message: message)
        let hash2 = try signer.hash(message: message)

        XCTAssertEqual(hash1, hash2)
    }

    func testHashDifferentMessages() throws {
        let signer = try KazSigner(level: .level128)
        let message1 = "Message 1".data(using: .utf8)!
        let message2 = "Message 2".data(using: .utf8)!

        let hash1 = try signer.hash(message: message1)
        let hash2 = try signer.hash(message: message2)

        XCTAssertNotEqual(hash1, hash2)
    }

    func testHashString() throws {
        let signer = try KazSigner(level: .level128)
        let message = "Test string"

        let hash = try signer.hash(message: message)

        XCTAssertEqual(hash.count, SecurityLevel.level128.hashBytes)
    }

    func testHashEmpty() throws {
        let signer = try KazSigner(level: .level128)
        let hash = try signer.hash(message: Data())

        XCTAssertEqual(hash.count, SecurityLevel.level128.hashBytes)
        XCTAssertFalse(hash.allSatisfy { $0 == 0 })  // Hash of empty should not be all zeros
    }

    func testHashNonZero() throws {
        let signer = try KazSigner(level: .level128)
        let message = "Test".data(using: .utf8)!
        let hash = try signer.hash(message: message)

        XCTAssertFalse(hash.allSatisfy { $0 == 0 })
    }

    // MARK: - Multiple Operations

    func testMultipleSignatures() throws {
        let signer = try KazSigner(level: .level128)
        let keyPair = try signer.generateKeyPair()

        let messages = ["Message 1", "Message 2", "Message 3"]

        for message in messages {
            let messageData = message.data(using: .utf8)!
            let signResult = try signer.sign(message: messageData, secretKey: keyPair.secretKey)
            let verifyResult = try signer.verify(signature: signResult.signature, publicKey: keyPair.publicKey)

            XCTAssertTrue(verifyResult.isValid)
            XCTAssertEqual(verifyResult.message, messageData)
        }
    }

    func testMultipleKeyPairs() throws {
        let signer = try KazSigner(level: .level128)
        let message = "Same message".data(using: .utf8)!

        for _ in 0..<5 {
            let keyPair = try signer.generateKeyPair()
            let signResult = try signer.sign(message: message, secretKey: keyPair.secretKey)
            let verifyResult = try signer.verify(signature: signResult.signature, publicKey: keyPair.publicKey)

            XCTAssertTrue(verifyResult.isValid)
        }
    }

    func testRepeatedSignVerify() throws {
        let signer = try KazSigner(level: .level128)
        let keyPair = try signer.generateKeyPair()
        let message = "Repeated test".data(using: .utf8)!

        for _ in 0..<10 {
            let signResult = try signer.sign(message: message, secretKey: keyPair.secretKey)
            let verifyResult = try signer.verify(signature: signResult.signature, publicKey: keyPair.publicKey)
            XCTAssertTrue(verifyResult.isValid)
        }
    }

    // MARK: - Data Extension Tests

    func testHexStringConversion() {
        let data = Data([0x00, 0x01, 0x0F, 0xFF, 0xAB])
        XCTAssertEqual(data.hexString, "00010fffab")
    }

    func testHexStringInit() {
        let data = Data(hexString: "00010fffab")
        XCTAssertEqual(data, Data([0x00, 0x01, 0x0F, 0xFF, 0xAB]))
    }

    func testHexStringInitUppercase() {
        let data = Data(hexString: "00010FFFAB")
        XCTAssertEqual(data, Data([0x00, 0x01, 0x0F, 0xFF, 0xAB]))
    }

    func testHexStringInitInvalid() {
        let data = Data(hexString: "invalid")
        XCTAssertNil(data)
    }

    func testHexStringInitOddLength() {
        let data = Data(hexString: "abc")
        XCTAssertNil(data)
    }

    func testHexStringEmpty() {
        let data = Data(hexString: "")
        XCTAssertEqual(data, Data())
    }

    func testHexStringRoundTrip() {
        let original = Data([0xDE, 0xAD, 0xBE, 0xEF])
        let hex = original.hexString
        let restored = Data(hexString: hex)
        XCTAssertEqual(restored, original)
    }
}

// MARK: - Performance Tests

extension KazSignTests {
    func testKeyGenerationPerformance128() throws {
        let signer = try KazSigner(level: .level128)

        measure {
            _ = try? signer.generateKeyPair()
        }
    }

    func testKeyGenerationPerformance192() throws {
        let signer = try KazSigner(level: .level192)

        measure {
            _ = try? signer.generateKeyPair()
        }
    }

    func testKeyGenerationPerformance256() throws {
        let signer = try KazSigner(level: .level256)

        measure {
            _ = try? signer.generateKeyPair()
        }
    }

    func testSigningPerformance128() throws {
        let signer = try KazSigner(level: .level128)
        let keyPair = try signer.generateKeyPair()
        let message = "Performance test message".data(using: .utf8)!

        measure {
            _ = try? signer.sign(message: message, secretKey: keyPair.secretKey)
        }
    }

    func testSigningPerformance192() throws {
        let signer = try KazSigner(level: .level192)
        let keyPair = try signer.generateKeyPair()
        let message = "Performance test message".data(using: .utf8)!

        measure {
            _ = try? signer.sign(message: message, secretKey: keyPair.secretKey)
        }
    }

    func testSigningPerformance256() throws {
        let signer = try KazSigner(level: .level256)
        let keyPair = try signer.generateKeyPair()
        let message = "Performance test message".data(using: .utf8)!

        measure {
            _ = try? signer.sign(message: message, secretKey: keyPair.secretKey)
        }
    }

    func testVerificationPerformance128() throws {
        let signer = try KazSigner(level: .level128)
        let keyPair = try signer.generateKeyPair()
        let message = "Performance test message".data(using: .utf8)!
        let signResult = try signer.sign(message: message, secretKey: keyPair.secretKey)

        measure {
            _ = try? signer.verify(signature: signResult.signature, publicKey: keyPair.publicKey)
        }
    }

    func testVerificationPerformance192() throws {
        let signer = try KazSigner(level: .level192)
        let keyPair = try signer.generateKeyPair()
        let message = "Performance test message".data(using: .utf8)!
        let signResult = try signer.sign(message: message, secretKey: keyPair.secretKey)

        measure {
            _ = try? signer.verify(signature: signResult.signature, publicKey: keyPair.publicKey)
        }
    }

    func testVerificationPerformance256() throws {
        let signer = try KazSigner(level: .level256)
        let keyPair = try signer.generateKeyPair()
        let message = "Performance test message".data(using: .utf8)!
        let signResult = try signer.sign(message: message, secretKey: keyPair.secretKey)

        measure {
            _ = try? signer.verify(signature: signResult.signature, publicKey: keyPair.publicKey)
        }
    }

    func testHashPerformance128() throws {
        let signer = try KazSigner(level: .level128)
        let message = Data(repeating: 0x42, count: 1000)

        measure {
            _ = try? signer.hash(message: message)
        }
    }
}

// MARK: - Stress Tests

extension KazSignTests {
    func testStressKeyGeneration() throws {
        let signer = try KazSigner(level: .level128)
        var keyPairs: [KeyPair] = []

        for _ in 0..<100 {
            let keyPair = try signer.generateKeyPair()
            keyPairs.append(keyPair)
        }

        // All keys should be unique
        let publicKeys = Set(keyPairs.map { $0.publicKey })
        XCTAssertEqual(publicKeys.count, 100)
    }

    func testStressSignVerify() throws {
        let signer = try KazSigner(level: .level128)
        let keyPair = try signer.generateKeyPair()

        for i in 0..<50 {
            let message = "Stress test message \(i)".data(using: .utf8)!
            let signResult = try signer.sign(message: message, secretKey: keyPair.secretKey)
            let verifyResult = try signer.verify(signature: signResult.signature, publicKey: keyPair.publicKey)

            XCTAssertTrue(verifyResult.isValid, "Failed at iteration \(i)")
            XCTAssertEqual(verifyResult.message, message, "Message mismatch at iteration \(i)")
        }
    }
}
