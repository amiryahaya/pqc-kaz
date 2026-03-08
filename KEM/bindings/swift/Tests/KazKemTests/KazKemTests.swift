import XCTest
@testable import KazKem

final class KazKemTests: XCTestCase {

    override func tearDown() {
        KazKem.cleanup()
        super.tearDown()
    }

    // MARK: - Initialization Tests

    func testInitializeLevel128() throws {
        let kem = try KazKem.initialize(level: .level128)
        XCTAssertEqual(kem.securityLevel, .level128)
        XCTAssertTrue(KazKem.isInitialized)
    }

    func testInitializeLevel192() throws {
        let kem = try KazKem.initialize(level: .level192)
        XCTAssertEqual(kem.securityLevel, .level192)
    }

    func testInitializeLevel256() throws {
        let kem = try KazKem.initialize(level: .level256)
        XCTAssertEqual(kem.securityLevel, .level256)
    }

    func testVersion() throws {
        _ = try KazKem.initialize()
        let version = KazKem.version
        XCTAssertFalse(version.isEmpty)
        XCTAssertTrue(version.contains("2.1"))
    }

    func testIsInitializedAfterCleanup() throws {
        _ = try KazKem.initialize()
        XCTAssertTrue(KazKem.isInitialized)
        KazKem.cleanup()
        XCTAssertFalse(KazKem.isInitialized)
    }

    // MARK: - Key Generation Tests

    func testGenerateKeyPair() throws {
        let kem = try KazKem.initialize()
        let keyPair = try kem.generateKeyPair()

        XCTAssertEqual(keyPair.publicKeySize, kem.publicKeySize)
        XCTAssertEqual(keyPair.privateKeySize, kem.privateKeySize)
        XCTAssertEqual(keyPair.securityLevel, .level128)
    }

    func testMultipleKeyPairsAreUnique() throws {
        let kem = try KazKem.initialize()

        let keyPair1 = try kem.generateKeyPair()
        let keyPair2 = try kem.generateKeyPair()
        let keyPair3 = try kem.generateKeyPair()

        XCTAssertNotEqual(keyPair1.publicKey, keyPair2.publicKey)
        XCTAssertNotEqual(keyPair2.publicKey, keyPair3.publicKey)
        XCTAssertNotEqual(keyPair1.privateKey, keyPair2.privateKey)
    }

    func testKeyPairGetPublicKey() throws {
        let kem = try KazKem.initialize()
        let keyPair = try kem.generateKeyPair()
        let publicKey = keyPair.getPublicKey()

        XCTAssertEqual(publicKey.data, keyPair.publicKey)
        XCTAssertEqual(publicKey.securityLevel, keyPair.securityLevel)
    }

    // MARK: - Encapsulation Tests

    func testEncapsulateDecapsulate() throws {
        let kem = try KazKem.initialize()
        let keyPair = try kem.generateKeyPair()

        let encResult = try kem.encapsulate(publicKey: keyPair.getPublicKey())
        let decapsulatedSecret = try kem.decapsulate(ciphertext: encResult.ciphertext, keyPair: keyPair)

        XCTAssertEqual(encResult.sharedSecret, decapsulatedSecret)
    }

    func testEncapsulateWithPublicKeyData() throws {
        let kem = try KazKem.initialize()
        let keyPair = try kem.generateKeyPair()

        let encResult = try kem.encapsulate(publicKey: keyPair.publicKey)
        let decapsulatedSecret = try kem.decapsulate(ciphertext: encResult.ciphertext, privateKey: keyPair.privateKey)

        XCTAssertEqual(encResult.sharedSecret, decapsulatedSecret)
    }

    func testEncapsulateMultipleTimesProducesDifferentResults() throws {
        let kem = try KazKem.initialize()
        let keyPair = try kem.generateKeyPair()

        let result1 = try kem.encapsulate(publicKey: keyPair.getPublicKey())
        let result2 = try kem.encapsulate(publicKey: keyPair.getPublicKey())

        XCTAssertNotEqual(result1.ciphertext, result2.ciphertext)
        XCTAssertNotEqual(result1.sharedSecret, result2.sharedSecret)
    }

    func testDecapsulateWithWrongKeyProducesDifferentSecret() throws {
        let kem = try KazKem.initialize()
        let keyPair1 = try kem.generateKeyPair()
        let keyPair2 = try kem.generateKeyPair()

        let encResult = try kem.encapsulate(publicKey: keyPair1.getPublicKey())
        let wrongSecret = try kem.decapsulate(ciphertext: encResult.ciphertext, keyPair: keyPair2)

        XCTAssertNotEqual(encResult.sharedSecret, wrongSecret)
    }

    // MARK: - All Security Levels Tests

    func testEncapsulateDecapsulateLevel192() throws {
        let kem = try KazKem.initialize(level: .level192)
        let keyPair = try kem.generateKeyPair()

        let encResult = try kem.encapsulate(publicKey: keyPair.getPublicKey())
        let decapsulatedSecret = try kem.decapsulate(ciphertext: encResult.ciphertext, keyPair: keyPair)

        XCTAssertEqual(encResult.sharedSecret, decapsulatedSecret)
    }

    func testEncapsulateDecapsulateLevel256() throws {
        let kem = try KazKem.initialize(level: .level256)
        let keyPair = try kem.generateKeyPair()

        let encResult = try kem.encapsulate(publicKey: keyPair.getPublicKey())
        let decapsulatedSecret = try kem.decapsulate(ciphertext: encResult.ciphertext, keyPair: keyPair)

        XCTAssertEqual(encResult.sharedSecret, decapsulatedSecret)
    }

    // MARK: - Error Handling Tests

    func testEncapsulateWithWrongSizePublicKey() throws {
        let kem = try KazKem.initialize()
        let wrongSizeKey = Data(repeating: 0, count: 16)

        XCTAssertThrowsError(try kem.encapsulate(publicKey: wrongSizeKey)) { error in
            guard case KazKemError.invalidParameter = error else {
                XCTFail("Expected invalidParameter error")
                return
            }
        }
    }

    func testDecapsulateWithWrongSizePrivateKey() throws {
        let kem = try KazKem.initialize()
        let keyPair = try kem.generateKeyPair()
        let encResult = try kem.encapsulate(publicKey: keyPair.getPublicKey())
        let wrongSizeKey = Data(repeating: 0, count: 16)

        XCTAssertThrowsError(try kem.decapsulate(ciphertext: encResult.ciphertext, privateKey: wrongSizeKey)) { error in
            guard case KazKemError.invalidParameter = error else {
                XCTFail("Expected invalidParameter error")
                return
            }
        }
    }

    func testCurrentThrowsWhenNotInitialized() {
        KazKem.cleanup()
        XCTAssertThrowsError(try KazKem.current) { error in
            guard case KazKemError.notInitialized = error else {
                XCTFail("Expected notInitialized error")
                return
            }
        }
    }

    // MARK: - Static Method Tests

    func testStaticGenerateKeyPair() throws {
        _ = try KazKem.initialize()
        let keyPair = try KazKem.generateKeyPair()
        XCTAssertFalse(keyPair.publicKey.isEmpty)
    }

    func testStaticEncapsulateDecapsulate() throws {
        _ = try KazKem.initialize()
        let keyPair = try KazKem.generateKeyPair()

        let encResult = try KazKem.encapsulate(publicKey: keyPair.getPublicKey())
        let decapsulatedSecret = try KazKem.decapsulate(ciphertext: encResult.ciphertext, keyPair: keyPair)

        XCTAssertEqual(encResult.sharedSecret, decapsulatedSecret)
    }

    // MARK: - Data Extension Tests

    func testDataHexString() {
        let data = Data([0x00, 0x11, 0xAA, 0xFF])
        XCTAssertEqual(data.hexString, "0011aaff")
    }

    func testDataFromHexString() {
        let data = Data(hexString: "0011aaff")
        XCTAssertNotNil(data)
        XCTAssertEqual(data, Data([0x00, 0x11, 0xAA, 0xFF]))
    }

    func testDataFromInvalidHexString() {
        let data = Data(hexString: "xyz")
        XCTAssertNil(data)
    }

    // MARK: - Integration Tests

    func testFullKeyExchange() throws {
        // Alice generates key pair
        let alice = try KazKem.initialize(level: .level128)
        let aliceKeyPair = try alice.generateKeyPair()

        // Alice shares her public key with Bob
        let alicePublicKey = aliceKeyPair.getPublicKey()

        // Bob encapsulates a shared secret
        let bobEncapsulation = try alice.encapsulate(publicKey: alicePublicKey)
        let bobSecret = bobEncapsulation.sharedSecret

        // Bob sends ciphertext to Alice
        let ciphertext = bobEncapsulation.ciphertext

        // Alice decapsulates to get the shared secret
        let aliceSecret = try alice.decapsulate(ciphertext: ciphertext, keyPair: aliceKeyPair)

        // Both have the same shared secret
        XCTAssertEqual(aliceSecret, bobSecret)
    }

    func testKeyPairSerialization() throws {
        let kem = try KazKem.initialize()
        let originalKeyPair = try kem.generateKeyPair()

        // Export keys
        let publicKeyData = originalKeyPair.publicKey
        let privateKeyData = originalKeyPair.privateKey

        // Simulate storage/retrieval
        let publicKeyBase64 = publicKeyData.base64EncodedString()
        let privateKeyBase64 = privateKeyData.base64EncodedString()

        // Reconstruct
        let restoredPublicKey = Data(base64Encoded: publicKeyBase64)!
        let restoredPrivateKey = Data(base64Encoded: privateKeyBase64)!

        // Use restored keys
        let publicKey = KazKemPublicKey(data: restoredPublicKey, securityLevel: .level128)
        let encResult = try kem.encapsulate(publicKey: publicKey)
        let decapsulatedSecret = try kem.decapsulate(ciphertext: encResult.ciphertext, privateKey: restoredPrivateKey)

        XCTAssertEqual(encResult.sharedSecret, decapsulatedSecret)
    }

    func testLargeNumberOfOperations() throws {
        let kem = try KazKem.initialize()
        let keyPair = try kem.generateKeyPair()

        for _ in 0..<100 {
            let encResult = try kem.encapsulate(publicKey: keyPair.getPublicKey())
            let decapsulatedSecret = try kem.decapsulate(ciphertext: encResult.ciphertext, keyPair: keyPair)
            XCTAssertEqual(encResult.sharedSecret, decapsulatedSecret)
        }
    }

    // MARK: - Thread Safety Tests

    func testConcurrentEncapsulation() throws {
        let kem = try KazKem.initialize()
        let keyPair = try kem.generateKeyPair()
        let publicKey = keyPair.getPublicKey()

        let expectation = XCTestExpectation(description: "Concurrent encapsulation")
        expectation.expectedFulfillmentCount = 10

        let queue = DispatchQueue(label: "test.concurrent", attributes: .concurrent)

        for _ in 0..<10 {
            queue.async {
                do {
                    let result = try kem.encapsulate(publicKey: publicKey)
                    let secret = try kem.decapsulate(ciphertext: result.ciphertext, keyPair: keyPair)
                    XCTAssertEqual(result.sharedSecret, secret)
                    expectation.fulfill()
                } catch {
                    XCTFail("Concurrent operation failed: \(error)")
                }
            }
        }

        wait(for: [expectation], timeout: 10.0)
    }

    func testConcurrentKeyGeneration() throws {
        _ = try KazKem.initialize()

        let expectation = XCTestExpectation(description: "Concurrent key generation")
        expectation.expectedFulfillmentCount = 10

        let queue = DispatchQueue(label: "test.keygen", attributes: .concurrent)

        for _ in 0..<10 {
            queue.async {
                do {
                    let keyPair = try KazKem.generateKeyPair()
                    XCTAssertFalse(keyPair.publicKey.isEmpty)
                    XCTAssertFalse(keyPair.privateKey.isEmpty)
                    expectation.fulfill()
                } catch {
                    XCTFail("Concurrent key generation failed: \(error)")
                }
            }
        }

        wait(for: [expectation], timeout: 10.0)
    }

    // MARK: - Input Validation Tests

    func testDecapsulateWithEmptyCiphertext() throws {
        let kem = try KazKem.initialize()
        let keyPair = try kem.generateKeyPair()
        let emptyCiphertext = Data()

        XCTAssertThrowsError(try kem.decapsulate(ciphertext: emptyCiphertext, keyPair: keyPair)) { error in
            guard case KazKemError.invalidParameter = error else {
                XCTFail("Expected invalidParameter error for empty ciphertext")
                return
            }
        }
    }

    func testDecapsulateWithOversizedCiphertext() throws {
        let kem = try KazKem.initialize()
        let keyPair = try kem.generateKeyPair()
        let oversizedCiphertext = Data(repeating: 0, count: kem.ciphertextSize + 100)

        XCTAssertThrowsError(try kem.decapsulate(ciphertext: oversizedCiphertext, keyPair: keyPair)) { error in
            guard case KazKemError.invalidParameter = error else {
                XCTFail("Expected invalidParameter error for oversized ciphertext")
                return
            }
        }
    }

    // MARK: - Security Tests

    func testEncapsulationResultClear() throws {
        let kem = try KazKem.initialize()
        let keyPair = try kem.generateKeyPair()

        var result = try kem.encapsulate(publicKey: keyPair.getPublicKey())
        let originalSecret = result.sharedSecret

        XCTAssertFalse(originalSecret.isEmpty)

        result.clear()

        // After clearing, shared secret should be empty or zeroed
        XCTAssertTrue(result.sharedSecret.isEmpty || result.sharedSecret.allSatisfy { $0 == 0 })
    }

    func testKeyPairDeallocation() throws {
        weak var weakKeyPair: KazKemKeyPair?

        try autoreleasepool {
            let kem = try KazKem.initialize()
            let keyPair = try kem.generateKeyPair()
            weakKeyPair = keyPair

            // Use the key pair
            _ = try kem.encapsulate(publicKey: keyPair.getPublicKey())
        }

        // Key pair should be deallocated (and memory cleared)
        XCTAssertNil(weakKeyPair)
    }

    // MARK: - Edge Cases

    func testReinitializeWithDifferentLevel() throws {
        let kem128 = try KazKem.initialize(level: .level128)
        XCTAssertEqual(kem128.securityLevel, .level128)

        let kem256 = try KazKem.initialize(level: .level256)
        XCTAssertEqual(kem256.securityLevel, .level256)

        // Verify sizes changed
        XCTAssertNotEqual(kem128.publicKeySize, kem256.publicKeySize)
    }

    func testKeyPairFromRestoredKeys() throws {
        let kem = try KazKem.initialize()
        let original = try kem.generateKeyPair()

        // Restore keys from raw data
        let publicKey = KazKemPublicKey(data: original.publicKey, securityLevel: .level128)

        // Encapsulate with restored public key
        let result = try kem.encapsulate(publicKey: publicKey)

        // Decapsulate with original private key
        let secret = try kem.decapsulate(ciphertext: result.ciphertext, privateKey: original.privateKey)

        XCTAssertEqual(result.sharedSecret, secret)
    }
}
