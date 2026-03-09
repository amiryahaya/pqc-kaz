# KAZ-KEM Swift Bindings

Post-Quantum Key Encapsulation Mechanism (KEM) library for Apple platforms. This library provides quantum-resistant key exchange capabilities using the KAZ-KEM algorithm.

## Features

- **Post-Quantum Security**: Resistant to attacks from quantum computers
- **Three Security Levels**: 128-bit, 192-bit, and 256-bit security
- **Thread-Safe**: Safe for concurrent use across multiple threads
- **Swift-Native API**: Idiomatic Swift with proper error handling
- **Cross-Platform**: Supports iOS, macOS, tvOS, and watchOS
- **Async/Await Ready**: Modern Swift concurrency support

## Requirements

- Swift 5.9+
- macOS 12.0+ / iOS 15.0+ / tvOS 15.0+ / watchOS 8.0+
- Xcode 15.0+

## Installation

### Swift Package Manager

Add to your `Package.swift`:

```swift
dependencies: [
    .package(url: "https://github.com/pqc-kaz/KazKem.git", from: "2.0.0")
]
```

Then add to your target:

```swift
.target(
    name: "YourTarget",
    dependencies: ["KazKem"]
)
```

### XCFramework (for iOS/macOS apps)

1. Build the XCFramework:
   ```bash
   ./scripts/build-xcframework.sh
   ```

2. Drag `Frameworks/KazKemNative.xcframework` into your Xcode project

3. Add to your target's "Frameworks, Libraries, and Embedded Content"

4. Set "Embed" to "Embed & Sign"

## Quick Start

```swift
import KazKem

// Initialize with security level
try KazKem.initialize(level: .level128)

// Generate a key pair
let keyPair = try KazKem.generateKeyPair()

// Encapsulate a shared secret (sender side)
let result = try KazKem.encapsulate(publicKey: keyPair.getPublicKey())

// Decapsulate the shared secret (receiver side)
let sharedSecret = try KazKem.decapsulate(
    ciphertext: result.ciphertext,
    privateKey: keyPair.privateKey
)

// Both parties now have the same shared secret
assert(result.sharedSecret == sharedSecret)

// Cleanup when done
KazKem.cleanup()
```

## API Reference

### KazKem Class

The main entry point for all KEM operations.

#### Initialization

```swift
// Initialize with default level (128-bit)
let kem = try KazKem.initialize()

// Initialize with specific security level
let kem128 = try KazKem.initialize(level: .level128)
let kem192 = try KazKem.initialize(level: .level192)
let kem256 = try KazKem.initialize(level: .level256)

// Get library version
let version = KazKem.version  // "2.0.0"
```

#### Static Properties

```swift
KazKem.isInitialized  // Bool - check if initialized
KazKem.version        // String - library version
try KazKem.current    // KazKem - current instance (throws if not initialized)
```

#### Instance Properties

```swift
kem.securityLevel     // SecurityLevel
kem.publicKeySize     // Int (bytes)
kem.privateKeySize    // Int (bytes)
kem.ciphertextSize    // Int (bytes)
kem.sharedSecretSize  // Int (bytes)
```

#### Key Generation

```swift
// Instance method
let keyPair = try kem.generateKeyPair()

// Static convenience
let keyPair = try KazKem.generateKeyPair()
```

#### Encapsulation

```swift
// With KazKemPublicKey
let result = try kem.encapsulate(publicKey: keyPair.getPublicKey())

// With raw Data
let result = try kem.encapsulate(publicKey: publicKeyData)
```

#### Decapsulation

```swift
// With KazKemKeyPair
let secret = try kem.decapsulate(ciphertext: ciphertext, keyPair: keyPair)

// With raw private key Data
let secret = try kem.decapsulate(ciphertext: ciphertext, privateKey: privateKeyData)
```

#### Cleanup

```swift
KazKem.cleanup()  // Release resources
```

### SecurityLevel

```swift
public enum SecurityLevel: Int, CaseIterable, Sendable {
    case level128 = 128  // NIST Level 1 - Standard security (fastest)
    case level192 = 192  // NIST Level 3 - Enhanced security
    case level256 = 256  // NIST Level 5 - Maximum security (slowest)
}
```

### KazKemKeyPair

```swift
let keyPair = try kem.generateKeyPair()

keyPair.publicKey       // Data
keyPair.privateKey      // Data
keyPair.securityLevel   // SecurityLevel
keyPair.publicKeySize   // Int
keyPair.privateKeySize  // Int

// Get public key wrapper
let publicKey = keyPair.getPublicKey()  // KazKemPublicKey

// Serialization
let publicKeyBase64 = keyPair.publicKeyBase64
let privateKeyBase64 = keyPair.privateKeyBase64
```

### KazKemPublicKey

```swift
let publicKey = KazKemPublicKey(data: publicKeyData, securityLevel: .level128)

publicKey.data           // Data
publicKey.securityLevel  // SecurityLevel

// Serialization
let base64 = publicKey.base64Encoded
let restored = try KazKemPublicKey(base64: base64String, securityLevel: .level128)
```

### KazKemEncapsulationResult

```swift
let result = try kem.encapsulate(publicKey: publicKey)

result.ciphertext       // Data
result.sharedSecret     // Data
result.ciphertextSize   // Int
result.sharedSecretSize // Int

// Serialization
let ciphertextBase64 = result.ciphertextBase64
let secretHex = result.sharedSecretHex
```

### Error Handling

```swift
public enum KazKemError: Error, LocalizedError {
    case notInitialized
    case initializationFailed(String)
    case keyGenerationFailed(String)
    case encapsulationFailed(String)
    case decapsulationFailed(String)
    case invalidParameter(String)
    case randomGenerationFailed

    var errorDescription: String? {
        switch self {
        case .notInitialized:
            return "KAZ-KEM is not initialized. Call KazKem.initialize() first."
        case .initializationFailed(let msg):
            return "Initialization failed: \(msg)"
        // ... etc
        }
    }
}
```

## Usage Examples

### Complete Key Exchange Protocol

```swift
import KazKem

class KeyExchangeProtocol {

    /// Perform a complete key exchange between Alice and Bob
    func performKeyExchange() throws {
        // === ALICE (Key Pair Owner) ===
        let kem = try KazKem.initialize(level: .level128)
        let aliceKeyPair = try kem.generateKeyPair()

        // Alice shares her public key (e.g., via network)
        let alicePublicKeyBase64 = aliceKeyPair.publicKey.base64EncodedString()

        // === BOB (Initiator) ===
        // Bob receives Alice's public key
        guard let receivedPublicKeyData = Data(base64Encoded: alicePublicKeyBase64) else {
            throw KazKemError.invalidParameter("Invalid public key encoding")
        }

        let receivedPublicKey = KazKemPublicKey(
            data: receivedPublicKeyData,
            securityLevel: .level128
        )

        // Bob encapsulates a shared secret
        let encapsulation = try kem.encapsulate(publicKey: receivedPublicKey)

        // Bob sends ciphertext to Alice (e.g., via network)
        let ciphertextBase64 = encapsulation.ciphertext.base64EncodedString()
        let bobSharedSecret = encapsulation.sharedSecret

        // === ALICE (Decapsulation) ===
        // Alice receives ciphertext
        guard let ciphertext = Data(base64Encoded: ciphertextBase64) else {
            throw KazKemError.invalidParameter("Invalid ciphertext encoding")
        }

        // Alice decapsulates using her private key
        let aliceSharedSecret = try kem.decapsulate(
            ciphertext: ciphertext,
            privateKey: aliceKeyPair.privateKey
        )

        // Both have the same shared secret!
        precondition(aliceSharedSecret == bobSharedSecret, "Key exchange failed!")
        print("Key exchange successful! Shared secret: \(aliceSharedSecret.prefix(8).hexString)...")
    }
}
```

### Hybrid Encryption (KEM + AES-GCM)

```swift
import KazKem
import CryptoKit

/// Hybrid encryption combining KEM with AES-GCM
class HybridEncryption {

    private let kem: KazKem

    struct EncryptedMessage {
        let kemCiphertext: Data
        let aesCiphertext: Data
        let nonce: Data
        let tag: Data
    }

    init(securityLevel: SecurityLevel = .level128) throws {
        self.kem = try KazKem.initialize(level: securityLevel)
    }

    /// Encrypt a message using hybrid encryption
    func encrypt(message: Data, recipientPublicKey: KazKemPublicKey) throws -> EncryptedMessage {
        // Step 1: KEM encapsulation to get shared secret
        let kemResult = try kem.encapsulate(publicKey: recipientPublicKey)

        // Step 2: Derive AES key from shared secret
        let symmetricKey = SymmetricKey(data: kemResult.sharedSecret)

        // Step 3: Generate random nonce
        let nonce = try AES.GCM.Nonce()

        // Step 4: Encrypt message with AES-GCM
        let sealedBox = try AES.GCM.seal(message, using: symmetricKey, nonce: nonce)

        return EncryptedMessage(
            kemCiphertext: kemResult.ciphertext,
            aesCiphertext: sealedBox.ciphertext,
            nonce: Data(nonce),
            tag: sealedBox.tag
        )
    }

    /// Decrypt a hybrid-encrypted message
    func decrypt(encrypted: EncryptedMessage, keyPair: KazKemKeyPair) throws -> Data {
        // Step 1: KEM decapsulation to recover shared secret
        let sharedSecret = try kem.decapsulate(
            ciphertext: encrypted.kemCiphertext,
            privateKey: keyPair.privateKey
        )

        // Step 2: Derive AES key from shared secret
        let symmetricKey = SymmetricKey(data: sharedSecret)

        // Step 3: Reconstruct sealed box
        let nonce = try AES.GCM.Nonce(data: encrypted.nonce)
        let sealedBox = try AES.GCM.SealedBox(
            nonce: nonce,
            ciphertext: encrypted.aesCiphertext,
            tag: encrypted.tag
        )

        // Step 4: Decrypt message
        let plaintext = try AES.GCM.open(sealedBox, using: symmetricKey)

        return plaintext
    }
}

// Usage
func hybridEncryptionExample() throws {
    let encryption = try HybridEncryption(securityLevel: .level256)
    let keyPair = try KazKem.generateKeyPair()

    // Encrypt
    let message = "Hello, Post-Quantum World!".data(using: .utf8)!
    let encrypted = try encryption.encrypt(
        message: message,
        recipientPublicKey: keyPair.getPublicKey()
    )

    // Decrypt
    let decrypted = try encryption.decrypt(encrypted: encrypted, keyPair: keyPair)

    print(String(data: decrypted, encoding: .utf8)!)  // "Hello, Post-Quantum World!"
}
```

### Secure Keychain Storage

```swift
import KazKem
import Security

/// Secure key storage using iOS/macOS Keychain
class SecureKeyStorage {

    private let serviceName = "com.pqc.kazkem"

    enum KeychainError: Error {
        case saveFailed(OSStatus)
        case loadFailed(OSStatus)
        case deleteFailed(OSStatus)
        case notFound
        case invalidData
    }

    /// Save a key pair to Keychain
    func saveKeyPair(_ keyPair: KazKemKeyPair, identifier: String) throws {
        // Save public key
        try saveData(
            keyPair.publicKey,
            identifier: "\(identifier).public",
            accessibility: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        )

        // Save private key with stronger protection
        try saveData(
            keyPair.privateKey,
            identifier: "\(identifier).private",
            accessibility: kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        )

        // Save security level
        let levelData = withUnsafeBytes(of: keyPair.securityLevel.rawValue) { Data($0) }
        try saveData(
            levelData,
            identifier: "\(identifier).level",
            accessibility: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        )
    }

    /// Load a key pair from Keychain
    func loadKeyPair(identifier: String) throws -> KazKemKeyPair {
        let publicKey = try loadData(identifier: "\(identifier).public")
        let privateKey = try loadData(identifier: "\(identifier).private")
        let levelData = try loadData(identifier: "\(identifier).level")

        guard levelData.count == MemoryLayout<Int>.size else {
            throw KeychainError.invalidData
        }

        let levelValue = levelData.withUnsafeBytes { $0.load(as: Int.self) }
        guard let level = SecurityLevel(rawValue: levelValue) else {
            throw KeychainError.invalidData
        }

        return KazKemKeyPair(
            publicKey: publicKey,
            privateKey: privateKey,
            securityLevel: level
        )
    }

    /// Delete a key pair from Keychain
    func deleteKeyPair(identifier: String) throws {
        try deleteData(identifier: "\(identifier).public")
        try deleteData(identifier: "\(identifier).private")
        try deleteData(identifier: "\(identifier).level")
    }

    /// Check if a key pair exists
    func hasKeyPair(identifier: String) -> Bool {
        do {
            _ = try loadData(identifier: "\(identifier).private")
            return true
        } catch {
            return false
        }
    }

    // MARK: - Private Helpers

    private func saveData(_ data: Data, identifier: String, accessibility: CFString) throws {
        // Delete existing item first
        try? deleteData(identifier: identifier)

        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: serviceName,
            kSecAttrAccount as String: identifier,
            kSecValueData as String: data,
            kSecAttrAccessible as String: accessibility
        ]

        let status = SecItemAdd(query as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw KeychainError.saveFailed(status)
        }
    }

    private func loadData(identifier: String) throws -> Data {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: serviceName,
            kSecAttrAccount as String: identifier,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]

        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)

        guard status == errSecSuccess else {
            if status == errSecItemNotFound {
                throw KeychainError.notFound
            }
            throw KeychainError.loadFailed(status)
        }

        guard let data = result as? Data else {
            throw KeychainError.invalidData
        }

        return data
    }

    private func deleteData(identifier: String) throws {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: serviceName,
            kSecAttrAccount as String: identifier
        ]

        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw KeychainError.deleteFailed(status)
        }
    }
}

// Usage
func keychainExample() throws {
    let storage = SecureKeyStorage()
    let kem = try KazKem.initialize()

    // Generate and save
    let keyPair = try kem.generateKeyPair()
    try storage.saveKeyPair(keyPair, identifier: "my_identity")

    // Later: load and use
    let loadedKeyPair = try storage.loadKeyPair(identifier: "my_identity")
    let result = try kem.encapsulate(publicKey: loadedKeyPair.getPublicKey())
    let secret = try kem.decapsulate(ciphertext: result.ciphertext, keyPair: loadedKeyPair)

    // Cleanup
    try storage.deleteKeyPair(identifier: "my_identity")
}
```

### SwiftUI Integration with ObservableObject

```swift
import SwiftUI
import KazKem
import Combine

@MainActor
class KeyExchangeViewModel: ObservableObject {
    @Published var status: String = "Ready"
    @Published var sharedSecretHex: String = ""
    @Published var isProcessing: Bool = false
    @Published var error: KazKemError?

    private var kem: KazKem?
    private var keyPair: KazKemKeyPair?

    func initialize(level: SecurityLevel = .level128) {
        isProcessing = true
        status = "Initializing..."

        Task {
            do {
                kem = try KazKem.initialize(level: level)
                status = "Initialized with \(level)"
                isProcessing = false
            } catch let err as KazKemError {
                error = err
                status = "Initialization failed"
                isProcessing = false
            } catch {
                status = "Unknown error"
                isProcessing = false
            }
        }
    }

    func generateKeyPair() {
        guard let kem = kem else {
            status = "Not initialized"
            return
        }

        isProcessing = true
        status = "Generating key pair..."

        Task.detached(priority: .userInitiated) { [weak self] in
            do {
                let keyPair = try kem.generateKeyPair()
                await MainActor.run {
                    self?.keyPair = keyPair
                    self?.status = "Key pair generated (\(keyPair.publicKeySize) bytes public key)"
                    self?.isProcessing = false
                }
            } catch {
                await MainActor.run {
                    self?.status = "Key generation failed: \(error)"
                    self?.isProcessing = false
                }
            }
        }
    }

    func performKeyExchange() {
        guard let kem = kem, let keyPair = keyPair else {
            status = "Generate key pair first"
            return
        }

        isProcessing = true
        status = "Performing key exchange..."

        Task.detached(priority: .userInitiated) { [weak self] in
            do {
                // Encapsulate
                let result = try kem.encapsulate(publicKey: keyPair.getPublicKey())

                // Decapsulate
                let secret = try kem.decapsulate(
                    ciphertext: result.ciphertext,
                    keyPair: keyPair
                )

                // Verify
                let success = result.sharedSecret == secret

                await MainActor.run {
                    if success {
                        self?.sharedSecretHex = secret.prefix(16).map {
                            String(format: "%02x", $0)
                        }.joined()
                        self?.status = "Key exchange successful!"
                    } else {
                        self?.status = "Key exchange verification failed!"
                    }
                    self?.isProcessing = false
                }
            } catch {
                await MainActor.run {
                    self?.status = "Key exchange failed: \(error)"
                    self?.isProcessing = false
                }
            }
        }
    }

    func cleanup() {
        KazKem.cleanup()
        keyPair = nil
        kem = nil
        sharedSecretHex = ""
        status = "Cleaned up"
    }
}

struct KeyExchangeView: View {
    @StateObject private var viewModel = KeyExchangeViewModel()
    @State private var selectedLevel: SecurityLevel = .level128

    var body: some View {
        VStack(spacing: 20) {
            Text("KAZ-KEM Key Exchange")
                .font(.title)

            // Security Level Picker
            Picker("Security Level", selection: $selectedLevel) {
                ForEach(SecurityLevel.allCases, id: \.self) { level in
                    Text("Level \(level.rawValue)").tag(level)
                }
            }
            .pickerStyle(.segmented)

            // Status
            Text(viewModel.status)
                .font(.headline)
                .foregroundColor(viewModel.status.contains("failed") ? .red : .primary)

            // Progress
            if viewModel.isProcessing {
                ProgressView()
            }

            // Action Buttons
            VStack(spacing: 12) {
                Button("Initialize") {
                    viewModel.initialize(level: selectedLevel)
                }
                .disabled(viewModel.isProcessing)

                Button("Generate Key Pair") {
                    viewModel.generateKeyPair()
                }
                .disabled(viewModel.isProcessing)

                Button("Perform Key Exchange") {
                    viewModel.performKeyExchange()
                }
                .disabled(viewModel.isProcessing)

                Button("Cleanup", role: .destructive) {
                    viewModel.cleanup()
                }
            }
            .buttonStyle(.bordered)

            // Result
            if !viewModel.sharedSecretHex.isEmpty {
                VStack {
                    Text("Shared Secret (first 16 bytes):")
                        .font(.caption)
                    Text(viewModel.sharedSecretHex)
                        .font(.system(.body, design: .monospaced))
                        .padding(8)
                        .background(Color.green.opacity(0.1))
                        .cornerRadius(8)
                }
            }

            Spacer()
        }
        .padding()
    }
}
```

### Async/Await with Actor

```swift
import KazKem

/// Thread-safe KEM manager using Swift actors
actor KemManager {
    private var kem: KazKem?

    func initialize(level: SecurityLevel = .level128) throws {
        kem = try KazKem.initialize(level: level)
    }

    var isInitialized: Bool {
        kem != nil && KazKem.isInitialized
    }

    func generateKeyPair() throws -> KazKemKeyPair {
        guard let kem = kem else {
            throw KazKemError.notInitialized
        }
        return try kem.generateKeyPair()
    }

    func encapsulate(publicKey: KazKemPublicKey) throws -> KazKemEncapsulationResult {
        guard let kem = kem else {
            throw KazKemError.notInitialized
        }
        return try kem.encapsulate(publicKey: publicKey)
    }

    func decapsulate(ciphertext: Data, privateKey: Data) throws -> Data {
        guard let kem = kem else {
            throw KazKemError.notInitialized
        }
        return try kem.decapsulate(ciphertext: ciphertext, privateKey: privateKey)
    }

    func cleanup() {
        KazKem.cleanup()
        kem = nil
    }
}

// Usage
func asyncExample() async throws {
    let manager = KemManager()

    try await manager.initialize(level: .level256)

    let keyPair = try await manager.generateKeyPair()
    let result = try await manager.encapsulate(publicKey: keyPair.getPublicKey())
    let secret = try await manager.decapsulate(
        ciphertext: result.ciphertext,
        privateKey: keyPair.privateKey
    )

    print("Shared secret: \(secret.hexString)")

    await manager.cleanup()
}
```

### Combine Framework Integration

```swift
import KazKem
import Combine

class KemPublisher {
    private let kem: KazKem

    init(securityLevel: SecurityLevel = .level128) throws {
        self.kem = try KazKem.initialize(level: securityLevel)
    }

    /// Publisher for key pair generation
    func generateKeyPairPublisher() -> AnyPublisher<KazKemKeyPair, KazKemError> {
        Future { [weak self] promise in
            DispatchQueue.global(qos: .userInitiated).async {
                guard let self = self else {
                    promise(.failure(.notInitialized))
                    return
                }

                do {
                    let keyPair = try self.kem.generateKeyPair()
                    promise(.success(keyPair))
                } catch let error as KazKemError {
                    promise(.failure(error))
                } catch {
                    promise(.failure(.keyGenerationFailed(error.localizedDescription)))
                }
            }
        }
        .eraseToAnyPublisher()
    }

    /// Publisher for encapsulation
    func encapsulatePublisher(publicKey: KazKemPublicKey) -> AnyPublisher<KazKemEncapsulationResult, KazKemError> {
        Future { [weak self] promise in
            DispatchQueue.global(qos: .userInitiated).async {
                guard let self = self else {
                    promise(.failure(.notInitialized))
                    return
                }

                do {
                    let result = try self.kem.encapsulate(publicKey: publicKey)
                    promise(.success(result))
                } catch let error as KazKemError {
                    promise(.failure(error))
                } catch {
                    promise(.failure(.encapsulationFailed(error.localizedDescription)))
                }
            }
        }
        .eraseToAnyPublisher()
    }

    /// Publisher for decapsulation
    func decapsulatePublisher(ciphertext: Data, privateKey: Data) -> AnyPublisher<Data, KazKemError> {
        Future { [weak self] promise in
            DispatchQueue.global(qos: .userInitiated).async {
                guard let self = self else {
                    promise(.failure(.notInitialized))
                    return
                }

                do {
                    let secret = try self.kem.decapsulate(
                        ciphertext: ciphertext,
                        privateKey: privateKey
                    )
                    promise(.success(secret))
                } catch let error as KazKemError {
                    promise(.failure(error))
                } catch {
                    promise(.failure(.decapsulationFailed(error.localizedDescription)))
                }
            }
        }
        .eraseToAnyPublisher()
    }
}

// Usage with Combine
class CombineViewModel: ObservableObject {
    @Published var sharedSecret: Data?
    @Published var error: KazKemError?

    private var cancellables = Set<AnyCancellable>()
    private let kemPublisher: KemPublisher

    init() throws {
        self.kemPublisher = try KemPublisher(securityLevel: .level128)
    }

    func performKeyExchange() {
        kemPublisher.generateKeyPairPublisher()
            .flatMap { [weak self] keyPair -> AnyPublisher<(KazKemKeyPair, KazKemEncapsulationResult), KazKemError> in
                guard let self = self else {
                    return Fail(error: KazKemError.notInitialized).eraseToAnyPublisher()
                }
                return self.kemPublisher.encapsulatePublisher(publicKey: keyPair.getPublicKey())
                    .map { (keyPair, $0) }
                    .eraseToAnyPublisher()
            }
            .flatMap { [weak self] (keyPair, result) -> AnyPublisher<Data, KazKemError> in
                guard let self = self else {
                    return Fail(error: KazKemError.notInitialized).eraseToAnyPublisher()
                }
                return self.kemPublisher.decapsulatePublisher(
                    ciphertext: result.ciphertext,
                    privateKey: keyPair.privateKey
                )
            }
            .receive(on: DispatchQueue.main)
            .sink(
                receiveCompletion: { [weak self] completion in
                    if case .failure(let error) = completion {
                        self?.error = error
                    }
                },
                receiveValue: { [weak self] secret in
                    self?.sharedSecret = secret
                }
            )
            .store(in: &cancellables)
    }
}
```

### App Lifecycle Integration

```swift
import SwiftUI
import KazKem

@main
struct MyApp: App {
    @Environment(\.scenePhase) private var scenePhase

    init() {
        // Initialize KAZ-KEM at app launch
        do {
            _ = try KazKem.initialize(level: .level128)
            print("KAZ-KEM initialized: v\(KazKem.version)")
        } catch {
            fatalError("Failed to initialize KAZ-KEM: \(error)")
        }
    }

    var body: some Scene {
        WindowGroup {
            ContentView()
        }
        .onChange(of: scenePhase) { newPhase in
            switch newPhase {
            case .background:
                // Optionally cleanup when backgrounded
                // KazKem.cleanup()
                break
            case .active:
                // Re-initialize if needed
                if !KazKem.isInitialized {
                    try? KazKem.initialize(level: .level128)
                }
            case .inactive:
                break
            @unknown default:
                break
            }
        }
    }
}

// AppDelegate for UIKit apps
class AppDelegate: NSObject, UIApplicationDelegate {
    func application(
        _ application: UIApplication,
        didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]?
    ) -> Bool {
        do {
            _ = try KazKem.initialize(level: .level128)
        } catch {
            print("KAZ-KEM initialization failed: \(error)")
        }
        return true
    }

    func applicationWillTerminate(_ application: UIApplication) {
        KazKem.cleanup()
    }
}
```

## Best Practices

### Security

1. **Clear sensitive data** when done:
   ```swift
   var privateKeyData = keyPair.privateKey
   defer {
       // Zero out the data
       privateKeyData.resetBytes(in: 0..<privateKeyData.count)
   }
   // Use privateKeyData...
   ```

2. **Choose appropriate security level** based on data sensitivity:
   - **Level 128**: General applications, IoT devices (fastest)
   - **Level 192**: Financial data, healthcare (balanced)
   - **Level 256**: Government, military, long-term secrets (most secure)

3. **Store private keys in Keychain** with appropriate protection:
   ```swift
   // Use kSecAttrAccessibleWhenUnlockedThisDeviceOnly for maximum security
   // Use kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly for background access
   ```

4. **Never log private keys or shared secrets**:
   ```swift
   // BAD
   print("Private key: \(keyPair.privateKey.hexString)")

   // GOOD
   print("Key pair generated, public key size: \(keyPair.publicKeySize) bytes")
   ```

5. **Use hybrid encryption** - KEM provides key exchange, combine with AES for data encryption

6. **Validate public keys** before use:
   ```swift
   guard publicKeyData.count == kem.publicKeySize else {
       throw KazKemError.invalidParameter("Invalid public key size")
   }
   ```

### Performance

1. **Initialize once** at app startup:
   ```swift
   // In App.init() or AppDelegate
   try KazKem.initialize(level: .level128)
   ```

2. **Use background threads** for cryptographic operations:
   ```swift
   Task.detached(priority: .userInitiated) {
       let keyPair = try kem.generateKeyPair()
       await MainActor.run {
           // Update UI
       }
   }
   ```

3. **Reuse key pairs** when appropriate (avoid generating new pairs for every operation)

4. **Batch operations** when possible:
   ```swift
   let keyPairs = try await withThrowingTaskGroup(of: KazKemKeyPair.self) { group in
       for _ in 0..<10 {
           group.addTask {
               try KazKem.generateKeyPair()
           }
       }
       return try await group.reduce(into: []) { $0.append($1) }
   }
   ```

### Thread Safety

The `KazKem` class is thread-safe. You can safely call methods from multiple threads:

```swift
// Safe concurrent operations
DispatchQueue.concurrentPerform(iterations: 100) { i in
    do {
        let result = try KazKem.encapsulate(publicKey: publicKey)
        print("Thread \(i): Success")
    } catch {
        print("Thread \(i): \(error)")
    }
}

// Safe with Swift Concurrency
await withTaskGroup(of: Void.self) { group in
    for _ in 0..<10 {
        group.addTask {
            let _ = try? KazKem.generateKeyPair()
        }
    }
}
```

### Error Handling

```swift
func safeKeyExchange(publicKey: KazKemPublicKey) -> Data? {
    do {
        // Ensure initialized
        if !KazKem.isInitialized {
            try KazKem.initialize()
        }

        let result = try KazKem.encapsulate(publicKey: publicKey)
        return result.sharedSecret

    } catch KazKemError.notInitialized {
        print("Error: KAZ-KEM not initialized")
        return nil

    } catch KazKemError.invalidParameter(let msg) {
        print("Error: Invalid parameter - \(msg)")
        return nil

    } catch KazKemError.encapsulationFailed(let msg) {
        print("Error: Encapsulation failed - \(msg)")
        return nil

    } catch {
        print("Error: Unknown - \(error)")
        return nil
    }
}
```

## Building from Source

### Local Development

```bash
# Install dependencies
brew install openssl@3 gmp

# Build native library
./scripts/build-local.sh

# Run tests
swift test
```

### XCFramework for Distribution

```bash
# Build XCFramework for all Apple platforms
./scripts/build-xcframework.sh

# Output: Frameworks/KazKemNative.xcframework
```

### Dependencies

- OpenSSL 3.x (for cryptographic primitives)
- GMP (GNU Multiple Precision library)

## Troubleshooting

### Library not found

If you get "Library not loaded: @rpath/libkazkem.dylib":

1. Ensure the library is in the correct path
2. For development, run:
   ```bash
   ./scripts/build-local.sh
   ```
3. Or add lib directory to runpath:
   ```bash
   export DYLD_LIBRARY_PATH=/path/to/lib:$DYLD_LIBRARY_PATH
   ```

### Build fails on iOS

Ensure you've built the XCFramework with iOS support:
```bash
./scripts/build-xcframework.sh
```

### OpenSSL not found

Set the OpenSSL path:
```bash
export OPENSSL_PREFIX=$(brew --prefix openssl@3)
./scripts/build-local.sh
```

### Xcode Signing Issues

For XCFramework, ensure code signing is properly configured:
```bash
codesign --force --sign - Frameworks/KazKemNative.xcframework
```

## Security Considerations

1. **Quantum Resistance**: This library provides protection against quantum computer attacks on key exchange
2. **Forward Secrecy**: Generate new key pairs for each session when possible
3. **Side-Channel Protection**: The library uses constant-time operations where possible
4. **Memory Safety**: Swift's memory management helps prevent common vulnerabilities
5. **Keychain Integration**: Use iOS/macOS Keychain for secure key storage

## Platform-Specific Notes

### iOS
- Use `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` for maximum key security
- Consider Face ID/Touch ID protection for key access

### macOS
- Keys can be stored in the system Keychain or app-specific Keychain
- Consider Secure Enclave for hardware-backed key protection

### watchOS
- Limited background processing; initialize on-demand
- Smaller key sizes (Level 128) recommended for performance

### tvOS
- Similar to iOS; no Keychain persistence across app installations

## License

NIST-developed software license. All code is provided "AS IS" by NIST as a public service.

## Version History

- **2.0.0**: Initial release
  - Support for iOS, macOS, tvOS, watchOS
  - Three security levels (128/192/256)
  - Thread-safe API
  - Swift Concurrency support
  - 33 unit tests

## Data Extensions

```swift
// Useful extensions for working with Data
extension Data {
    var hexString: String {
        map { String(format: "%02x", $0) }.joined()
    }

    init?(hexString: String) {
        let len = hexString.count / 2
        var data = Data(capacity: len)
        var index = hexString.startIndex
        for _ in 0..<len {
            let nextIndex = hexString.index(index, offsetBy: 2)
            guard let byte = UInt8(hexString[index..<nextIndex], radix: 16) else {
                return nil
            }
            data.append(byte)
            index = nextIndex
        }
        self = data
    }
}
```
