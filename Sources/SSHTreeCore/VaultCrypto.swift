import Foundation
import CryptoKit
import CommonCrypto
import Security

public enum VaultError: Error, LocalizedError, Sendable {
    case notConfigured, locked, corrupt(String), unsupportedVersion, invalidPassword, missingKey
    case keychain(Int32), invalidConfiguration(String), network(String), targetExists, targetMissing
    case conflictsRequireResolution, invalidResolution, sourceChanged, concurrentOperation
    public var errorDescription: String? {
        switch self {
        case .notConfigured: "尚未配置存储位置。"
        case .locked: "保险库尚未解锁。"
        case .corrupt(let detail): "保险库数据损坏：\(detail)"
        case .unsupportedVersion: "保险库版本不受支持。"
        case .invalidPassword: "密码错误，或加密数据已损坏。"
        case .missingKey: "钥匙串中的保险库密钥缺失。原始文件已保留。"
        case .keychain(let code): "钥匙串操作失败（\(code)）。"
        case .invalidConfiguration(let message): message
        case .network(let message): "云存储请求失败：\(message)"
        case .targetExists: "目标保险库已存在，请选择打开。"
        case .targetMissing: "未找到目标保险库。"
        case .conflictsRequireResolution: "请先解决同步冲突。"
        case .invalidResolution: "冲突选项已失效，请重新检查。"
        case .sourceChanged: "存储位置已更改，请重试。"
        case .concurrentOperation: "另一项存储操作正在进行，请稍后重试。"
        }
    }
}

extension Data {
    var hex: String { map { String(format: "%02x", $0) }.joined() }
    var sha256: String { Data(SHA256.hash(data: self)).hex }
}

enum VaultCrypto {
    static let rounds: UInt32 = 600_000
    static let maxBytes = 32 * 1024 * 1024
    // Header is authenticated as AAD: magic + version + algorithm + KDF + rounds + salt.
    // Fixed lengths prevent untrusted headers from selecting arbitrary CPU/memory parameters.
    static func random(_ count: Int) throws -> Data {
        var data = Data(count: count)
        let result = data.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, count, $0.baseAddress!) }
        guard result == errSecSuccess else { throw VaultError.keychain(result) }
        return data
    }
    static func pbkdf2(_ password: String, salt: Data, rounds: UInt32, count: Int = 32) throws -> Data {
        let passwordBytes = Data(password.utf8)
        var output = Data(count: count)
        let result = output.withUnsafeMutableBytes { destination in
            salt.withUnsafeBytes { saltBytes in
                passwordBytes.withUnsafeBytes { passwordBuffer in
                    CCKeyDerivationPBKDF(CCPBKDFAlgorithm(kCCPBKDF2), passwordBuffer.baseAddress?.assumingMemoryBound(to: Int8.self), passwordBytes.count,
                                        saltBytes.baseAddress?.assumingMemoryBound(to: UInt8.self), salt.count,
                                        CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256), rounds,
                                        destination.baseAddress!.assumingMemoryBound(to: UInt8.self), count)
                }
            }
        }
        guard result == kCCSuccess else { throw VaultError.corrupt("密钥派生失败") }
        return output
    }
    static func passwordKey(_ password: String, salt: Data) throws -> SymmetricKey {
        guard !password.isEmpty, salt.count == 32 else { throw VaultError.invalidConfiguration("请输入主密码。") }
        return SymmetricKey(data: try pbkdf2(password, salt: salt, rounds: rounds))
    }
    static func header(salt: Data, passwordBased: Bool) throws -> Data {
        guard salt.count == 32 else { throw VaultError.corrupt("盐长度无效") }
        var bytes = Data("SSHTREE\0".utf8)
        bytes.append(contentsOf: [1, 1, passwordBased ? 1 : 0, 0])
        let count = passwordBased ? rounds : 0
        bytes.append(contentsOf: [UInt8((count >> 24) & 255), UInt8((count >> 16) & 255), UInt8((count >> 8) & 255), UInt8(count & 255)])
        bytes.append(salt)
        return bytes
    }
    static func salt(in data: Data, passwordBased: Bool = true) throws -> Data {
        guard data.count >= 48 + 28, data.count <= maxBytes + 76, data.prefix(8) == Data("SSHTREE\0".utf8) else { throw VaultError.corrupt("加密文件头无效") }
        guard data[8] == 1, data[9] == 1 else { throw VaultError.unsupportedVersion }
        let extracted = Data(data[16..<48])
        guard data.prefix(48) == (try header(salt: extracted, passwordBased: passwordBased)) else { throw VaultError.corrupt("加密参数无效") }
        return extracted
    }
    static func seal(_ plaintext: Data, key: SymmetricKey, salt: Data, passwordBased: Bool = true) throws -> Data {
        guard plaintext.count <= maxBytes else { throw VaultError.corrupt("保险库文件过大") }
        let prefix = try header(salt: salt, passwordBased: passwordBased)
        let sealed = try AES.GCM.seal(plaintext, using: key, authenticating: prefix)
        guard let combined = sealed.combined else { throw VaultError.corrupt("加密失败") }
        return prefix + combined
    }
    static func open(_ data: Data, key: SymmetricKey, expectedSalt: Data, passwordBased: Bool = true) throws -> Data {
        guard try salt(in: data, passwordBased: passwordBased) == expectedSalt else { throw VaultError.corrupt("保险库盐不一致") }
        do { return try AES.GCM.open(AES.GCM.SealedBox(combined: data.dropFirst(48)), using: key, authenticating: data.prefix(48)) }
        catch { throw VaultError.invalidPassword }
    }
}

protocol SecretStore: Sendable {
    func read(_ account: String) async throws -> Data?
    func write(_ value: Data, account: String) async throws
    func remove(_ account: String) async throws
}

// The macOS login Keychain supports Developer ID and ad-hoc builds without an access-group entitlement.
// No iCloud synchronization; credentials remain protected by the login Keychain and its access control.
actor KeychainSecrets: SecretStore {
    private let service = "app.sshtree.mac"
    private func query(_ account: String) -> [String: Any] {
        [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service, kSecAttrAccount as String: account,
         kSecAttrSynchronizable as String: false]
    }
    func read(_ account: String) throws -> Data? {
        var attributes = query(account); attributes[kSecReturnData as String] = true; attributes[kSecMatchLimit as String] = kSecMatchLimitOne
        var result: CFTypeRef?
        let status = SecItemCopyMatching(attributes as CFDictionary, &result)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess, let data = result as? Data else { throw VaultError.keychain(status) }
        return data
    }
    func write(_ value: Data, account: String) throws {
        let attributes = query(account)
        let update = [kSecValueData as String: value]
        let status = SecItemUpdate(attributes as CFDictionary, update as CFDictionary)
        if status == errSecItemNotFound {
            var insert = attributes; insert[kSecValueData as String] = value; insert[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
            let added = SecItemAdd(insert as CFDictionary, nil)
            guard added == errSecSuccess else { throw VaultError.keychain(added) }
        } else if status != errSecSuccess { throw VaultError.keychain(status) }
    }
    func remove(_ account: String) throws {
        let status = SecItemDelete(query(account) as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else { throw VaultError.keychain(status) }
    }
}

// chmod every sensitive directory/file, retain previous verified ciphertext, and replace atomically.
enum VaultFiles {
    static func directory(_ url: URL) throws {
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: url.path)
    }
    static func write(_ bytes: Data, to url: URL, backup: Bool = true) throws {
        try directory(url.deletingLastPathComponent())
        if backup, FileManager.default.fileExists(atPath: url.path) {
            let previous = try Data(contentsOf: url, options: .mappedIfSafe)
            try previous.write(to: url.appendingPathExtension("previous"), options: .atomic)
            try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.appendingPathExtension("previous").path)
        }
        try bytes.write(to: url, options: .atomic)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
    }
    static func read(_ url: URL) throws -> Data {
        let attributes = try FileManager.default.attributesOfItem(atPath: url.path)
        guard let size = attributes[.size] as? NSNumber, size.intValue <= VaultCrypto.maxBytes + 76 else { throw VaultError.corrupt("文件过大") }
        return try Data(contentsOf: url)
    }
}
