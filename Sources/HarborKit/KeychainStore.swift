import Foundation
import Security

public enum KeychainAccount {
    public static let vaultKey = "vault.localKey"
    public static let ossSecret = "oss.secret"
    public static let ossPassphrase = "oss.passphrase"
}

public enum KeychainStore {
    public static let service = "app.harbor.mac"

    public static func setString(_ value: String, account: String) throws {
        if value.isEmpty {
            remove(account: account)
            return
        }
        try setData(Data(value.utf8), account: account)
    }

    public static func getString(account: String) throws -> String? {
        guard let data = try getData(account: account) else { return nil }
        return String(data: data, encoding: .utf8)
    }

    public static func setData(_ data: Data, account: String) throws {
        let query = baseQuery(account: account)
        SecItemDelete(query as CFDictionary)
        var add = query
        add[kSecValueData as String] = data
        add[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlock
        let status = SecItemAdd(add as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw HarborError.keychain("钥匙串写入失败（\(status)）。")
        }
    }

    public static func getData(account: String) throws -> Data? {
        var query = baseQuery(account: account)
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess else {
            throw HarborError.keychain("钥匙串读取失败（\(status)）。")
        }
        return item as? Data
    }

    public static func remove(account: String) {
        SecItemDelete(baseQuery(account: account) as CFDictionary)
    }

    private static func baseQuery(account: String) -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account
        ]
    }
}
