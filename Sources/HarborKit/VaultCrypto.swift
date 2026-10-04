import CryptoKit
import Foundation
import CommonCrypto

public enum VaultCrypto {
    public static let cloudIterations = 200_000
    private static let localMagic = Data("HBRL".utf8)
    private static let cloudMagic = Data("HBRC".utf8)

    public static func sealLocal(_ document: VaultDocument, key: SymmetricKey) throws -> Data {
        let plain = try encode(document)
        let sealed = try AES.GCM.seal(plain, using: key)
        guard let combined = sealed.combined else {
            throw HarborError.crypto("本地加密失败。")
        }
        var data = Data()
        data.append(localMagic)
        data.append(1)
        data.append(combined)
        return data
    }

    public static func openLocal(_ data: Data, key: SymmetricKey) throws -> VaultDocument {
        let combined = try combinedPayload(data, magic: localMagic, context: "本地连接库")
        do {
            let box = try AES.GCM.SealedBox(combined: combined)
            let plain = try AES.GCM.open(box, using: key)
            return try decode(plain)
        } catch let error as HarborError {
            throw error
        } catch {
            throw HarborError.crypto("本地连接库无法解密。原文件已保留。")
        }
    }

    public static func sealCloud(_ document: VaultDocument, passphrase: String, iterations: Int = cloudIterations) throws -> Data {
        let trimmed = passphrase.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else {
            throw HarborError.crypto("先设置加密口令。云端文件靠它加密，口令不会上传。")
        }
        guard (1_000...500_000).contains(iterations) else {
            throw HarborError.crypto("加密强度超出范围。")
        }
        var salt = Data(count: 16)
        let saltStatus = salt.withUnsafeMutableBytes { buffer in
            SecRandomCopyBytes(kSecRandomDefault, 16, buffer.baseAddress!)
        }
        guard saltStatus == errSecSuccess else {
            throw HarborError.crypto("无法生成加密盐。")
        }
        let key = try deriveKey(passphrase: trimmed, salt: salt, iterations: iterations)
        let plain = try encode(document)
        let sealed = try AES.GCM.seal(plain, using: key)
        guard let combined = sealed.combined else {
            throw HarborError.crypto("云端加密失败。")
        }
        var data = Data()
        data.append(cloudMagic)
        data.append(1)
        data.append(uint32(UInt32(iterations)))
        data.append(salt)
        data.append(combined)
        return data
    }

    public static func openCloud(_ data: Data, passphrase: String) throws -> VaultDocument {
        let trimmed = passphrase.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else {
            throw HarborError.crypto("先填写加密口令，才能解开云端连接库。")
        }
        guard data.count > 4 + 1 + 4 + 16 + 28, data.prefix(4) == cloudMagic else {
            throw HarborError.crypto("这不是 SSHTree 的云端连接库。")
        }
        let version = data[data.index(data.startIndex, offsetBy: 4)]
        guard version == 1 else {
            throw HarborError.crypto("这是更新版本的 SSHTree 写的云端文件，当前版本打不开。")
        }
        let iterationStart = data.index(data.startIndex, offsetBy: 5)
        let iterations = Int(readUInt32(data[iterationStart..<data.index(iterationStart, offsetBy: 4)]))
        guard (1_000...500_000).contains(iterations) else {
            throw HarborError.crypto("云端文件的加密参数不在接受范围内。")
        }
        let saltStart = data.index(iterationStart, offsetBy: 4)
        let salt = data[saltStart..<data.index(saltStart, offsetBy: 16)]
        let combined = data[data.index(saltStart, offsetBy: 16)...]
        let key = try deriveKey(passphrase: trimmed, salt: Data(salt), iterations: iterations)
        do {
            let box = try AES.GCM.SealedBox(combined: combined)
            let plain = try AES.GCM.open(box, using: key)
            return try decode(plain)
        } catch let error as HarborError {
            throw error
        } catch {
            throw HarborError.crypto("口令无法解开云端文件。确认这台 Mac 和上传时用的是同一口令。")
        }
    }

    private static func combinedPayload(_ data: Data, magic: Data, context: String) throws -> Data {
        guard data.count > 5 + 28, data.prefix(4) == magic else {
            throw HarborError.crypto("\(context)的格式认不出来。")
        }
        let version = data[data.index(data.startIndex, offsetBy: 4)]
        guard version == 1 else {
            throw HarborError.crypto("这是更新版本的 SSHTree 写的文件，当前版本打不开。")
        }
        return data.dropFirst(5)
    }

    private static func encode(_ document: VaultDocument) throws -> Data {
        guard document.schema == 1 else {
            throw HarborError.crypto("连接库版本不受支持。")
        }
        return try HarborJSON.encoder().encode(document)
    }

    private static func decode(_ data: Data) throws -> VaultDocument {
        let document = try HarborJSON.decoder().decode(VaultDocument.self, from: data)
        guard document.schema == 1 else {
            throw HarborError.crypto("连接库版本不受支持。")
        }
        return document
    }

    private static func deriveKey(passphrase: String, salt: Data, iterations: Int) throws -> SymmetricKey {
        let password = Array(passphrase.utf8)
        var key = Data(count: 32)
        let status: Int32 = password.withUnsafeBytes { passwordBytes in
            salt.withUnsafeBytes { saltBytes in
                key.withUnsafeMutableBytes { keyBytes in
                    CCKeyDerivationPBKDF(
                        CCPBKDFAlgorithm(kCCPBKDF2),
                        passwordBytes.bindMemory(to: CChar.self).baseAddress,
                        password.count,
                        saltBytes.bindMemory(to: UInt8.self).baseAddress,
                        salt.count,
                        CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256),
                        UInt32(iterations),
                        keyBytes.bindMemory(to: UInt8.self).baseAddress,
                        32
                    )
                }
            }
        }
        guard status == kCCSuccess else {
            throw HarborError.crypto("无法从口令派生密钥。")
        }
        return SymmetricKey(data: key)
    }

    private static func uint32(_ value: UInt32) -> Data {
        var big = value.bigEndian
        return Data(bytes: &big, count: 4)
    }

    private static func readUInt32(_ data: Data) -> UInt32 {
        var value: UInt32 = 0
        for byte in data.prefix(4) {
            value = (value << 8) | UInt32(byte)
        }
        return value
    }
}
