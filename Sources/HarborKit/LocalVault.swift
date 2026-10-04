import CryptoKit
import Foundation

public struct LocalVault: Sendable {
    public let directory: URL
    public let key: SymmetricKey

    public init(directory: URL, key: SymmetricKey) throws {
        self.directory = directory
        self.key = key
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: directory.appendingPathComponent("bin", isDirectory: true), withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: directory.appendingPathComponent("secrets", isDirectory: true), withIntermediateDirectories: true)
    }

    public var vaultURL: URL { directory.appendingPathComponent("vault.hbr") }
    public var configURL: URL { directory.appendingPathComponent("oss.json") }
    public var syncURL: URL { directory.appendingPathComponent("sync.json") }
    public var askpassURL: URL { directory.appendingPathComponent("bin/askpass") }
    public var secretsURL: URL { directory.appendingPathComponent("secrets", isDirectory: true) }

    public func load() throws -> VaultDocument {
        guard FileManager.default.fileExists(atPath: vaultURL.path) else {
            return .empty
        }
        let data = try Data(contentsOf: vaultURL)
        do {
            return try VaultCrypto.openLocal(data, key: key)
        } catch {
            let broken = directory.appendingPathComponent("vault.hbr.broken")
            if FileManager.default.fileExists(atPath: broken.path) {
                try? FileManager.default.removeItem(at: broken)
            }
            try? FileManager.default.copyItem(at: vaultURL, to: broken)
            throw error
        }
    }

    public func save(_ document: VaultDocument) throws {
        let data = try VaultCrypto.sealLocal(document, key: key)
        try write(data, to: vaultURL)
    }

    public func loadConfig() -> OSSConfig {
        guard let data = try? Data(contentsOf: configURL),
              let config = try? HarborJSON.decoder().decode(OSSConfig.self, from: data) else {
            return OSSConfig()
        }
        return config
    }

    public func saveConfig(_ config: OSSConfig) throws {
        try write(try HarborJSON.encoder().encode(config), to: configURL)
    }

    public func loadSyncState() -> SyncState {
        guard let data = try? Data(contentsOf: syncURL),
              let state = try? HarborJSON.decoder().decode(SyncState.self, from: data) else {
            return SyncState()
        }
        return state
    }

    public func saveSyncState(_ state: SyncState) throws {
        try write(try HarborJSON.encoder().encode(state), to: syncURL)
    }

    public func prepareAskpass() throws -> URL {
        let script = """
        #!/bin/sh
        if [ -z "$HARBOR_ASKPASS_FILE" ] || [ ! -f "$HARBOR_ASKPASS_FILE" ]; then
          exit 1
        fi
        /bin/cat "$HARBOR_ASKPASS_FILE"
        """
        try script.write(to: askpassURL, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: askpassURL.path)
        return askpassURL
    }

    public func writeSecret(_ secret: String, named name: String) throws -> URL {
        let url = secretsURL.appendingPathComponent(name)
        let data = Data((secret + "\n").utf8)
        FileManager.default.createFile(atPath: url.path, contents: data, attributes: [.posixPermissions: 0o600])
        return url
    }

    public func deleteSecret(named name: String) {
        try? FileManager.default.removeItem(at: secretsURL.appendingPathComponent(name))
    }

    public func cleanSecrets() {
        let urls = (try? FileManager.default.contentsOfDirectory(at: secretsURL, includingPropertiesForKeys: nil)) ?? []
        for url in urls {
            try? FileManager.default.removeItem(at: url)
        }
    }

    private func write(_ data: Data, to url: URL) throws {
        try data.write(to: url, options: .atomic)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
    }
}
