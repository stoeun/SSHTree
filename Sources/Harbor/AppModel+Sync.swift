import Foundation
import HarborKit

extension AppModel {
    var isConfigured: Bool {
        let config = normalizedConfig()
        return !config.region.isEmpty
            && !config.bucket.isEmpty
            && !config.objectKey.isEmpty
            && !config.accessKeyID.isEmpty
            && !ossSecret.isEmpty
            && !ossPassphrase.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
    }

    func saveCloudSettings() {
        ossConfig = normalizedConfig()
        do {
            guard !usingEphemeralStore else { return }
            try vaultBox.saveConfig(ossConfig)
            try KeychainStore.setString(ossSecret, account: KeychainAccount.ossSecret)
            try KeychainStore.setString(ossPassphrase, account: KeychainAccount.ossPassphrase)
        } catch {
            present(error)
        }
    }

    func smartSync() {
        Task { await runSmartSync() }
    }

    func forceUpload() {
        Task { await upload() }
    }

    func forceDownload() {
        Task { await download() }
    }

    func testAccess() {
        Task { await runTest() }
    }

    func verifyPassphrase() {
        Task { await runVerify() }
    }

    func resolve(useRemote: Bool) {
        conflict = nil
        if useRemote {
            forceDownload()
        } else {
            forceUpload()
        }
    }

    func autoSyncIfNeeded() async {
        guard ossConfig.autoSync, !didAutoSync else { return }
        didAutoSync = true
        guard isConfigured else { return }
        await runSmartSync()
    }

    private func runSmartSync() async {
        guard beginNetwork() else { return }
        defer { isSyncing = false }
        do {
            let client = try makeClient()
            let passphrase = try requirePassphrase()
            let head = try await client.head()
            guard let head else {
                try await uploadDocument(client: client, passphrase: passphrase)
                return
            }
            if head.revision == document.revision {
                try markSynced(revision: document.revision)
                notice = "已和云端一致"
                return
            }
            if document.connections.isEmpty && syncState.lastSyncedRevision == nil {
                try await downloadDocument(client: client, passphrase: passphrase)
                return
            }
            if syncState.lastSyncedRevision == document.revision {
                try await downloadDocument(client: client, passphrase: passphrase)
                return
            }
            if let remote = head.revision, syncState.lastSyncedRevision == remote {
                try await uploadDocument(client: client, passphrase: passphrase)
                return
            }
            conflict = SyncConflict(localUpdated: document.updatedAt, remoteUpdated: head.updatedAt)
        } catch {
            present(error)
        }
    }

    private func upload() async {
        guard beginNetwork() else { return }
        defer { isSyncing = false }
        do {
            let client = try makeClient()
            try await uploadDocument(client: client, passphrase: try requirePassphrase())
        } catch {
            present(error)
        }
    }

    private func download() async {
        guard beginNetwork() else { return }
        defer { isSyncing = false }
        do {
            let client = try makeClient()
            try await downloadDocument(client: client, passphrase: try requirePassphrase())
        } catch {
            present(error)
        }
    }

    private func runTest() async {
        guard beginNetwork() else { return }
        defer { isSyncing = false }
        do {
            let client = try makeClient()
            let head = try await client.head()
            notice = head == nil ? "可以访问。云端还没有连接库。" : "可以访问。云端已有连接库。"
        } catch {
            present(error)
        }
    }

    private func runVerify() async {
        guard beginNetwork() else { return }
        defer { isSyncing = false }
        do {
            let client = try makeClient()
            let data = try await client.get()
            let passphrase = try requirePassphrase()
            _ = try await Task.detached(priority: .userInitiated) {
                try VaultCrypto.openCloud(data, passphrase: passphrase)
            }.value
            notice = "口令正确。"
        } catch HarborError.notFound {
            notice = "云端还没有文件。这个口令会在第一次上传时使用。"
        } catch {
            present(error)
        }
    }

    private func uploadDocument(client: OSSClient, passphrase: String) async throws {
        let snapshot = document
        let payload = try await Task.detached(priority: .userInitiated) {
            try VaultCrypto.sealCloud(snapshot, passphrase: passphrase)
        }.value
        try await client.put(payload, revision: snapshot.revision, updatedAt: snapshot.updatedAt)
        try markSynced(revision: snapshot.revision)
        notice = "已上传到 OSS"
    }

    private func downloadDocument(client: OSSClient, passphrase: String) async throws {
        let data = try await client.get()
        let remote = try await Task.detached(priority: .userInitiated) {
            try VaultCrypto.openCloud(data, passphrase: passphrase)
        }.value
        try replaceDocument(remote)
        try markSynced(revision: remote.revision)
        notice = "已从 OSS 下载"
    }

    private func makeClient() throws -> OSSClient {
        saveCloudSettings()
        guard isConfigured else {
            throw HarborError.invalid("先在设置里填写 Bucket、AccessKey 和加密口令。")
        }
        return OSSClient(config: normalizedConfig(), accessKeySecret: ossSecret)
    }

    private func requirePassphrase() throws -> String {
        let passphrase = ossPassphrase.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !passphrase.isEmpty else {
            throw HarborError.crypto("先设置加密口令。云端文件靠它加密，口令不会上传。")
        }
        return passphrase
    }

    private func beginNetwork() -> Bool {
        guard !isSyncing else { return false }
        if usingEphemeralStore {
            present(HarborError.storage("本地连接库这次没能打开，已停止同步，避免盖掉原来的文件。"))
            return false
        }
        isSyncing = true
        notice = nil
        return true
    }

    private func normalizedConfig() -> OSSConfig {
        var config = ossConfig
        config.region = config.region.trimmingCharacters(in: .whitespacesAndNewlines)
        config.bucket = config.bucket.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        config.objectKey = OSSEndpoint.normalizeKey(config.objectKey)
        config.endpointOverride = config.endpointOverride.trimmingCharacters(in: .whitespacesAndNewlines)
        config.accessKeyID = config.accessKeyID.trimmingCharacters(in: .whitespacesAndNewlines)
        return config
    }
}
