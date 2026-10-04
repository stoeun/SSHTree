import XCTest
@testable import SSHTreeCore
import CryptoKit

final class StorageCryptoTests: XCTestCase {
    func testVersionedEnvelopeRejectsWrongKeyAndTampering() throws {
        let salt = Data(repeating: 7, count: 32)
        let key = try VaultCrypto.passwordKey("secret", salt: salt)
        let bytes = try VaultCrypto.seal(Data("private".utf8), key: key, salt: salt)
        XCTAssertEqual(try VaultCrypto.open(bytes, key: key, expectedSalt: salt), Data("private".utf8))
        XCTAssertThrowsError(try VaultCrypto.open(bytes, key: SymmetricKey(size: .bits256), expectedSalt: salt))
        var changed = bytes; changed[changed.count - 1] ^= 1
        XCTAssertThrowsError(try VaultCrypto.open(changed, key: key, expectedSalt: salt))
        XCTAssertThrowsError(try VaultCrypto.open(bytes, key: key, expectedSalt: Data(repeating: 8, count: 32)))
    }
    func testPBKDF2IndependentRFC7914Vector() throws {
        // RFC 7914 section 11 PBKDF2-HMAC-SHA256 vector, no app-specific round trip oracle.
        XCTAssertEqual(try VaultCrypto.pbkdf2("passwd", salt: Data("salt".utf8), rounds: 1, count: 64).hex,
                       "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783")
    }
}

final class StorageSignerTests: XCTestCase {
    func testOSSOfficialCanonicalRequestHash() throws {
        let headers = ["content-disposition":"attachment", "content-length":"3", "content-md5":"ICy5YqxZB1uWSwcVLSNLcA==", "content-type":"text/plain", "x-oss-content-sha256":"UNSIGNED-PAYLOAD", "x-oss-date":"20250411T064124Z"]
        let canonical = CloudSigner.ossCanonical(method: "PUT", resource: "/examplebucket/exampleobject", query: [:], headers: headers, additional: ["content-disposition", "content-length"])
        XCTAssertEqual(Data(SHA256.hash(data: Data(canonical.utf8))).hex, "c46d96390bdbc2d739ac9363293ae9d710b14e48081fcb22cd8ad54b63136eca")
    }
    func testOSSOfficialSDKAuthorizationVectorsIncludingSTSAndAdditionalHeaders() {
        // Alibaba's Swift SDK SignerV4Tests.swift vectors, independently published expected signatures.
        let query = ["param1":"value1", "+param1":"value3", "|param1":"value4", "+param2":"", "|param2":"", "param2":""]
        var headers = ["x-oss-head1":"value", "abc":"value", "zabc":"value", "xyz":"value", "content-type":"text/plain", "x-oss-content-sha256":"UNSIGNED-PAYLOAD", "x-oss-date":"20231216T162057Z"]
        let credentials = CloudCredentials(accessKeyID: "ak", secretKey: "sk")
        let first = CloudSigner.ossAuthorization(method: "PUT", resource: "/bucket/1234+-/123/1.txt", query: query, headers: headers, credentials: credentials, region: "cn-hangzhou", timestamp: "20231216T162057Z")
        XCTAssertEqual(first, "OSS4-HMAC-SHA256 Credential=ak/20231216/cn-hangzhou/oss/aliyun_v4_request,Signature=e21d18daa82167720f9b1047ae7e7f1ce7cb77a31e8203a7d5f4624fa0284afe")
        headers["x-oss-date"] = "20231217T034736Z"; headers["x-oss-security-token"] = "token"
        let token = CloudSigner.ossAuthorization(method: "PUT", resource: "/bucket/1234+-/123/1.txt", query: query, headers: headers, credentials: CloudCredentials(accessKeyID: "ak", secretKey: "sk", securityToken: "token"), region: "cn-hangzhou", timestamp: "20231217T034736Z")
        XCTAssertTrue(token.hasSuffix("Signature=b94a3f999cf85bcdc00d332fbd3734ba03e48382c36fa4d5af5df817395bd9ea"), token)
        headers["x-oss-security-token"] = nil; headers["x-oss-date"] = "20231216T172512Z"
        let additional = CloudSigner.ossAuthorization(method: "PUT", resource: "/bucket/1234+-/123/1.txt", query: query, headers: headers, credentials: credentials, region: "cn-hangzhou", timestamp: "20231216T172512Z", additional: ["abc", "zabc"])
        XCTAssertTrue(additional.hasSuffix("Signature=4a4183c187c07c8947db7620deb0a6b38d9fbdd34187b6dbaccb316fa251212f"), additional)
    }
    func testCOSOfficialIndependentSignatureVector() {
        let credentials = CloudCredentials(accessKeyID: "AKIDQjz3ltompVjBni5LitkWHFlFpwkn9U5q", secretKey: "BQYIM75p8x0iWVFSIgqEKwFprpRSVHlz")
        let auth = CloudSigner.cosAuthorization(method: "GET", path: "/testfile", query: [:], headers: ["host":"bucket1-1254000000.cos.ap-beijing.myqcloud.com", "range":"bytes=0-3"], credentials: credentials, keyTime: "1417773892;1417853898")
        XCTAssertTrue(auth.hasSuffix("q-signature=4b6cbab14ce01381c29032423481ebffd514e8be"), auth)
    }
    func testPaginationRejectsMissingCursorAndParsesEscaping() throws {
        let page = try ObjectListPage.parse(Data("<ListBucketResult><Contents><Key>a&amp;b</Key></Contents><IsTruncated>true</IsTruncated><NextMarker>next&amp;one</NextMarker></ListBucketResult>".utf8), kind: .cos)
        XCTAssertEqual(page.keys, ["a&b"]); XCTAssertEqual(page.next, "next&one")
        XCTAssertThrowsError(try ObjectListPage.parse(Data("<ListBucketResult><IsTruncated>true</IsTruncated></ListBucketResult>".utf8), kind: .oss))
    }
}

actor MemorySecrets: SecretStore {
    var values: [String: Data] = [:]
    func read(_ account: String) throws -> Data? { values[account] }
    func write(_ value: Data, account: String) throws { values[account] = value }
    func remove(_ account: String) throws { values.removeValue(forKey: account) }
}
actor MemoryObjects: ObjectStore {
    var values: [String: Data] = [:]
    var hidden: Set<String> = []
    var failUploads = false
    var attempts: [OutboxObject] = []
    var gets: [String] = []
    var pauseList = false
    var listGate: CheckedContinuation<Void, Never>?
    var observer: CheckedContinuation<Void, Never>?
    func get(_ key: String) throws -> Data? { gets.append(key); return values[key] }
    func put(_ data: Data, key: String, createOnly: Bool) throws {
        attempts.append(OutboxObject(key: key, bytes: data))
        if failUploads { throw VaultError.network("offline") }
        if createOnly && values[key] != nil { throw VaultError.targetExists }
        values[key] = data
    }
    func list(prefix: String) async throws -> [String] {
        let result = values.keys.filter { $0.hasPrefix(prefix) && !hidden.contains($0) }.sorted()
        if pauseList {
            pauseList = false
            await withCheckedContinuation { continuation in listGate = continuation; observer?.resume(); observer = nil }
        }
        return result
    }
    func pauseNextListing() { pauseList = true }
    func waitForPausedListing() async { if listGate != nil { return }; await withCheckedContinuation { observer = $0 } }
    func resumeListing() { listGate?.resume(); listGate = nil }
    func uploadHistory() -> [OutboxObject] { attempts }
    func allObjects() -> [String: Data] { values }
    func setObject(_ bytes: Data, key: String) { values[key] = bytes }
    func unhide() { hidden = [] }
    func hide(_ keys: Set<String>) { hidden = keys }
    func getHistory() -> [String] { gets }
    func setFail(_ flag: Bool) { failUploads = flag }
    func hideAllCommits() { hidden = Set(values.keys.filter { $0.hasSuffix(".commit") }) }
}

final class StorageRepositoryTests: XCTestCase {
    func temp() throws -> URL { let url = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString); try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true); return url }
    func testLocalCorruptionNeverBecomesEmptyAndCannotOverwrite() async throws {
        let root = try temp(); defer { try? FileManager.default.removeItem(at: root) }
        let secrets = MemorySecrets(); let repository = VaultRepository(applicationDirectory: root, secrets: secrets)
        let config = StorageConfiguration()
        let initial = VaultDocument(connections: [SSHConnection(name: "keep", host: "host")])
        _ = try await repository.setup(VaultSetupRequest(configuration: config, initialDocument: initial))
        let path = await repository.activeStateURLForTesting()
        try Data("corrupt".utf8).write(to: XCTUnwrap(path))
        let restored = VaultRepository(applicationDirectory: root, secrets: secrets)
        do { _ = try await restored.restore(); XCTFail("Corruption accepted") } catch {}
        do { _ = try await repository.save(VaultDocument()); XCTFail("Overwrote corrupt file") } catch {}
        XCTAssertEqual(try Data(contentsOf: XCTUnwrap(path)), Data("corrupt".utf8))
    }
    func testCloudConcurrentCredentialEditAndDeletionAreExplicitConflicts() async throws {
        let objects = MemoryObjects(); let secrets = MemorySecrets(); let aRoot = try temp(); let bRoot = try temp()
        defer { try? FileManager.default.removeItem(at: aRoot); try? FileManager.default.removeItem(at: bRoot) }
        let credentials = CloudCredentials(accessKeyID: "id", secretKey: "secret")
        let config = StorageConfiguration(kind: .cos, region: "ap-beijing", bucket: "test-123")
        let credential = SSHCredential(password: "first")
        let connection = SSHConnection(name: "node", host: "h", authentication: .password, credentialID: credential.id)
        let original = VaultDocument(connections: [connection], credentials: [credential.id: credential])
        let a = VaultRepository(applicationDirectory: aRoot, secrets: secrets, storeFactory: { _, _ in objects })
        let b = VaultRepository(applicationDirectory: bRoot, secrets: secrets, storeFactory: { _, _ in objects })
        _ = try await a.setup(VaultSetupRequest(configuration: config, masterPassword: "password", cloudCredentials: credentials, initialDocument: original))
        _ = try await b.setup(VaultSetupRequest(configuration: config, mode: .open, masterPassword: "password", cloudCredentials: credentials))
        var edit = original; edit.credentials[credential.id]?.password = "changed"
        _ = try await a.save(edit)
        _ = try await b.save(VaultDocument(deletions: [connection.id: Date()]))
        _ = try await a.sync(); let conflict = try await b.sync()
        XCTAssertEqual(conflict.conflicts.count, 1)
        XCTAssertTrue(conflict.conflicts[0].options.contains { $0.connection == nil })
        XCTAssertTrue(conflict.conflicts[0].options.contains { $0.credential?.password == "changed" })
        var lateEdit = conflict.document; lateEdit.connections.append(SSHConnection(name: "late unrelated"))
        let revisedConflict = try await b.save(lateEdit); XCTAssertEqual(revisedConflict.status, .conflict)
        let selected = try XCTUnwrap(revisedConflict.conflicts[0].options.first { $0.connection != nil })
        let resolved = try await b.resolveConflicts(choices: [connection.id: selected.id])
        XCTAssertEqual(resolved.document.credentials[credential.id]?.password, "changed")
        XCTAssertTrue(resolved.document.connections.contains { $0.name == "late unrelated" })
        _ = try await b.sync(); await objects.hideAllCommits()
        let stable = try await b.sync(); XCTAssertTrue(stable.conflicts.isEmpty)
    }
    func testOutboxPersistsExactBytesAcrossOfflineRestart() async throws {
        let root = try temp(); defer { try? FileManager.default.removeItem(at: root) }
        let objects = MemoryObjects(); let secrets = MemorySecrets()
        let config = StorageConfiguration(kind: .oss, region: "cn-hangzhou", bucket: "test")
        let a = VaultRepository(applicationDirectory: root, secrets: secrets, storeFactory: { _, _ in objects })
        _ = try await a.setup(VaultSetupRequest(configuration: config, masterPassword: "password", cloudCredentials: CloudCredentials(accessKeyID: "id", secretKey: "s")))
        await objects.setFail(true)
        _ = try await a.save(VaultDocument(connections: [SSHConnection(name: "offline")]))
        do { _ = try await a.sync(); XCTFail() } catch {}
        let history = await objects.uploadHistory(); let failedBytes = try XCTUnwrap(history.last)
        let b = VaultRepository(applicationDirectory: root, secrets: secrets, storeFactory: { _, _ in objects })
        let restored = try await b.restore(); XCTAssertEqual(restored?.document.connections.first?.name, "offline")
        await objects.setFail(false)
        let synced = try await b.sync(); XCTAssertEqual(synced.status, .synced)
        let uploaded = await objects.allObjects(); XCTAssertEqual(uploaded[failedBytes.key], failedBytes.bytes)
    }
}

actor PageHTTP {
    var cursors: [String?] = []
    let kind: StorageKind
    let repeatCursor: Bool
    init(_ kind: StorageKind, repeatCursor: Bool = false) { self.kind = kind; self.repeatCursor = repeatCursor }
    func respond(_ request: URLRequest) throws -> (Data, Int) {
        let params = URLComponents(url: request.url!, resolvingAgainstBaseURL: false)!.queryItems ?? []
        let cursor = params.first { $0.name == (kind == .oss ? "continuation-token" : "marker") }?.value
        cursors.append(cursor)
        if cursors.count == 1 || repeatCursor {
            let tag = kind == .oss ? "NextContinuationToken" : "NextMarker"
            return (Data("<ListBucketResult><Contents><Key>prefix/one</Key></Contents><IsTruncated>true</IsTruncated><\(tag)>page&amp;+二</\(tag)></ListBucketResult>".utf8), 200)
        }
        guard cursor == "page&+二" else { throw VaultError.corrupt("cursor changed") }
        return (Data("<ListBucketResult><Contents><Key>prefix/two</Key></Contents><IsTruncated>false</IsTruncated></ListBucketResult>".utf8), 200)
    }
    func count() -> Int { cursors.count }
}

final class StoragePaginationTests: XCTestCase {
    func testOSSAndCOSListEveryPageAndPreserveOpaqueCursor() async throws {
        for kind in [StorageKind.oss, .cos] {
            let http = PageHTTP(kind)
            let store = try CloudObjectStore(configuration: StorageConfiguration(kind: kind, region: kind == .oss ? "cn-hangzhou" : "ap-beijing", bucket: "example-123"), credentials: CloudCredentials(accessKeyID: "id", secretKey: "key"), transport: { try await http.respond($0) })
            let result = try await store.list(prefix: "prefix/")
            XCTAssertEqual(result, ["prefix/one", "prefix/two"])
            let count = await http.count(); XCTAssertEqual(count, 2)
        }
    }
    func testRepeatedCursorFailsWithoutInfiniteLoop() async throws {
        let http = PageHTTP(.cos, repeatCursor: true)
        let store = try CloudObjectStore(configuration: StorageConfiguration(kind: .cos, region: "ap-beijing", bucket: "example-123"), credentials: CloudCredentials(accessKeyID: "id", secretKey: "key"), transport: { try await http.respond($0) })
        do { _ = try await store.list(prefix: "prefix/"); XCTFail("Accepted repeating cursor") } catch VaultError.corrupt {} catch { XCTFail("\(error)") }
        let count = await http.count(); XCTAssertEqual(count, 2)
    }
}

extension StorageRepositoryTests {
    func testEditDuringSuspendedListingIsNeverOverwritten() async throws {
        let root = try temp(); defer { try? FileManager.default.removeItem(at: root) }
        let objects = MemoryObjects(); let secrets = MemorySecrets()
        let config = StorageConfiguration(kind: .cos, region: "ap-beijing", bucket: "example-123")
        let repo = VaultRepository(applicationDirectory: root, secrets: secrets, storeFactory: { _, _ in objects })
        _ = try await repo.setup(VaultSetupRequest(configuration: config, masterPassword: "pw", cloudCredentials: CloudCredentials(accessKeyID: "id", secretKey: "key")))
        await objects.pauseNextListing()
        let running = Task { try await repo.sync() }
        await objects.waitForPausedListing()
        let document = VaultDocument(connections: [SSHConnection(name: "edited while downloading", host: "h")])
        _ = try await repo.save(document)
        await objects.resumeListing()
        let synced = try await running.value
        XCTAssertEqual(synced.document, document)
        let restarted = VaultRepository(applicationDirectory: root, secrets: secrets, storeFactory: { _, _ in objects })
        let restored = try await restarted.restore(); XCTAssertEqual(restored?.document, document)
    }
    func testFailedSwitchKeepsOriginalSourceAndPendingEdits() async throws {
        let root = try temp(); defer { try? FileManager.default.removeItem(at: root) }
        let objects = MemoryObjects(); let secrets = MemorySecrets()
        let cloudConfig = StorageConfiguration(kind: .oss, region: "cn-hangzhou", bucket: "example-123")
        let repo = VaultRepository(applicationDirectory: root, secrets: secrets, storeFactory: { _, _ in objects })
        let cloudCredentials = CloudCredentials(accessKeyID: "id", secretKey: "key")
        _ = try await repo.setup(VaultSetupRequest(configuration: cloudConfig, masterPassword: "pw", cloudCredentials: cloudCredentials))
        let localConfig = StorageConfiguration()
        let original = VaultDocument(connections: [SSHConnection(name: "source")])
        _ = try await repo.setup(VaultSetupRequest(configuration: localConfig, initialDocument: original))
        await objects.pauseNextListing()
        let switching = Task { try await repo.setup(VaultSetupRequest(configuration: cloudConfig, mode: .open, masterPassword: "pw", cloudCredentials: cloudCredentials, initialDocument: original)) }
        await objects.waitForPausedListing()
        var edited = original; edited.connections[0].name = "new source edit"
        _ = try await repo.save(edited); await objects.resumeListing()
        do { _ = try await switching.value; XCTFail("Switched with stale migration") } catch VaultError.sourceChanged {} catch { XCTFail("\(error)") }
        let restored = try await repo.restore(); XCTAssertEqual(restored?.configuration, localConfig); XCTAssertEqual(restored?.document, edited)
    }
    func testBackupConflictPersistsAndLocalResolutionRetainsChosenCredential() async throws {
        let root = try temp(); defer { try? FileManager.default.removeItem(at: root) }
        let secrets = MemorySecrets(); let repo = VaultRepository(applicationDirectory: root, secrets: secrets)
        let credential = SSHCredential(password: "exact password  ")
        let connection = SSHConnection(name: "kept", authentication: .password, credentialID: credential.id)
        var document = VaultDocument(connections: [connection], credentials: [credential.id: credential])
        _ = try await repo.setup(VaultSetupRequest(configuration: StorageConfiguration(), initialDocument: document))
        let backup = try await repo.exportBackup(password: "backup")
        document.credentials[credential.id]?.password = "different"
        _ = try await repo.save(document)
        do { _ = try await repo.importBackup(backup, password: "wrong"); XCTFail("Accepted wrong password") } catch VaultError.invalidPassword {} catch { XCTFail("\(error)") }
        let pending = try await repo.importBackup(backup, password: "backup"); XCTAssertEqual(pending.status, .conflict)
        var lateEdit = pending.document; lateEdit.connections.append(SSHConnection(name: "late unrelated")); lateEdit.credentials[credential.id]?.password = "third version"
        let editedConflict = try await repo.save(lateEdit); XCTAssertEqual(editedConflict.conflicts.first?.options.count, 3)
        lateEdit.connections[1].notes = "newest local edit supersedes prior local variant"
        let newestConflict = try await repo.save(lateEdit); XCTAssertEqual(newestConflict.conflicts.count, 1); XCTAssertEqual(newestConflict.conflicts.first?.options.count, 3)
        let restarted = VaultRepository(applicationDirectory: root, secrets: secrets)
        let restoredOptional = try await restarted.restore(); let restored = try XCTUnwrap(restoredOptional)
        let conflict = try XCTUnwrap(restored.conflicts.first)
        let backupOption = try XCTUnwrap(conflict.options.first { $0.credential?.password == "exact password  " })
        let resolved = try await restarted.resolveConflicts(choices: [connection.id: backupOption.id])
        XCTAssertEqual(resolved.document.credentials[credential.id]?.password, "exact password  ")
        XCTAssertEqual(resolved.status, .local)
        XCTAssertTrue(resolved.document.connections.contains { $0.name == "late unrelated" && $0.notes == "newest local edit supersedes prior local variant" })
    }
    func testRecoveryValidatesBeforeCreatingAndPreservesCorruptVault() async throws {
        let root = try temp(); defer { try? FileManager.default.removeItem(at: root) }
        let secrets = MemorySecrets(); let original = VaultRepository(applicationDirectory: root, secrets: secrets)
        let config = StorageConfiguration(); let document = VaultDocument(connections: [SSHConnection(name: "recover me")])
        _ = try await original.setup(VaultSetupRequest(configuration: config, initialDocument: document))
        let backup = try await original.exportBackup(password: "backup")
        let oldOptional = await original.activeStateURLForTesting(); let oldPath = try XCTUnwrap(oldOptional); let corrupt = Data("corrupt original".utf8)
        try corrupt.write(to: oldPath)
        let recovery = VaultRepository(applicationDirectory: root, secrets: secrets)
        do { _ = try await recovery.restore(); XCTFail() } catch {}
        let target = StorageConfiguration()
        do { _ = try await recovery.recoverBackup(backup, password: "wrong", configuration: target); XCTFail() } catch VaultError.invalidPassword {} catch { XCTFail("\(error)") }
        let targetPath = root.appendingPathComponent("Local/v1/\(target.vaultID.uuidString.lowercased())/vault.local")
        XCTAssertFalse(FileManager.default.fileExists(atPath: targetPath.path))
        let recovered = try await recovery.recoverBackup(backup, password: "backup", configuration: target)
        XCTAssertEqual(recovered.document, document); XCTAssertEqual(try Data(contentsOf: oldPath), corrupt)
        do { _ = try await recovery.recoverBackup(backup, password: "backup", configuration: target); XCTFail("Overwrote existing recovery") } catch VaultError.targetExists {} catch { XCTFail("\(error)") }
    }
    func testLocalMigrationMergesRecordsAndKeepsPreviousEncryptedFile() async throws {
        let root = try temp(); defer { try? FileManager.default.removeItem(at: root) }
        let secrets = MemorySecrets(); let repo = VaultRepository(applicationDirectory: root, secrets: secrets)
        let config = StorageConfiguration()
        let connection = SSHConnection(name: "target")
        _ = try await repo.setup(VaultSetupRequest(configuration: config, initialDocument: VaultDocument(connections: [connection])))
        let pathOptional = await repo.activeStateURLForTesting(); let path = try XCTUnwrap(pathOptional); let previousBytes = try Data(contentsOf: path)
        let migrated = try await repo.setup(VaultSetupRequest(configuration: config, mode: .open, initialDocument: VaultDocument(connections: [SSHConnection(name: "migrated")])))
        XCTAssertEqual(Set(migrated.document.connections.map(\.name)), ["target", "migrated"])
        XCTAssertEqual(try Data(contentsOf: path.appendingPathExtension("previous")), previousBytes)
        let mode = try FileManager.default.attributesOfItem(atPath: path.path)[.posixPermissions] as? NSNumber; XCTAssertEqual(mode?.intValue, 0o600)
    }
    func testCloudLockedRestoreCannotSaveAndWrongPasswordDoesNotSwitch() async throws {
        let root = try temp(); defer { try? FileManager.default.removeItem(at: root) }
        let objects = MemoryObjects(); let secrets = MemorySecrets()
        let config = StorageConfiguration(kind: .cos, region: "ap-beijing", bucket: "example-123")
        let repo = VaultRepository(applicationDirectory: root, secrets: secrets, storeFactory: { _, _ in objects })
        let credentials = CloudCredentials(accessKeyID: "id", secretKey: "key")
        _ = try await repo.setup(VaultSetupRequest(configuration: config, masterPassword: "pw", cloudCredentials: credentials, rememberUnlock: false))
        do { _ = try await repo.restore(); XCTFail("Did not lock") } catch VaultError.locked {} catch { XCTFail("\(error)") }
        do { _ = try await repo.save(VaultDocument()); XCTFail("Saved locked vault") } catch VaultError.locked {} catch { XCTFail("\(error)") }
        do { _ = try await repo.unlock(password: "wrong"); XCTFail() } catch VaultError.invalidPassword {} catch { XCTFail("\(error)") }
        let unlocked = try await repo.unlock(password: "pw"); XCTAssertEqual(unlocked.configuration, config)
    }
}

extension StorageRepositoryTests {
    func testDelayedListingFetchesMissingParentDirectlyAndKeepsKnownHeads() async throws {
        let aRoot = try temp(); let bRoot = try temp()
        defer { try? FileManager.default.removeItem(at: aRoot); try? FileManager.default.removeItem(at: bRoot) }
        let objects = MemoryObjects(); let secrets = MemorySecrets()
        let config = StorageConfiguration(kind: .cos, region: "ap-beijing", bucket: "example-123")
        let credentials = CloudCredentials(accessKeyID: "id", secretKey: "key")
        let a = VaultRepository(applicationDirectory: aRoot, secrets: secrets, storeFactory: { _, _ in objects })
        let b = VaultRepository(applicationDirectory: bRoot, secrets: secrets, storeFactory: { _, _ in objects })
        _ = try await a.setup(VaultSetupRequest(configuration: config, masterPassword: "pw", cloudCredentials: credentials))
        _ = try await b.setup(VaultSetupRequest(configuration: config, mode: .open, masterPassword: "pw", cloudCredentials: credentials))
        let initialObjects = await objects.allObjects()
        _ = try await a.save(VaultDocument(connections: [SSHConnection(name: "parent revision")]))
        _ = try await a.sync()
        let parentObjects = await objects.allObjects()
        let hiddenParents = Set(parentObjects.keys.filter { $0.hasSuffix(".commit") && initialObjects[$0] == nil })
        let finalDocument = VaultDocument(connections: [SSHConnection(name: "child revision")])
        _ = try await a.save(finalDocument); _ = try await a.sync()
        await objects.hide(hiddenParents)
        let discovered = try await b.sync()
        XCTAssertEqual(discovered.document.connections.map(\.name), ["child revision"])
        let gets = await objects.getHistory(); XCTAssertTrue(hiddenParents.allSatisfy(gets.contains))
        await objects.hideAllCommits()
        let stable = try await b.sync(); XCTAssertEqual(stable.document, discovered.document); XCTAssertEqual(stable.status, .synced)
    }
    func testIndependentConcurrentRecordEditsMergeAndConsumeBothHeads() async throws {
        let aRoot = try temp(); let bRoot = try temp()
        defer { try? FileManager.default.removeItem(at: aRoot); try? FileManager.default.removeItem(at: bRoot) }
        let objects = MemoryObjects(); let secrets = MemorySecrets()
        let config = StorageConfiguration(kind: .oss, region: "cn-hangzhou", bucket: "example-123")
        let credentials = CloudCredentials(accessKeyID: "id", secretKey: "key")
        let original = VaultDocument(connections: [SSHConnection(name: "A"), SSHConnection(name: "B")])
        let a = VaultRepository(applicationDirectory: aRoot, secrets: secrets, storeFactory: { _, _ in objects })
        let b = VaultRepository(applicationDirectory: bRoot, secrets: secrets, storeFactory: { _, _ in objects })
        _ = try await a.setup(VaultSetupRequest(configuration: config, masterPassword: "pw", cloudCredentials: credentials, initialDocument: original))
        _ = try await b.setup(VaultSetupRequest(configuration: config, mode: .open, masterPassword: "pw", cloudCredentials: credentials))
        var aEdit = original; aEdit.connections[0].name = "A edited"
        var bEdit = original; bEdit.connections[1].name = "B edited"
        _ = try await a.save(aEdit); _ = try await b.save(bEdit)
        _ = try await a.sync(); let merged = try await b.sync()
        XCTAssertEqual(Set(merged.document.connections.map(\.name)), ["A edited", "B edited"])
        XCTAssertTrue(merged.conflicts.isEmpty); XCTAssertEqual(merged.status, .synced)
        let acknowledged = try await a.sync(); XCTAssertEqual(acknowledged.document, merged.document)
    }
    func testMissingRemoteSnapshotIsCorruptionAndKeepsCurrentData() async throws {
        let aRoot = try temp(); let bRoot = try temp()
        defer { try? FileManager.default.removeItem(at: aRoot); try? FileManager.default.removeItem(at: bRoot) }
        let objects = MemoryObjects(); let secrets = MemorySecrets()
        let config = StorageConfiguration(kind: .cos, region: "ap-beijing", bucket: "example-123")
        let credentials = CloudCredentials(accessKeyID: "id", secretKey: "key")
        let original = VaultDocument(connections: [SSHConnection(name: "never lose")])
        let a = VaultRepository(applicationDirectory: aRoot, secrets: secrets, storeFactory: { _, _ in objects })
        let b = VaultRepository(applicationDirectory: bRoot, secrets: secrets, storeFactory: { _, _ in objects })
        _ = try await a.setup(VaultSetupRequest(configuration: config, masterPassword: "pw", cloudCredentials: credentials, initialDocument: original))
        _ = try await b.setup(VaultSetupRequest(configuration: config, mode: .open, masterPassword: "pw", cloudCredentials: credentials))
        let before = await objects.allObjects()
        _ = try await a.save(VaultDocument(connections: [SSHConnection(name: "remote")]))
        _ = try await a.sync(); let after = await objects.allObjects()
        let changedBlob = try XCTUnwrap(after.keys.first { $0.hasSuffix(".vault") && before[$0] == nil })
        await objects.setObject(Data("bad snapshot".utf8), key: changedBlob)
        do { _ = try await b.sync(); XCTFail("Accepted corrupted remote snapshot") } catch VaultError.corrupt {} catch { XCTFail("\(error)") }
        let restored = try await b.restore(); XCTAssertEqual(restored?.document, original)
    }
}

final class StorageKeychainTests: XCTestCase {
    func testDeviceKeychainStoresUpdatesAndRemovesOnlyScopedAccount() async throws {
        let store = KeychainSecrets(); let account = "storage.test." + UUID().uuidString
        try await store.write(Data("first".utf8), account: account)
        let first = try await store.read(account); XCTAssertEqual(first, Data("first".utf8))
        try await store.write(Data("second".utf8), account: account)
        let second = try await store.read(account); XCTAssertEqual(second, Data("second".utf8))
        try await store.remove(account)
        let removed = try await store.read(account); XCTAssertNil(removed)
    }
}

extension StorageRepositoryTests {
    func testCrissCrossResolutionsRetainDisagreementAcrossMultipleMergeBases() async throws {
        let aRoot = try temp(); let bRoot = try temp()
        defer { try? FileManager.default.removeItem(at: aRoot); try? FileManager.default.removeItem(at: bRoot) }
        let objects = MemoryObjects(); let secrets = MemorySecrets()
        let config = StorageConfiguration(kind: .cos, region: "ap-beijing", bucket: "example-123")
        let credentials = CloudCredentials(accessKeyID: "id", secretKey: "key")
        let connection = SSHConnection(name: "base")
        let original = VaultDocument(connections: [connection])
        let a = VaultRepository(applicationDirectory: aRoot, secrets: secrets, storeFactory: { _, _ in objects })
        let b = VaultRepository(applicationDirectory: bRoot, secrets: secrets, storeFactory: { _, _ in objects })
        _ = try await a.setup(VaultSetupRequest(configuration: config, masterPassword: "pw", cloudCredentials: credentials, initialDocument: original))
        _ = try await b.setup(VaultSetupRequest(configuration: config, mode: .open, masterPassword: "pw", cloudCredentials: credentials))
        var aEdit = original; aEdit.connections[0].name = "A"
        var bEdit = original; bEdit.connections[0].name = "B"
        _ = try await a.save(aEdit); _ = try await b.save(bEdit)
        _ = try await a.sync(); let bConflict = try await b.sync(); let aConflict = try await a.sync()
        let aOption = try XCTUnwrap(aConflict.conflicts[0].options.first { $0.connection?.name == "A" })
        let bOption = try XCTUnwrap(bConflict.conflicts[0].options.first { $0.connection?.name == "B" })
        _ = try await a.resolveConflicts(choices: [connection.id: aOption.id])
        _ = try await b.resolveConflicts(choices: [connection.id: bOption.id])
        _ = try await a.sync(); let crissCross = try await b.sync()
        XCTAssertEqual(crissCross.status, .conflict)
        XCTAssertEqual(Set(crissCross.conflicts[0].options.compactMap { $0.connection?.name }), ["A", "B"])
    }
    func testImportDuringSuspendedSyncPreservesAllBackupVariants() async throws {
        let root = try temp(); defer { try? FileManager.default.removeItem(at: root) }
        let objects = MemoryObjects(); let secrets = MemorySecrets()
        let config = StorageConfiguration(kind: .oss, region: "cn-hangzhou", bucket: "example-123")
        let connection = SSHConnection(name: "backup version")
        let original = VaultDocument(connections: [connection])
        let repo = VaultRepository(applicationDirectory: root, secrets: secrets, storeFactory: { _, _ in objects })
        _ = try await repo.setup(VaultSetupRequest(configuration: config, masterPassword: "pw", cloudCredentials: CloudCredentials(accessKeyID: "id", secretKey: "key"), initialDocument: original))
        let backup = try await repo.exportBackup(password: "backup")
        var edited = original; edited.connections[0].name = "new version"
        _ = try await repo.save(edited)
        await objects.pauseNextListing(); let running = Task { try await repo.sync() }; await objects.waitForPausedListing()
        let imported = try await repo.importBackup(backup, password: "backup"); XCTAssertEqual(imported.status, .conflict)
        await objects.resumeListing(); let finished = try await running.value
        XCTAssertEqual(finished.status, .conflict)
        XCTAssertEqual(Set(finished.conflicts[0].options.compactMap { $0.connection?.name }), ["backup version", "new version"])
    }
    func testMissingLocalKeyPreservesCiphertextAndRestoreNilOnlyWithoutConfig() async throws {
        let root = try temp(); defer { try? FileManager.default.removeItem(at: root) }
        let secrets = MemorySecrets(); let repo = VaultRepository(applicationDirectory: root, secrets: secrets)
        let noConfig = try await repo.restore(); XCTAssertNil(noConfig)
        let config = StorageConfiguration()
        _ = try await repo.setup(VaultSetupRequest(configuration: config, initialDocument: VaultDocument(connections: [SSHConnection(name: "important")])))
        let pathOptional = await repo.activeStateURLForTesting(); let path = try XCTUnwrap(pathOptional); let before = try Data(contentsOf: path)
        try await secrets.remove("local-key." + config.vaultID.uuidString.lowercased())
        do { _ = try await repo.restore(); XCTFail("Missing key became empty vault") } catch VaultError.missingKey {} catch { XCTFail("\(error)") }
        do { _ = try await repo.save(VaultDocument()); XCTFail("Saved without key") } catch VaultError.locked {} catch { XCTFail("\(error)") }
        XCTAssertEqual(try Data(contentsOf: path), before)
    }
}

actor VersionedHTTP {
    var puts = 0
    var queries: [String] = []
    func respond(_ request: URLRequest) -> (Data, Int) {
        if request.httpMethod == "PUT" { puts += 1; return (Data(), 200) }
        if request.url!.query?.contains("versioning") == true { queries.append(request.url!.query!); return (Data("<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>".utf8), 200) }
        return (Data(), 404)
    }
    func putCount() -> Int { puts }
}
extension StoragePaginationTests {
    func testVersionedBucketsCannotOverwriteImmutableDescriptor() async throws {
        for kind in [StorageKind.oss, .cos] {
            let http = VersionedHTTP()
            let store = try CloudObjectStore(configuration: StorageConfiguration(kind: kind, region: kind == .oss ? "cn-hangzhou" : "ap-beijing", bucket: "example-123"), credentials: CloudCredentials(accessKeyID: "id", secretKey: "key"), transport: { await http.respond($0) })
            do { try await store.put(Data("descriptor".utf8), key: "v1/id/vault.json", createOnly: true); XCTFail("Wrote a versioned bucket") } catch VaultError.invalidConfiguration {} catch { XCTFail("\(error)") }
            let count = await http.putCount(); XCTAssertEqual(count, 0)
        }
    }
}

extension StorageRepositoryTests {
    func testUnreferencedCredentialVersionsAreNeverSilentlyDiscarded() async throws {
        let root = try temp(); defer { try? FileManager.default.removeItem(at: root) }
        let secrets = MemorySecrets(); let repo = VaultRepository(applicationDirectory: root, secrets: secrets)
        let credential = SSHCredential(password: "first")
        let original = VaultDocument(credentials: [credential.id: credential])
        _ = try await repo.setup(VaultSetupRequest(configuration: StorageConfiguration(), initialDocument: original))
        let backup = try await repo.exportBackup(password: "backup")
        var edited = original; edited.credentials[credential.id]?.password = "second"
        _ = try await repo.save(edited)
        let imported = try await repo.importBackup(backup, password: "backup")
        XCTAssertEqual(imported.status, .conflict); XCTAssertEqual(imported.conflicts.count, 1)
        XCTAssertEqual(Set(imported.conflicts[0].options.compactMap { $0.credential?.password }), ["first", "second"])
        let option = try XCTUnwrap(imported.conflicts[0].options.first { $0.credential?.password == "first" })
        let resolved = try await repo.resolveConflicts(choices: [credential.id: option.id])
        XCTAssertEqual(resolved.document.credentials[credential.id]?.password, "first")
    }
}

extension StorageRepositoryTests {
    func testSharedCredentialCollisionPreservesBothSecretsForReview() async throws {
        let aRoot = try temp(); let bRoot = try temp()
        defer { try? FileManager.default.removeItem(at: aRoot); try? FileManager.default.removeItem(at: bRoot) }
        let objects = MemoryObjects(); let secrets = MemorySecrets()
        let config = StorageConfiguration(kind: .oss, region: "cn-hangzhou", bucket: "example-123")
        let credentials = CloudCredentials(accessKeyID: "id", secretKey: "key")
        let credential = SSHCredential(password: "original")
        let connection = SSHConnection(name: "old", authentication: .password, credentialID: credential.id)
        let original = VaultDocument(connections: [connection], credentials: [credential.id: credential])
        let a = VaultRepository(applicationDirectory: aRoot, secrets: secrets, storeFactory: { _, _ in objects })
        let b = VaultRepository(applicationDirectory: bRoot, secrets: secrets, storeFactory: { _, _ in objects })
        _ = try await a.setup(VaultSetupRequest(configuration: config, masterPassword: "pw", cloudCredentials: credentials, initialDocument: original))
        _ = try await b.setup(VaultSetupRequest(configuration: config, mode: .open, masterPassword: "pw", cloudCredentials: credentials))
        var aEdit = original; aEdit.connections.append(SSHConnection(name: "new sharing key", authentication: .password, credentialID: credential.id))
        var bEdit = original; bEdit.credentials[credential.id]?.password = "changed"
        _ = try await a.save(aEdit); _ = try await b.save(bEdit)
        _ = try await a.sync(); let result = try await b.sync()
        XCTAssertEqual(result.status, .conflict)
        let shared = try XCTUnwrap(result.conflicts.first { $0.id == credential.id })
        XCTAssertEqual(Set(shared.options.compactMap { $0.credential?.password }), ["original", "changed"])
        var choices: [UUID: String] = [:]
        for conflict in result.conflicts { choices[conflict.id] = try XCTUnwrap(conflict.options.first { $0.credential?.password == "changed" || $0.credential == nil }).id }
        let resolved = try await b.resolveConflicts(choices: choices)
        XCTAssertEqual(resolved.document.credentials[credential.id]?.password, "changed")
        XCTAssertEqual(resolved.document.connections.count, 2)
    }
}

extension StorageRepositoryTests {
    func testLocalDiscoveryOpensSameVaultWithNewConfigurationIdentity() async throws {
        let root = try temp(); defer { try? FileManager.default.removeItem(at: root) }
        let secrets = MemorySecrets(); let repo = VaultRepository(applicationDirectory: root, secrets: secrets)
        let directory = root.appendingPathComponent("external local")
        let config = StorageConfiguration(localDirectory: directory.path)
        let original = VaultDocument(connections: [SSHConnection(name: "discover me")])
        _ = try await repo.setup(VaultSetupRequest(configuration: config, initialDocument: original))
        let ids = try await repo.discoverLocalVaults(directory: directory); XCTAssertEqual(ids, [config.vaultID])
        let reopened = try await repo.setup(VaultSetupRequest(configuration: StorageConfiguration(vaultID: config.vaultID, localDirectory: directory.path), mode: .open))
        XCTAssertEqual(reopened.document, original)
        let pathOptional = await repo.activeStateURLForTesting(); let path = try XCTUnwrap(pathOptional)
        try Data("corrupt".utf8).write(to: path)
        do { _ = try await repo.discoverLocalVaults(directory: directory); XCTFail("Corruption became empty discovery") } catch VaultError.corrupt {} catch { XCTFail("\(error)") }
    }
    func testMigrationIntoPendingBackupConflictCannotDropAnyVariant() async throws {
        let root = try temp(); defer { try? FileManager.default.removeItem(at: root) }
        let secrets = MemorySecrets(); let repo = VaultRepository(applicationDirectory: root, secrets: secrets)
        let config = StorageConfiguration(); let connection = SSHConnection(name: "backup")
        var document = VaultDocument(connections: [connection])
        _ = try await repo.setup(VaultSetupRequest(configuration: config, initialDocument: document))
        let backup = try await repo.exportBackup(password: "backup")
        document.connections[0].name = "current"; _ = try await repo.save(document)
        let pending = try await repo.importBackup(backup, password: "backup")
        do { _ = try await repo.setup(VaultSetupRequest(configuration: config, mode: .open, initialDocument: VaultDocument(connections: [SSHConnection(name: "migration")]))); XCTFail("Overwrote pending review variants") } catch VaultError.conflictsRequireResolution {} catch { XCTFail("\(error)") }
        let restored = try await repo.restore()
        XCTAssertEqual(Set(restored?.conflicts[0].options.compactMap { $0.connection?.name } ?? []), Set(pending.conflicts[0].options.compactMap { $0.connection?.name }))
    }
}

extension StorageRepositoryTests {
    func testMigrationConflictKeepsSourceActiveUntilReviewedResolution() async throws {
        let root = try temp(); defer { try? FileManager.default.removeItem(at: root) }
        let secrets = MemorySecrets()
        let targetConfig = StorageConfiguration(localDirectory: root.appendingPathComponent("target").path)
        let connection = SSHConnection(name: "target version")
        let targetDocument = VaultDocument(connections: [connection, SSHConnection(name: "target only")])
        let target = VaultRepository(applicationDirectory: root.appendingPathComponent("target app"), secrets: secrets)
        _ = try await target.setup(VaultSetupRequest(configuration: targetConfig, initialDocument: targetDocument))
        let source = VaultRepository(applicationDirectory: root.appendingPathComponent("source app"), secrets: secrets)
        let sourceConfig = StorageConfiguration()
        var sourceDocument = VaultDocument(connections: [connection]); sourceDocument.connections[0].name = "source version"
        _ = try await source.setup(VaultSetupRequest(configuration: sourceConfig, initialDocument: sourceDocument))
        let sourcePathOptional = await source.activeStateURLForTesting(); let sourcePath = try XCTUnwrap(sourcePathOptional); let originalSourceBytes = try Data(contentsOf: sourcePath)
        let pending = try await source.setup(VaultSetupRequest(configuration: targetConfig, mode: .open, initialDocument: sourceDocument))
        XCTAssertEqual(pending.configuration, sourceConfig); XCTAssertEqual(pending.document, sourceDocument); XCTAssertEqual(pending.status, .conflict)
        let configured = try JSONDecoder().decode(StorageConfiguration.self, from: Data(contentsOf: root.appendingPathComponent("source app/storage.json")))
        XCTAssertEqual(configured, sourceConfig)
        XCTAssertEqual(try Data(contentsOf: sourcePath), originalSourceBytes)
        let migrationChoice = try XCTUnwrap(pending.conflicts[0].options.first { $0.connection?.name == "source version" })
        let activated = try await source.resolveConflicts(choices: [connection.id: migrationChoice.id])
        XCTAssertEqual(activated.configuration, targetConfig)
        XCTAssertEqual(Set(activated.document.connections.map(\.name)), ["source version", "target only"])
        XCTAssertEqual(try Data(contentsOf: sourcePath), originalSourceBytes)
    }
    func testMigrationResolutionCannotOverwriteNewSourceEdits() async throws {
        let root = try temp(); defer { try? FileManager.default.removeItem(at: root) }
        let secrets = MemorySecrets(); let targetConfig = StorageConfiguration(localDirectory: root.appendingPathComponent("target").path)
        let connection = SSHConnection(name: "target")
        let target = VaultRepository(applicationDirectory: root.appendingPathComponent("target app"), secrets: secrets)
        _ = try await target.setup(VaultSetupRequest(configuration: targetConfig, initialDocument: VaultDocument(connections: [connection])))
        let source = VaultRepository(applicationDirectory: root.appendingPathComponent("source app"), secrets: secrets)
        let sourceConfig = StorageConfiguration(); var document = VaultDocument(connections: [connection]); document.connections[0].name = "source"
        _ = try await source.setup(VaultSetupRequest(configuration: sourceConfig, initialDocument: document))
        let pending = try await source.setup(VaultSetupRequest(configuration: targetConfig, mode: .open, initialDocument: document))
        document.connections[0].name = "edited after review began"; _ = try await source.save(document)
        do { _ = try await source.resolveConflicts(choices: [connection.id: pending.conflicts[0].options[0].id]); XCTFail("Activated stale migration") } catch VaultError.sourceChanged {} catch { XCTFail("\(error)") }
        let restored = try await source.restore(); XCTAssertEqual(restored?.configuration, sourceConfig); XCTAssertEqual(restored?.document, document)
        let stagedTarget = try await target.restore(); XCTAssertEqual(stagedTarget?.conflicts.count, 1)
        XCTAssertEqual(Set(stagedTarget?.conflicts[0].options.compactMap { $0.connection?.name } ?? []), ["source", "target"])
    }
}

extension StorageRepositoryTests {
    func testOnlineHistorySnapshotsStayBoundedAndOfflineOutboxUsesSeparateFiles() async throws {
        let root = try temp(); defer { try? FileManager.default.removeItem(at: root) }
        let objects = MemoryObjects(); let secrets = MemorySecrets()
        let config = StorageConfiguration(kind: .cos, region: "ap-beijing", bucket: "example-123")
        let credential = SSHCredential(privateKey: Data(repeating: 65, count: 1_024 * 1_024))
        let connection = SSHConnection(name: "base", authentication: .privateKey, credentialID: credential.id)
        var document = VaultDocument(connections: [connection], credentials: [credential.id: credential])
        let repo = VaultRepository(applicationDirectory: root, secrets: secrets, storeFactory: { _, _ in objects })
        _ = try await repo.setup(VaultSetupRequest(configuration: config, masterPassword: "pw", cloudCredentials: CloudCredentials(accessKeyID: "id", secretKey: "key"), initialDocument: document))
        for index in 1...35 { document.connections[0].name = "online edit \(index)"; _ = try await repo.save(document); _ = try await repo.sync() }
        let pathOptional = await repo.activeStateURLForTesting(); let path = try XCTUnwrap(pathOptional)
        XCTAssertLessThan(try Data(contentsOf: path).count, 6 * 1_024 * 1_024)
        await objects.setFail(true)
        for index in 1...30 { document.connections[0].name = "offline edit \(index)"; _ = try await repo.save(document) }
        XCTAssertLessThan(try Data(contentsOf: path).count, 6 * 1_024 * 1_024)
        let queue = try FileManager.default.contentsOfDirectory(at: path.deletingLastPathComponent().appendingPathComponent("outbox"), includingPropertiesForKeys: nil)
        XCTAssertGreaterThanOrEqual(queue.count, 60)
        let restarted = VaultRepository(applicationDirectory: root, secrets: secrets, storeFactory: { _, _ in objects })
        let restored = try await restarted.restore(); XCTAssertEqual(restored?.document, document)
        await objects.setFail(false); let synced = try await restarted.sync(); XCTAssertEqual(synced.status, .synced); XCTAssertEqual(synced.document, document)
    }
    func testReopeningCloudSourceWithNewIdentityFindsOldPendingOutbox() async throws {
        let root = try temp(); defer { try? FileManager.default.removeItem(at: root) }
        let objects = MemoryObjects(); let secrets = MemorySecrets()
        let config = StorageConfiguration(kind: .oss, region: "cn-hangzhou", bucket: "example-123")
        let credentials = CloudCredentials(accessKeyID: "id", secretKey: "key")
        let repo = VaultRepository(applicationDirectory: root, secrets: secrets, storeFactory: { _, _ in objects })
        _ = try await repo.setup(VaultSetupRequest(configuration: config, masterPassword: "pw", cloudCredentials: credentials))
        await objects.setFail(true)
        let pendingDocument = VaultDocument(connections: [SSHConnection(name: "unpushed cloud edit")])
        _ = try await repo.save(pendingDocument)
        _ = try await repo.setup(VaultSetupRequest(configuration: StorageConfiguration()))
        let reopenedConfig = StorageConfiguration(vaultID: config.vaultID, kind: .oss, region: config.region, bucket: config.bucket, prefix: config.prefix)
        let reopened = try await repo.setup(VaultSetupRequest(configuration: reopenedConfig, mode: .open, masterPassword: "pw", cloudCredentials: credentials))
        XCTAssertEqual(reopened.document, pendingDocument); XCTAssertEqual(reopened.status, .pending)
        await objects.setFail(false); let synced = try await repo.sync(); XCTAssertEqual(synced.document, pendingDocument); XCTAssertEqual(synced.status, .synced)
    }
}

extension StorageRepositoryTests {
    func testSelectingDeletionRemovesOnlyItsUnreferencedCredential() async throws {
        let root = try temp(); defer { try? FileManager.default.removeItem(at: root) }
        let secrets = MemorySecrets(); let repo = VaultRepository(applicationDirectory: root, secrets: secrets)
        let deletedSecret = SSHCredential(password: "remove me")
        let standalone = SSHCredential(password: "retain standalone")
        let connection = SSHConnection(name: "delete", authentication: .password, credentialID: deletedSecret.id)
        let original = VaultDocument(connections: [connection], credentials: [deletedSecret.id: deletedSecret, standalone.id: standalone])
        _ = try await repo.setup(VaultSetupRequest(configuration: StorageConfiguration(), initialDocument: original))
        let deleted = VaultDocument(deletions: [connection.id: Date()])
        let salt = try VaultCrypto.random(32); let key = try VaultCrypto.passwordKey("backup", salt: salt)
        let backup = try VaultCrypto.seal(JSONEncoder().encode(deleted), key: key, salt: salt)
        let pending = try await repo.importBackup(backup, password: "backup")
        let deletion = try XCTUnwrap(pending.conflicts.first { $0.id == connection.id }?.options.first { $0.connection == nil && $0.credential == nil })
        let resolved = try await repo.resolveConflicts(choices: [connection.id: deletion.id])
        XCTAssertTrue(resolved.document.connections.isEmpty)
        XCTAssertNil(resolved.document.credentials[deletedSecret.id])
        XCTAssertEqual(resolved.document.credentials[standalone.id], standalone)
    }
}

extension StorageRepositoryTests {
    func testConcurrentRemoteBranchAndSuspendedLocalSaveRetainMergeBase() async throws {
        let aRoot = try temp(); let bRoot = try temp()
        defer { try? FileManager.default.removeItem(at: aRoot); try? FileManager.default.removeItem(at: bRoot) }
        let objects = MemoryObjects(); let secrets = MemorySecrets()
        let config = StorageConfiguration(kind: .cos, region: "ap-beijing", bucket: "example-123")
        let credentials = CloudCredentials(accessKeyID: "id", secretKey: "key")
        let connection = SSHConnection(name: "base")
        let original = VaultDocument(connections: [connection])
        let a = VaultRepository(applicationDirectory: aRoot, secrets: secrets, storeFactory: { _, _ in objects })
        let b = VaultRepository(applicationDirectory: bRoot, secrets: secrets, storeFactory: { _, _ in objects })
        _ = try await a.setup(VaultSetupRequest(configuration: config, masterPassword: "pw", cloudCredentials: credentials, initialDocument: original))
        _ = try await b.setup(VaultSetupRequest(configuration: config, mode: .open, masterPassword: "pw", cloudCredentials: credentials))
        var remote = original; remote.connections[0].name = "remote"
        _ = try await b.save(remote); _ = try await b.sync()
        await objects.pauseNextListing(); let syncing = Task { try await a.sync() }; await objects.waitForPausedListing()
        var local = original; local.connections[0].name = "local during listing"
        _ = try await a.save(local); await objects.resumeListing()
        let result = try await syncing.value
        XCTAssertEqual(result.status, .conflict)
        XCTAssertEqual(Set(result.conflicts[0].options.compactMap { $0.connection?.name }), ["remote", "local during listing"])
    }
}
