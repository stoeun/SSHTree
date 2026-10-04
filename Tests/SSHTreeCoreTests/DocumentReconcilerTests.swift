import Foundation
import XCTest
@testable import SSHTreeCore

final class DocumentReconcilerTests: XCTestCase {
    func testLateSnapshotPreservesRenameAndRemoteAddition() {
        let connection = SSHConnection(name: "旧名称", host: "example.com", username: "root")
        let baseline = VaultDocument(connections: [connection])
        var current = baseline
        current.connections[0].name = "等待期间修改"
        var incoming = baseline
        let remote = SSHConnection(name: "远程新增", host: "remote.example", username: "root")
        incoming.connections.append(remote)
        let result = VaultDocumentReconciler.reconcile(incoming: incoming, baseline: baseline, current: current)
        XCTAssertEqual(result.connections.first { $0.id == connection.id }?.name, "等待期间修改")
        XCTAssertTrue(result.connections.contains(remote))
    }

    func testLateSnapshotPreservesCredentialBytesWithoutTrimming() {
        let credential = SSHCredential(password: "old")
        let connection = SSHConnection(name: "主机", host: "example.com", username: "root", authentication: .password, credentialID: credential.id)
        let baseline = VaultDocument(connections: [connection], credentials: [credential.id: credential])
        var current = baseline
        let password = "  secret\nwith whitespace  "
        let key = Data(" PRIVATE KEY\n\n ".utf8)
        current.credentials[credential.id] = SSHCredential(id: credential.id, password: password, privateKey: key, passphrase: "  phrase  ")
        let result = VaultDocumentReconciler.reconcile(incoming: baseline, baseline: baseline, current: current)
        XCTAssertEqual(result.credentials[credential.id]?.password, password)
        XCTAssertEqual(result.credentials[credential.id]?.privateKey, key)
        XCTAssertEqual(result.credentials[credential.id]?.passphrase, "  phrase  ")
    }

    func testLateSnapshotDoesNotReviveDeletedRecord() {
        let connection = SSHConnection(name: "删除", host: "example.com", username: "root")
        let baseline = VaultDocument(connections: [connection])
        let date = Date(timeIntervalSince1970: 10)
        let current = VaultDocument(deletions: [connection.id: date])
        let result = VaultDocumentReconciler.reconcile(incoming: baseline, baseline: baseline, current: current)
        XCTAssertTrue(result.connections.isEmpty)
        XCTAssertEqual(result.deletions[connection.id], date)
    }

    func testIndependentLocalAndRemoteAdditionsBothRemain() {
        let local = SSHConnection(name: "本地新增", host: "local.example", username: "root")
        let remote = SSHConnection(name: "远程新增", host: "remote.example", username: "root")
        let result = VaultDocumentReconciler.reconcile(incoming: VaultDocument(connections: [remote]), baseline: VaultDocument(), current: VaultDocument(connections: [local]))
        XCTAssertEqual(Set(result.connections.map(\.id)), Set([local.id, remote.id]))
    }

    func testUntouchedRecordUsesRemoteUpdate() {
        let original = SSHConnection(name: "旧", host: "example.com", username: "root")
        let baseline = VaultDocument(connections: [original])
        var incoming = baseline
        incoming.connections[0].name = "远程修改"
        let result = VaultDocumentReconciler.reconcile(incoming: incoming, baseline: baseline, current: baseline)
        XCTAssertEqual(result, incoming)
    }

    func testNewTombstoneWithoutVisibleRecordIsPreserved() {
        let id = UUID(), date = Date(timeIntervalSince1970: 20)
        let current = VaultDocument(deletions: [id: date])
        let result = VaultDocumentReconciler.reconcile(incoming: VaultDocument(), baseline: VaultDocument(), current: current)
        XCTAssertEqual(result.deletions[id], date)
    }
}
