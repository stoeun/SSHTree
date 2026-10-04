import Foundation
import XCTest
@testable import SSHTreeCore

final class ConnectionEditBaselineTests: XCTestCase {
    func testRemoteHostChangeRejectsTheOldEditorDraft() {
        let source = UUID(), connection = SSHConnection(name: "原名称", host: "old.example", username: "root")
        let original = VaultDocument(connections: [connection])
        let baseline = VaultConnectionEditBaseline(configurationID: source, connectionID: connection.id, document: original)
        var current = original
        current.connections[0].host = "new.example"
        XCTAssertFalse(baseline.matches(configurationID: source, document: current))
    }

    func testCredentialOnlyChangeRejectsTheOldEditorDraft() {
        let source = UUID(), credential = SSHCredential(password: " original \n")
        let connection = SSHConnection(host: "example.com", username: "root", authentication: .password, credentialID: credential.id)
        let original = VaultDocument(connections: [connection], credentials: [credential.id: credential])
        let baseline = VaultConnectionEditBaseline(configurationID: source, connectionID: connection.id, document: original)
        var current = original
        current.credentials[credential.id]?.password = " changed \n"
        XCTAssertFalse(baseline.matches(configurationID: source, document: current))
    }

    func testDeletedRecordCannotBeRevivedByItsOldDraft() {
        let source = UUID(), connection = SSHConnection(host: "example.com", username: "root")
        let baseline = VaultConnectionEditBaseline(configurationID: source, connectionID: connection.id, document: VaultDocument(connections: [connection]))
        XCTAssertFalse(baseline.matches(configurationID: source, document: VaultDocument(deletions: [connection.id: Date()])))
    }

    func testSourceSwitchRejectsAnEmptyNewDraftAndAnIdenticalExistingRecord() {
        let oldSource = UUID(), newSource = UUID(), connection = SSHConnection(host: "example.com", username: "root")
        let empty = VaultDocument()
        let newBaseline = VaultConnectionEditBaseline(configurationID: oldSource, connectionID: UUID(), document: empty)
        XCTAssertFalse(newBaseline.matches(configurationID: newSource, document: empty))
        let document = VaultDocument(connections: [connection])
        let existingBaseline = VaultConnectionEditBaseline(configurationID: oldSource, connectionID: connection.id, document: document)
        XCTAssertFalse(existingBaseline.matches(configurationID: newSource, document: document))
    }

    func testUnrelatedRemoteRecordDoesNotBlockSaving() {
        let source = UUID(), connection = SSHConnection(host: "example.com", username: "root")
        let original = VaultDocument(connections: [connection])
        let baseline = VaultConnectionEditBaseline(configurationID: source, connectionID: connection.id, document: original)
        var current = original
        current.connections.append(SSHConnection(host: "unrelated.example", username: "admin"))
        XCTAssertTrue(baseline.matches(configurationID: source, document: current))
    }
}
