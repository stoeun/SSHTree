import Foundation

/// Prevents an editor from replacing a record changed while its draft was open.
public struct VaultConnectionEditBaseline: Sendable {
    public let configurationID: UUID?
    public let connectionID: UUID
    public let connection: SSHConnection?
    public let credential: SSHCredential?

    public init(configurationID: UUID?, connectionID: UUID, document: VaultDocument) {
        self.configurationID = configurationID
        self.connectionID = connectionID
        self.connection = document.connections.first { $0.id == connectionID }
        self.credential = connection?.credentialID.flatMap { document.credentials[$0] }
    }

    public func matches(configurationID: UUID?, document: VaultDocument) -> Bool {
        guard let configurationID, configurationID == self.configurationID else { return false }
        let current = document.connections.first { $0.id == connectionID }
        let currentCredential = current?.credentialID.flatMap { document.credentials[$0] }
        return current == connection && currentCredential == credential
    }
}
