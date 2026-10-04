import Foundation

/// Keeps edits made in the UI while a repository operation was awaiting I/O.
/// This does not create vault revisions; VaultRepository owns sync history.
public enum VaultDocumentReconciler {
    public static func reconcile(incoming: VaultDocument, baseline: VaultDocument, current: VaultDocument) -> VaultDocument {
        var result = incoming
        let before = Dictionary(uniqueKeysWithValues: baseline.connections.map { ($0.id, $0) })
        let now = Dictionary(uniqueKeysWithValues: current.connections.map { ($0.id, $0) })
        let recordIDs = Set(before.keys).union(now.keys).union(baseline.deletions.keys).union(current.deletions.keys)
        for id in recordIDs where before[id] != now[id] || baseline.deletions[id] != current.deletions[id] {
            result.connections.removeAll { $0.id == id }
            if let connection = now[id] { result.connections.append(connection) }
            result.deletions[id] = current.deletions[id]
        }
        for id in Set(baseline.credentials.keys).union(current.credentials.keys) where baseline.credentials[id] != current.credentials[id] {
            result.credentials[id] = current.credentials[id]
        }
        return result
    }
}
