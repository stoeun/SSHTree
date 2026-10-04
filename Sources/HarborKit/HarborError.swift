import Foundation

public enum HarborError: Error, Equatable, Sendable {
    case invalid(String)
    case crypto(String)
    case storage(String)
    case notFound
    case oss(status: Int, code: String, message: String)
    case keychain(String)
}

extension HarborError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .invalid(let message), .crypto(let message), .storage(let message), .keychain(let message):
            return message
        case .notFound:
            return "云端还没有连接库。"
        case .oss(let status, let code, let message):
            if code.isEmpty {
                return "OSS 返回 \(status)。\(message)"
            }
            return "OSS \(code)（\(status)）。\(message)"
        }
    }
}
