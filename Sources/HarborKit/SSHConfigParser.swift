import Foundation

public struct SSHConfigHost: Equatable, Sendable {
    public var alias: String
    public var hostName: String
    public var user: String?
    public var port: Int?
    public var identityFile: String?
    public var proxyJump: String?

    public init(alias: String, hostName: String, user: String? = nil, port: Int? = nil, identityFile: String? = nil, proxyJump: String? = nil) {
        self.alias = alias
        self.hostName = hostName
        self.user = user
        self.port = port
        self.identityFile = identityFile
        self.proxyJump = proxyJump
    }
}

public enum SSHConfigParser {
    public static func parse(_ text: String) -> [SSHConfigHost] {
        var hosts: [SSHConfigHost] = []
        var current: [Int] = []
        var skipping = false
        for rawLine in logicalLines(text) {
            let line = stripComment(rawLine).trimmingCharacters(in: .whitespacesAndNewlines)
            if line.isEmpty { continue }
            let tokens = tokenize(line)
            guard let keyword = tokens.first?.lowercased() else { continue }
            if keyword == "host" {
                current = []
                skipping = false
                for alias in tokens.dropFirst() where !alias.contains("*") && !alias.contains("?") {
                    hosts.append(SSHConfigHost(alias: alias, hostName: alias))
                    current.append(hosts.count - 1)
                }
                if current.isEmpty { skipping = true }
                continue
            }
            if keyword == "match" {
                skipping = true
                current = []
                continue
            }
            guard !skipping, !current.isEmpty else { continue }
            let value = tokens.dropFirst().joined(separator: " ")
            guard !value.isEmpty else { continue }
            for index in current {
                switch keyword {
                case "hostname":
                    hosts[index].hostName = value
                case "user":
                    hosts[index].user = value
                case "port":
                    hosts[index].port = Int(value)
                case "identityfile":
                    if hosts[index].identityFile == nil {
                        hosts[index].identityFile = value
                    }
                case "proxyjump":
                    hosts[index].proxyJump = value
                default:
                    break
                }
            }
        }
        return hosts.filter { !$0.hostName.contains("*") && !$0.hostName.contains("?") && !$0.hostName.isEmpty }
    }

    public static func connections(from hosts: [SSHConfigHost], defaultUser: String, existing: [SSHConnection]) -> [SSHConnection] {
        var imported: [SSHConnection] = []
        for (index, host) in hosts.enumerated() {
            let user = host.user ?? defaultUser
            let port = host.port ?? 22
            let duplicate = existing.contains { $0.host == host.hostName && $0.port == port && $0.username == user }
                || imported.contains { $0.host == host.hostName && $0.port == port && $0.username == user }
            if duplicate { continue }
            var connection = SSHConnection(
                name: host.alias,
                group: "SSH 配置",
                host: host.hostName,
                port: port,
                username: user,
                color: TagColor.allCases[index % TagColor.allCases.count]
            )
            if let identity = host.identityFile, !identity.isEmpty {
                connection.auth = .publicKey
                connection.identityFile = SSHLauncher.expandTilde(identity)
            }
            connection.proxyJump = host.proxyJump
            imported.append(connection.normalizedForSave())
        }
        return imported
    }

    static func logicalLines(_ text: String) -> [String] {
        var lines: [String] = []
        var pending = ""
        let parts = text.split(omittingEmptySubsequences: false, whereSeparator: \.isNewline)
        for part in parts {
            var line = String(part)
            if line.hasSuffix("\r") { line.removeLast() }
            let continues = line.hasSuffix("\\")
            if continues { line.removeLast() }
            pending += line
            if continues {
                pending += " "
            } else {
                lines.append(pending)
                pending = ""
            }
        }
        if !pending.isEmpty { lines.append(pending) }
        return lines
    }

    static func stripComment(_ line: String) -> String {
        var quote: Character?
        var result = ""
        for character in line {
            if let active = quote {
                if character == active { quote = nil }
                result.append(character)
                continue
            }
            if character == "#" { break }
            if character == "\"" || character == "'" { quote = character }
            result.append(character)
        }
        return result
    }

    static func tokenize(_ line: String) -> [String] {
        var tokens: [String] = []
        var current = ""
        var quote: Character?
        for character in line {
            if let active = quote {
                if character == active {
                    quote = nil
                } else {
                    current.append(character)
                }
                continue
            }
            if character == "\"" || character == "'" {
                quote = character
                continue
            }
            if character.isWhitespace {
                if !current.isEmpty {
                    tokens.append(current)
                    current = ""
                }
                continue
            }
            current.append(character)
        }
        if !current.isEmpty { tokens.append(current) }
        return tokens
    }
}
