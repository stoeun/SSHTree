import Foundation

public enum SSHAuth: String, Codable, CaseIterable, Sendable {
    case agent
    case password
    case publicKey

    public var title: String {
        switch self {
        case .agent: "系统代理"
        case .password: "密码"
        case .publicKey: "私钥"
        }
    }
}

public enum TagColor: String, Codable, CaseIterable, Sendable {
    case teal, blue, indigo, purple, pink, red, orange, green

    public var title: String {
        switch self {
        case .teal: "青绿"
        case .blue: "蓝"
        case .indigo: "靛"
        case .purple: "紫"
        case .pink: "粉"
        case .red: "红"
        case .orange: "橙"
        case .green: "绿"
        }
    }
}

public struct SSHConnection: Identifiable, Hashable, Sendable {
    public var id: UUID
    public var name: String
    public var group: String
    public var host: String
    public var port: Int
    public var username: String
    public var auth: SSHAuth
    public var identityFile: String?
    public var password: String?
    public var keyPassphrase: String?
    public var proxyJump: String?
    public var startupCommand: String?
    public var acceptNewHostKeys: Bool
    public var notes: String
    public var color: TagColor
    public var isFavorite: Bool
    public var createdAt: Date
    public var updatedAt: Date
    public var lastConnectedAt: Date?

    public init(
        id: UUID = UUID(),
        name: String,
        group: String = "",
        host: String,
        port: Int = 22,
        username: String,
        auth: SSHAuth = .agent,
        identityFile: String? = nil,
        password: String? = nil,
        keyPassphrase: String? = nil,
        proxyJump: String? = nil,
        startupCommand: String? = nil,
        acceptNewHostKeys: Bool = true,
        notes: String = "",
        color: TagColor = .teal,
        isFavorite: Bool = false,
        createdAt: Date = Date(),
        updatedAt: Date = Date(),
        lastConnectedAt: Date? = nil
    ) {
        self.id = id
        self.name = name
        self.group = group
        self.host = host
        self.port = port
        self.username = username
        self.auth = auth
        self.identityFile = identityFile
        self.password = password
        self.keyPassphrase = keyPassphrase
        self.proxyJump = proxyJump
        self.startupCommand = startupCommand
        self.acceptNewHostKeys = acceptNewHostKeys
        self.notes = notes
        self.color = color
        self.isFavorite = isFavorite
        self.createdAt = createdAt
        self.updatedAt = updatedAt
        self.lastConnectedAt = lastConnectedAt
    }

    public static func makeNew(username: String = NSUserName()) -> SSHConnection {
        SSHConnection(name: "", host: "", username: username)
    }

    public var endpointLabel: String {
        port == 22 ? "\(username)@\(host)" : "\(username)@\(host):\(port)"
    }

    public var validationProblem: String? {
        let host = host.trimmingCharacters(in: .whitespacesAndNewlines)
        let user = username.trimmingCharacters(in: .whitespacesAndNewlines)
        if host.isEmpty { return "请填写主机地址。" }
        if host.contains("@") { return "主机只填地址。用户名写在单独的一栏。" }
        if host.hasPrefix("-") || host.contains(where: { $0.isWhitespace }) {
            return "主机地址不能包含空格，也不能以 - 开头。"
        }
        if user.isEmpty { return "请填写用户名。" }
        if user.contains("@") || user.contains(where: { $0.isWhitespace }) || user.hasPrefix("-") {
            return "用户名不能包含空格或 @，也不能以 - 开头。"
        }
        if !(1...65535).contains(port) { return "端口需要在 1 到 65535 之间。" }
        if auth == .password && (password ?? "").trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            return "请填写密码，或改用私钥、系统代理。"
        }
        if auth == .publicKey && (identityFile ?? "").trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            return "请选择私钥文件。"
        }
        if let jump = blankToNil(proxyJump) {
            if jump.hasPrefix("-") || jump.contains(where: { $0.isWhitespace }) {
                return "跳板机写成 user@bastion 或 user@bastion:22。"
            }
        }
        return nil
    }

    public func normalizedForSave(now: Date = Date()) -> SSHConnection {
        var copy = self
        copy.name = name.trimmingCharacters(in: .whitespacesAndNewlines)
        copy.host = host.trimmingCharacters(in: .whitespacesAndNewlines)
        copy.username = username.trimmingCharacters(in: .whitespacesAndNewlines)
        copy.group = group.trimmingCharacters(in: .whitespacesAndNewlines)
        copy.notes = notes.trimmingCharacters(in: .whitespacesAndNewlines)
        if copy.name.isEmpty { copy.name = copy.host }
        copy.proxyJump = blankToNil(proxyJump)
        copy.startupCommand = blankToNil(startupCommand)
        copy.identityFile = blankToNil(identityFile)
        copy.password = blankToNil(password)
        copy.keyPassphrase = blankToNil(keyPassphrase)
        switch copy.auth {
        case .agent:
            copy.password = nil
            copy.keyPassphrase = nil
            copy.identityFile = nil
        case .password:
            copy.identityFile = nil
            copy.keyPassphrase = nil
        case .publicKey:
            copy.password = nil
        }
        copy.updatedAt = now
        return copy
    }

    public func matches(query: String) -> Bool {
        let fields = [name, host, username, group, notes, String(port), endpointLabel]
        return fields.contains { $0.localizedStandardContains(query) }
    }

    private func blankToNil(_ value: String?) -> String? {
        guard let value else { return nil }
        let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed.isEmpty ? nil : trimmed
    }
}

extension SSHConnection: Codable {
    enum CodingKeys: String, CodingKey {
        case id, name, group, host, port, username, auth
        case identityFile, password, keyPassphrase, proxyJump, startupCommand
        case acceptNewHostKeys, notes, color, isFavorite
        case createdAt, updatedAt, lastConnectedAt
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        id = try container.decode(UUID.self, forKey: .id)
        name = try container.decodeIfPresent(String.self, forKey: .name) ?? ""
        group = try container.decodeIfPresent(String.self, forKey: .group) ?? ""
        host = try container.decode(String.self, forKey: .host)
        port = try container.decodeIfPresent(Int.self, forKey: .port) ?? 22
        username = try container.decode(String.self, forKey: .username)
        auth = try container.decodeIfPresent(SSHAuth.self, forKey: .auth) ?? .agent
        identityFile = try container.decodeIfPresent(String.self, forKey: .identityFile)
        password = try container.decodeIfPresent(String.self, forKey: .password)
        keyPassphrase = try container.decodeIfPresent(String.self, forKey: .keyPassphrase)
        proxyJump = try container.decodeIfPresent(String.self, forKey: .proxyJump)
        startupCommand = try container.decodeIfPresent(String.self, forKey: .startupCommand)
        acceptNewHostKeys = try container.decodeIfPresent(Bool.self, forKey: .acceptNewHostKeys) ?? true
        notes = try container.decodeIfPresent(String.self, forKey: .notes) ?? ""
        color = try container.decodeIfPresent(TagColor.self, forKey: .color) ?? .teal
        isFavorite = try container.decodeIfPresent(Bool.self, forKey: .isFavorite) ?? false
        createdAt = try container.decodeIfPresent(Date.self, forKey: .createdAt) ?? Date()
        updatedAt = try container.decodeIfPresent(Date.self, forKey: .updatedAt) ?? createdAt
        lastConnectedAt = try container.decodeIfPresent(Date.self, forKey: .lastConnectedAt)
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(id, forKey: .id)
        try container.encode(name, forKey: .name)
        try container.encode(group, forKey: .group)
        try container.encode(host, forKey: .host)
        try container.encode(port, forKey: .port)
        try container.encode(username, forKey: .username)
        try container.encode(auth, forKey: .auth)
        try container.encodeIfPresent(identityFile, forKey: .identityFile)
        try container.encodeIfPresent(password, forKey: .password)
        try container.encodeIfPresent(keyPassphrase, forKey: .keyPassphrase)
        try container.encodeIfPresent(proxyJump, forKey: .proxyJump)
        try container.encodeIfPresent(startupCommand, forKey: .startupCommand)
        try container.encode(acceptNewHostKeys, forKey: .acceptNewHostKeys)
        try container.encode(notes, forKey: .notes)
        try container.encode(color, forKey: .color)
        try container.encode(isFavorite, forKey: .isFavorite)
        try container.encode(createdAt, forKey: .createdAt)
        try container.encode(updatedAt, forKey: .updatedAt)
        try container.encodeIfPresent(lastConnectedAt, forKey: .lastConnectedAt)
    }
}

public struct VaultDocument: Codable, Equatable, Sendable {
    public var schema: Int
    public var revision: UUID
    public var updatedAt: Date
    public var connections: [SSHConnection]

    public init(schema: Int = 1, revision: UUID = UUID(), updatedAt: Date = Date(), connections: [SSHConnection] = []) {
        self.schema = schema
        self.revision = revision
        self.updatedAt = updatedAt
        self.connections = connections
    }

    public static let empty = VaultDocument()
}

public struct OSSConfig: Codable, Equatable, Sendable {
    public var region: String
    public var endpointOverride: String
    public var bucket: String
    public var objectKey: String
    public var accessKeyID: String
    public var autoSync: Bool

    public init(
        region: String = "cn-hangzhou",
        endpointOverride: String = "",
        bucket: String = "",
        objectKey: String = "harbor/connections.vault",
        accessKeyID: String = "",
        autoSync: Bool = true
    ) {
        self.region = region
        self.endpointOverride = endpointOverride
        self.bucket = bucket
        self.objectKey = objectKey
        self.accessKeyID = accessKeyID
        self.autoSync = autoSync
    }
}

public struct SyncState: Codable, Equatable, Sendable {
    public var lastSyncedRevision: UUID?
    public var lastSyncAt: Date?

    public init(lastSyncedRevision: UUID? = nil, lastSyncAt: Date? = nil) {
        self.lastSyncedRevision = lastSyncedRevision
        self.lastSyncAt = lastSyncAt
    }
}

public struct OSSRegion: Identifiable, Hashable, Sendable {
    public var code: String
    public var name: String
    public var id: String { code }

    public init(code: String, name: String) {
        self.code = code
        self.name = name
    }

    public static let common: [OSSRegion] = [
        OSSRegion(code: "cn-hangzhou", name: "杭州"),
        OSSRegion(code: "cn-shanghai", name: "上海"),
        OSSRegion(code: "cn-nanjing", name: "南京"),
        OSSRegion(code: "cn-qingdao", name: "青岛"),
        OSSRegion(code: "cn-beijing", name: "北京"),
        OSSRegion(code: "cn-zhangjiakou", name: "张家口"),
        OSSRegion(code: "cn-huhehaote", name: "呼和浩特"),
        OSSRegion(code: "cn-wulanchabu", name: "乌兰察布"),
        OSSRegion(code: "cn-shenzhen", name: "深圳"),
        OSSRegion(code: "cn-heyuan", name: "河源"),
        OSSRegion(code: "cn-guangzhou", name: "广州"),
        OSSRegion(code: "cn-chengdu", name: "成都"),
        OSSRegion(code: "cn-hongkong", name: "香港"),
        OSSRegion(code: "ap-southeast-1", name: "新加坡"),
        OSSRegion(code: "ap-northeast-1", name: "东京"),
        OSSRegion(code: "ap-northeast-2", name: "首尔"),
        OSSRegion(code: "us-west-1", name: "硅谷"),
        OSSRegion(code: "us-east-1", name: "弗吉尼亚"),
        OSSRegion(code: "eu-central-1", name: "法兰克福"),
        OSSRegion(code: "eu-west-1", name: "伦敦"),
        OSSRegion(code: "me-east-1", name: "迪拜")
    ]
}

public enum HarborJSON {
    public static func encoder() -> JSONEncoder {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        encoder.dateEncodingStrategy = .iso8601
        return encoder
    }

    public static func decoder() -> JSONDecoder {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        return decoder
    }
}
