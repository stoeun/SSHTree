import Foundation
import Darwin

public enum SSHError: Error, LocalizedError, Sendable {
    case invalid(String), system(String, Int32), protocolFailure
    public var errorDescription: String? {
        switch self {
        case .invalid(let message): message
        case .system(let operation, let code): "\(operation)：\(String(cString: strerror(code)))"
        case .protocolFailure: "认证请求已取消或通信失败。"
        }
    }
}

public enum SSHAuthenticationPromptKind: String, Codable, Sendable {
    case hostConfirmation, password, passphrase, other
}

public enum SSHAuthenticationPrompt {
    public static func classify(_ prompt: String) -> SSHAuthenticationPromptKind {
        let hasFingerprint = prompt.contains("key fingerprint is SHA256:") || prompt.contains("key fingerprint is: SHA256:")
        if prompt.hasPrefix("The authenticity of host '") && hasFingerprint && prompt.hasSuffix("(yes/no/[fingerprint])? ") {
            return .hostConfirmation
        }
        if !prompt.contains("\n"), prompt.hasSuffix("'s password: "), prompt.contains("@") { return .password }
        if !prompt.contains("\n"), prompt.hasPrefix("Enter passphrase for key '"), prompt.hasSuffix("': ") { return .passphrase }
        return .other
    }

    /// Only exact, client-generated prompts receive a saved credential. Server
    /// keyboard-interactive text and prompts for other hosts/keys remain manual.
    public static func savedResponse(prompt: String, connection: SSHConnection, credential: SSHCredential?, privateKeyPath: String?) -> String? {
        guard let credential else { return nil }
        switch connection.authentication {
        case .password:
            guard prompt == "\(connection.username)@\(connection.host)'s password: " else { return nil }
            return credential.password
        case .privateKey:
            guard let privateKeyPath, prompt == "Enter passphrase for key '\(privateKeyPath)': " else { return nil }
            return credential.passphrase
        case .system:
            return nil
        }
    }
}

public struct SSHLaunchPlan: Sendable {
    public let executable: String
    public let arguments: [String]
    public let environment: [String: String]
    public let probeArguments: [String]

    public static func make(connection: SSHConnection, helperURL: URL, runtime: SSHRuntimeDirectory) throws -> Self {
        let hostCharacters = CharacterSet(charactersIn: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-:%[]")
        guard !connection.host.isEmpty, !connection.host.hasPrefix("-"), connection.host.unicodeScalars.allSatisfy({ hostCharacters.contains($0) }) else {
            throw SSHError.invalid("主机地址应为域名、SSH 配置别名或 IP 地址。")
        }
        guard !connection.username.isEmpty, !connection.username.hasPrefix("-"), !connection.username.contains("@"), !connection.username.contains("\0"), !connection.username.contains(where: { $0.isWhitespace }) else {
            throw SSHError.invalid("请填写有效的 SSH 用户名。")
        }
        guard (1...65535).contains(connection.port) else { throw SSHError.invalid("端口必须在 1 到 65535 之间。") }
        var arguments = ["-tt", "-p", String(connection.port), "-l", connection.username]
        for option in ["StrictHostKeyChecking=ask", "BatchMode=no", "ConnectTimeout=15", "ServerAliveInterval=30", "ServerAliveCountMax=3", "ControlMaster=yes", "ControlPersist=no", "ControlPath=\(runtime.controlSocketURL.path)", "PermitLocalCommand=no", "RemoteCommand=none", "SessionType=default"] {
            arguments += ["-o", option]
        }
        switch connection.authentication {
        case .system: break
        case .password:
            arguments += ["-o", "PubkeyAuthentication=no", "-o", "PreferredAuthentications=password,keyboard-interactive", "-o", "NumberOfPasswordPrompts=3"]
        case .privateKey:
            guard let keyURL = runtime.privateKeyURL else { throw SSHError.invalid("这条连接没有导入的私钥。") }
            arguments += ["-o", "IdentitiesOnly=yes", "-o", "PreferredAuthentications=publickey", "-i", keyURL.path]
        }
        arguments += ["--", connection.host]
        var environment: [String: String] = [:]
        let parent = ProcessInfo.processInfo.environment
        for name in ["PATH", "HOME", "USER", "LOGNAME", "LANG", "LC_ALL", "LC_CTYPE", "TMPDIR", "SSH_AUTH_SOCK"] {
            if let value = parent[name] { environment[name] = value }
        }
        environment["PATH"] = environment["PATH"] ?? "/usr/bin:/bin:/usr/sbin:/sbin"
        environment["TERM"] = "xterm-256color"
        environment["COLORTERM"] = "truecolor"
        environment["SSH_ASKPASS"] = helperURL.path
        environment["SSH_ASKPASS_REQUIRE"] = "force"
        environment["SSHTREE_ASKPASS_SOCKET"] = runtime.askpassSocketURL.path
        environment["SSHTREE_ASKPASS_OWNER_PID"] = String(getpid())
        return Self(executable: "/usr/bin/ssh", arguments: arguments, environment: environment,
                    probeArguments: ["-F", "none", "-S", runtime.controlSocketURL.path, "-o", "ControlMaster=no", "-o", "ConnectTimeout=1", "-O", "check", "localhost"])
    }
}
