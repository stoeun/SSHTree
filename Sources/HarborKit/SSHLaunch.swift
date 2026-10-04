import Foundation

public struct SSHLaunch: Equatable, Sendable {
    public var executable: String
    public var arguments: [String]
    public var extraEnvironment: [String: String]
    public var secret: String?

    public init(executable: String, arguments: [String], extraEnvironment: [String: String], secret: String?) {
        self.executable = executable
        self.arguments = arguments
        self.extraEnvironment = extraEnvironment
        self.secret = secret
    }
}

public enum SSHLauncher {
    public static func plan(for connection: SSHConnection, askpassPath: String, secretPath: String) throws -> SSHLaunch {
        let connection = connection.normalizedForSave()
        if let problem = connection.validationProblem {
            throw HarborError.invalid(problem)
        }
        var arguments = [
            "-o", "GSSAPIAuthentication=no",
            "-o", "ConnectTimeout=15",
            "-o", "ServerAliveInterval=30",
            "-o", "ServerAliveCountMax=3",
            "-p", String(connection.port)
        ]
        if connection.acceptNewHostKeys {
            arguments.append(contentsOf: ["-o", "StrictHostKeyChecking=accept-new"])
        }
        var secret: String?
        switch connection.auth {
        case .agent:
            break
        case .password:
            arguments.append(contentsOf: [
                "-o", "PubkeyAuthentication=no",
                "-o", "PreferredAuthentications=keyboard-interactive,password",
                "-o", "NumberOfPasswordPrompts=1"
            ])
            secret = connection.password
        case .publicKey:
            let path = expandTilde(connection.identityFile ?? "")
            arguments.append(contentsOf: [
                "-o", "IdentitiesOnly=yes",
                "-o", "PreferredAuthentications=publickey",
                "-i", path
            ])
            secret = connection.keyPassphrase
        }
        if let jump = connection.proxyJump {
            arguments.append(contentsOf: ["-J", jump])
        }
        let target = "\(connection.username)@\(connection.host)"
        if let startup = connection.startupCommand {
            arguments.append(contentsOf: ["-t", target, "\(startup); exec \"${SHELL:-/bin/bash}\" -l"])
        } else {
            arguments.append(target)
        }
        var environment: [String: String] = [:]
        if secret != nil {
            environment = [
                "SSH_ASKPASS": askpassPath,
                "SSH_ASKPASS_REQUIRE": "force",
                "HARBOR_ASKPASS_FILE": secretPath
            ]
        }
        return SSHLaunch(
            executable: "/usr/bin/ssh",
            arguments: arguments,
            extraEnvironment: environment,
            secret: secret
        )
    }

    public static func expandTilde(_ path: String) -> String {
        if path == "~" {
            return FileManager.default.homeDirectoryForCurrentUser.path
        }
        if path.hasPrefix("~/") {
            return FileManager.default.homeDirectoryForCurrentUser.path + path.dropFirst(1)
        }
        return path
    }
}
