import XCTest
import Darwin
@testable import SSHTreeCore

/// Opt-in tests against an isolated loopback sshd, never the user's SSH files.
/// Set SSHTREE_ASKPASS_HELPER to the just-built helper to opt in. Every test
/// generates its own keys, loopback listener and known_hosts, and defers cleanup.
final class SSHIntegrationTests: XCTestCase, @unchecked Sendable {
    func testRealPasswordAuthenticationPreservesWhitespace() async throws {
        let fixture = try configuration(passwordServer: true); defer { fixture.cleanup() }
        let runtime = try SSHRuntimeDirectory(); defer { runtime.cleanup() }
        let connection = SSHConnection(host: "127.0.0.1", port: fixture.port, username: "fixture-user", authentication: .password)
        let credential = SSHCredential(password: "  fixture password \t ")
        let plan = try SSHLaunchPlan.make(connection: connection, helperURL: fixture.helper, runtime: runtime)
        let requested = expectation(description: "client password prompt")
        let output = SSHFixtureState()
        let finished = expectation(description: "password session ended")
        let server = try SSHAskPassServer(socketURL: runtime.askpassSocketURL) { query, respond in
            if SSHAuthenticationPrompt.classify(query.prompt) == .hostConfirmation { respond("yes"); return }
            let value = SSHAuthenticationPrompt.savedResponse(prompt: query.prompt, connection: connection, credential: credential, privateKeyPath: nil)
            XCTAssertEqual(value, credential.password); requested.fulfill(); respond(value)
        }
        defer { server.stop() }
        let process = try SSHPTYProcess(executable: plan.executable, arguments: isolated(plan.arguments, runtime: runtime),
            environment: plan.environment.map { "\($0.key)=\($0.value)" }, columns: 80, rows: 24,
            onOutput: { output.append($0) }, onExit: { output.finish($0); finished.fulfill() })
        defer { process.close() }
        server.start(ancestorPID: process.pid, helperExecutablePath: fixture.helper.path)
        await fulfillment(of: [requested], timeout: 5)
        let authenticated = await waitForAuthentication(plan.probeArguments, state: output)
        XCTAssertTrue(authenticated, output.text)
        process.send(Data("exit\n".utf8))
        await fulfillment(of: [finished], timeout: 5)
        XCTAssertEqual(output.exit?.exitCode, 0)
        XCTAssertTrue(output.text.contains("PARAMIKO_PASSWORD_AUTH:24 80"))
    }

    func testSystemAuthenticationUsesAnIsolatedSSHConfiguration() async throws {
        let fixture = try configuration(); defer { fixture.cleanup() }
        let runtime = try SSHRuntimeDirectory(); defer { runtime.cleanup() }
        let configURL = runtime.directoryURL.appendingPathComponent("config")
        let configuration = """
        Host sshtree-fixture-alias
          HostName 127.0.0.1
          IdentityFile \(fixture.root.path)/client
          IdentitiesOnly yes
          UserKnownHostsFile \(runtime.directoryURL.path)/known_hosts
          GlobalKnownHostsFile /dev/null

        """
        try configuration.write(to: configURL, atomically: true, encoding: .utf8)
        let plan = try SSHLaunchPlan.make(connection: SSHConnection(host: "sshtree-fixture-alias", port: fixture.port, username: NSUserName(), authentication: .system), helperURL: fixture.helper, runtime: runtime)
        let output = SSHFixtureState()
        let finished = expectation(description: "system configuration session ended")
        let server = try SSHAskPassServer(socketURL: runtime.askpassSocketURL) { query, respond in
            switch SSHAuthenticationPrompt.classify(query.prompt) {
            case .hostConfirmation: respond("yes")
            case .passphrase: respond(" fixture phrase ")
            default: XCTFail("Unexpected system authentication prompt"); respond(nil)
            }
        }
        defer { server.stop() }
        let process = try SSHPTYProcess(executable: plan.executable, arguments: ["-F", configURL.path] + plan.arguments,
            environment: plan.environment.map { "\($0.key)=\($0.value)" }, columns: 80, rows: 24,
            onOutput: { output.append($0) }, onExit: { output.finish($0); finished.fulfill() })
        defer { process.close() }
        server.start(ancestorPID: process.pid, helperExecutablePath: fixture.helper.path)
        let authenticated = await waitForAuthentication(plan.probeArguments, state: output)
        XCTAssertTrue(authenticated, output.text)
        process.send(Data("printf 'SYSTEM_CONFIGURATION_AUTH\\n'; exit 0\n".utf8))
        await fulfillment(of: [finished], timeout: 5)
        XCTAssertEqual(output.exit?.exitCode, 0)
        XCTAssertTrue(output.text.contains("SYSTEM_CONFIGURATION_AUTH"))
        XCTAssertNil(runtime.privateKeyURL)
    }

    func testHostConfirmationCancellationNeverAuthenticates() async throws {
        let fixture = try configuration(); defer { fixture.cleanup() }
        let runtime = try SSHRuntimeDirectory(); defer { runtime.cleanup() }
        _ = try runtime.materializePrivateKey(Data(contentsOf: fixture.root.appendingPathComponent("client")))
        let plan = try SSHLaunchPlan.make(connection: SSHConnection(host: "127.0.0.1", port: fixture.port, username: NSUserName(), authentication: .privateKey), helperURL: fixture.helper, runtime: runtime)
        let requested = expectation(description: "host confirmation cancelled")
        let finished = expectation(description: "cancelled SSH reaped")
        let output = SSHFixtureState()
        let server = try SSHAskPassServer(socketURL: runtime.askpassSocketURL) { query, respond in
            XCTAssertEqual(SSHAuthenticationPrompt.classify(query.prompt), .hostConfirmation)
            requested.fulfill(); respond(nil)
        }
        defer { server.stop() }
        let process = try SSHPTYProcess(executable: plan.executable, arguments: isolated(plan.arguments, runtime: runtime),
            environment: plan.environment.map { "\($0.key)=\($0.value)" }, columns: 80, rows: 24,
            onOutput: { output.append($0) }, onExit: { output.finish($0); finished.fulfill() })
        defer { process.close() }
        server.start(ancestorPID: process.pid, helperExecutablePath: fixture.helper.path)
        await fulfillment(of: [requested, finished], timeout: 5)
        XCTAssertEqual(output.exit?.exitCode, 255)
        XCTAssertFalse(SSHControlMasterProbe.check(arguments: plan.probeArguments))
    }

    func testAuthenticatedSessionStillReportsRemoteShellFailure() async throws {
        let fixture = try configuration(); defer { fixture.cleanup() }
        let runtime = try SSHRuntimeDirectory(); defer { runtime.cleanup() }
        _ = try runtime.materializePrivateKey(Data(contentsOf: fixture.root.appendingPathComponent("client")))
        let plan = try SSHLaunchPlan.make(connection: SSHConnection(host: "127.0.0.1", port: fixture.port, username: NSUserName(), authentication: .privateKey), helperURL: fixture.helper, runtime: runtime)
        let output = SSHFixtureState()
        let finished = expectation(description: "remote shell failure reaped")
        let server = try SSHAskPassServer(socketURL: runtime.askpassSocketURL) { query, respond in
            switch SSHAuthenticationPrompt.classify(query.prompt) {
            case .hostConfirmation: respond("yes")
            case .passphrase: respond(" fixture phrase ")
            default: XCTFail("Unexpected authentication request"); respond(nil)
            }
        }
        defer { server.stop() }
        let process = try SSHPTYProcess(executable: plan.executable, arguments: isolated(plan.arguments, runtime: runtime),
            environment: plan.environment.map { "\($0.key)=\($0.value)" }, columns: 80, rows: 24,
            onOutput: { output.append($0) }, onExit: { output.finish($0); finished.fulfill() })
        defer { process.close() }
        server.start(ancestorPID: process.pid, helperExecutablePath: fixture.helper.path)
        let authenticated = await waitForAuthentication(plan.probeArguments, state: output)
        XCTAssertTrue(authenticated, output.text)
        guard authenticated else { process.close(); await fulfillment(of: [finished], timeout: 5); return }
        process.send(Data("exec /sshtree-fixture-missing-shell\n".utf8))
        await fulfillment(of: [finished], timeout: 5)
        XCTAssertEqual(output.exit?.exitCode, 127)
        XCTAssertTrue(output.text.contains("sshtree-fixture-missing-shell"))
        XCTAssertFalse(SSHControlMasterProbe.check(arguments: plan.probeArguments))
    }

    func testRealHostConfirmationPrivateKeyAuthenticationPTYAndRemoteExit() async throws {
        let fixture = try configuration(); defer { fixture.cleanup() }
        let runtime = try SSHRuntimeDirectory(); defer { runtime.cleanup() }
        let key = try runtime.materializePrivateKey(Data(contentsOf: fixture.root.appendingPathComponent("client")))
        let connection = SSHConnection(host: "127.0.0.1", port: fixture.port, username: NSUserName(), authentication: .privateKey)
        let plan = try SSHLaunchPlan.make(connection: connection, helperURL: fixture.helper, runtime: runtime)
        let hostConfirmed = expectation(description: "real raw host fingerprint")
        let output = SSHFixtureState()
        let finished = expectation(description: "remote exit reaped")
        let server = try SSHAskPassServer(socketURL: runtime.askpassSocketURL) { query, respond in
            switch SSHAuthenticationPrompt.classify(query.prompt) {
            case .hostConfirmation:
                XCTAssertTrue(query.prompt.contains("SHA256:"))
                XCTAssertTrue(query.prompt.contains("127.0.0.1"))
                hostConfirmed.fulfill(); respond("yes")
            case .passphrase:
                XCTAssertEqual(query.prompt, "Enter passphrase for key '\(key.path)': ")
                respond(" fixture phrase ")
            default: XCTFail("Unexpected fixture authentication prompt: \(query.prompt.debugDescription)"); respond(nil)
            }
        }
        defer { server.stop() }
        let process = try SSHPTYProcess(executable: plan.executable, arguments: isolated(plan.arguments, runtime: runtime),
            environment: plan.environment.map { "\($0.key)=\($0.value)" }, columns: 80, rows: 24,
            onOutput: { output.append($0) }, onExit: { output.finish($0); finished.fulfill() })
        defer { process.close() }
        server.start(ancestorPID: process.pid, helperExecutablePath: fixture.helper.path)
        await fulfillment(of: [hostConfirmed], timeout: 5)
        let authenticated = await waitForAuthentication(plan.probeArguments, state: output)
        XCTAssertTrue(authenticated, "Mux must acknowledge actual authentication. Terminal: \(output.text)")
        guard authenticated else { process.close(); await fulfillment(of: [finished], timeout: 5); return }
        runtime.removePrivateKey()
        XCTAssertFalse(FileManager.default.fileExists(atPath: key.path))
        process.send(Data("printf 'SSHTREE_REMOTE_TTY\\n'; stty size; exit 7\n".utf8))
        await fulfillment(of: [finished], timeout: 5)
        XCTAssertEqual(output.exit?.exitCode, 7)
        XCTAssertTrue(output.text.contains("SSHTREE_REMOTE_TTY"))
        XCTAssertTrue(output.text.contains("24 80"))
        XCTAssertFalse(SSHControlMasterProbe.check(arguments: plan.probeArguments))
        var status: Int32 = 0
        XCTAssertEqual(waitpid(process.pid, &status, WNOHANG), -1)
        XCTAssertEqual(errno, ECHILD)
    }

    func testChangedHostKeyFailsWithoutPromptOrAuthenticatedState() async throws {
        let fixture = try configuration(); defer { fixture.cleanup() }
        let runtime = try SSHRuntimeDirectory(); defer { runtime.cleanup() }
        _ = try runtime.materializePrivateKey(Data(contentsOf: fixture.root.appendingPathComponent("client")))
        let wrongPublicKey = try String(contentsOf: fixture.root.appendingPathComponent("client.pub"), encoding: .utf8)
        try "[127.0.0.1]:\(fixture.port) \(wrongPublicKey)".write(to: runtime.directoryURL.appendingPathComponent("known_hosts"), atomically: true, encoding: .utf8)
        let plan = try SSHLaunchPlan.make(connection: SSHConnection(host: "127.0.0.1", port: fixture.port, username: NSUserName(), authentication: .privateKey), helperURL: fixture.helper, runtime: runtime)
        let output = SSHFixtureState()
        let finished = expectation(description: "changed key rejected")
        let server = try SSHAskPassServer(socketURL: runtime.askpassSocketURL) { _, respond in XCTFail("Changed keys must not offer acceptance"); respond(nil) }
        defer { server.stop() }
        let process = try SSHPTYProcess(executable: plan.executable, arguments: isolated(plan.arguments, runtime: runtime),
            environment: plan.environment.map { "\($0.key)=\($0.value)" }, columns: 80, rows: 24,
            onOutput: { output.append($0) }, onExit: { output.finish($0); finished.fulfill() })
        defer { process.close() }
        server.start(ancestorPID: process.pid, helperExecutablePath: fixture.helper.path)
        let authenticated = await waitForAuthentication(plan.probeArguments, state: output)
        XCTAssertFalse(authenticated)
        await fulfillment(of: [finished], timeout: 5)
        XCTAssertEqual(output.exit?.exitCode, 255)
        XCTAssertTrue(output.text.contains("REMOTE HOST IDENTIFICATION HAS CHANGED"))
    }

    private func configuration(passwordServer: Bool = false) throws -> SSHLoopbackFixture {
        let env = ProcessInfo.processInfo.environment
        guard let helper = env["SSHTREE_ASKPASS_HELPER"] else { throw XCTSkip("Set SSHTREE_ASKPASS_HELPER to opt into an isolated loopback sshd fixture.") }
        return try SSHLoopbackFixture(helper: URL(fileURLWithPath: helper), passwordServer: passwordServer)
    }

    private func isolated(_ arguments: [String], runtime: SSHRuntimeDirectory) -> [String] {
        ["-F", "none", "-o", "UserKnownHostsFile=\(runtime.directoryURL.appendingPathComponent("known_hosts").path)", "-o", "GlobalKnownHostsFile=/dev/null"] + arguments
    }

    private func waitForAuthentication(_ arguments: [String], state: SSHFixtureState) async -> Bool {
        for _ in 0..<50 {
            if await Task.detached(operation: { SSHControlMasterProbe.check(arguments: arguments) }).value { return true }
            if state.exit != nil { return false }
            try? await Task.sleep(for: .milliseconds(100))
        }
        return false
    }
}

private final class SSHLoopbackFixture {
    let root: URL
    let port: Int
    let helper: URL
    private let daemon = Process()
    private let daemonExited = DispatchSemaphore(value: 0)
    private var log: FileHandle?
    private var removed = false

    init(helper: URL, passwordServer: Bool) throws {
        guard FileManager.default.isExecutableFile(atPath: helper.path) else { throw SSHError.invalid("Fixture helper is missing.") }
        self.helper = helper
        root = URL(fileURLWithPath: "/tmp").appendingPathComponent("sshtree-fixture-\(UUID().uuidString)")
        port = try Self.unusedLoopbackPort()
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        do {
            if passwordServer {
                try startPasswordServer()
                try awaitListening()
                return
            }
            try Self.run("/usr/bin/ssh-keygen", ["-q", "-t", "ed25519", "-N", "", "-f", root.appendingPathComponent("host").path])
            // This is a public test fixture phrase, never a user's credential.
            try Self.run("/usr/bin/ssh-keygen", ["-q", "-t", "ed25519", "-N", " fixture phrase ", "-f", root.appendingPathComponent("client").path])
            try Data(contentsOf: root.appendingPathComponent("client.pub")).write(to: root.appendingPathComponent("authorized_keys"))
            let configuration = """
            Port \(port)
            ListenAddress 127.0.0.1
            HostKey \(root.path)/host
            PidFile \(root.path)/sshd.pid
            AuthorizedKeysFile \(root.path)/authorized_keys
            StrictModes no
            PasswordAuthentication no
            KbdInteractiveAuthentication no
            PubkeyAuthentication yes
            UsePAM no
            AllowUsers \(NSUserName())
            LogLevel ERROR

            """
            let configURL = root.appendingPathComponent("sshd_config")
            try configuration.write(to: configURL, atomically: true, encoding: .utf8)
            try Self.run("/usr/sbin/sshd", ["-t", "-f", configURL.path])
            let logURL = root.appendingPathComponent("sshd.log")
            _ = FileManager.default.createFile(atPath: logURL.path, contents: nil, attributes: [.posixPermissions: 0o600])
            log = try FileHandle(forWritingTo: logURL)
            daemon.executableURL = URL(fileURLWithPath: "/usr/sbin/sshd")
            daemon.arguments = ["-D", "-e", "-f", configURL.path]
            daemon.standardInput = FileHandle.nullDevice; daemon.standardOutput = log; daemon.standardError = log
            try launchDaemon()
            try awaitListening()
        } catch { cleanup(); throw error }
    }

    func cleanup() {
        guard !removed else { return }; removed = true
        if daemon.isRunning {
            daemon.terminate()
            if daemonExited.wait(timeout: .now() + 0.3) == .timedOut {
                _ = kill(daemon.processIdentifier, SIGKILL)
                _ = daemonExited.wait(timeout: .now() + 2)
            }
        }
        try? log?.close(); log = nil
        try? FileManager.default.removeItem(at: root)
    }
    deinit { cleanup() }

    private func launchDaemon() throws {
        let completion = daemonExited
        daemon.terminationHandler = { _ in completion.signal() }
        try daemon.run()
    }

    private func awaitListening() throws {
        for _ in 0..<100 {
            if Self.canConnect(port: port) { return }
            if !daemon.isRunning { break }
            usleep(20_000)
        }
        throw SSHError.invalid("Isolated SSH fixture failed to listen: \((try? String(contentsOf: root.appendingPathComponent("sshd.log"), encoding: .utf8)) ?? "unknown error")")
    }

    private func startPasswordServer() throws {
        let python = ProcessInfo.processInfo.environment["SSHTREE_FIXTURE_PYTHON"] ?? "/usr/bin/python3"
        // Uses an existing Paramiko installation. This opt-in fixture accepts
        // only its public test phrase and does not inspect macOS passwords.
        let script = """
        import socket, threading, paramiko, sys
        class Server(paramiko.ServerInterface):
            def __init__(self):
                self.shell = threading.Event()
                self.size = (0, 0)
            def get_allowed_auths(self, username): return 'password'
            def check_auth_password(self, username, password):
                return paramiko.AUTH_SUCCESSFUL if username == 'fixture-user' and password == '  fixture password \\t ' else paramiko.AUTH_FAILED
            def check_channel_request(self, kind, chanid):
                return paramiko.OPEN_SUCCEEDED if kind == 'session' else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
            def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
                self.size = (height, width)
                return True
            def check_channel_shell_request(self, channel):
                self.shell.set()
                return True
        listener = socket.socket()
        listener.bind(('127.0.0.1', int(sys.argv[1])))
        listener.listen(4)
        key = paramiko.RSAKey.generate(2048)
        while True:
            client, _ = listener.accept()
            transport = paramiko.Transport(client)
            transport.add_server_key(key)
            server = Server()
            try:
                transport.start_server(server=server)
                channel = transport.accept(20)
                if channel is None or not server.shell.wait(20): continue
                channel.send(('PARAMIKO_PASSWORD_AUTH:%d %d\\r\\n' % server.size).encode())
                received = b''
                while b'exit' not in received:
                    data = channel.recv(1024)
                    if not data: break
                    received += data
                channel.send_exit_status(0)
                channel.close()
                break
            except (paramiko.SSHException, EOFError):
                pass
            finally:
                transport.close()
        listener.close()
        """
        let scriptURL = root.appendingPathComponent("password_server.py")
        try script.write(to: scriptURL, atomically: true, encoding: .utf8)
        let logURL = root.appendingPathComponent("sshd.log")
        _ = FileManager.default.createFile(atPath: logURL.path, contents: nil, attributes: [.posixPermissions: 0o600])
        log = try FileHandle(forWritingTo: logURL)
        daemon.executableURL = URL(fileURLWithPath: python)
        daemon.arguments = [scriptURL.path, String(port)]
        daemon.standardInput = FileHandle.nullDevice; daemon.standardOutput = log; daemon.standardError = log
        try launchDaemon()
    }

    private static func run(_ executable: String, _ arguments: [String]) throws {
        let process = Process(); process.executableURL = URL(fileURLWithPath: executable); process.arguments = arguments
        process.standardInput = FileHandle.nullDevice; process.standardOutput = FileHandle.nullDevice; process.standardError = FileHandle.nullDevice
        try process.run(); process.waitUntilExit()
        guard process.terminationStatus == 0 else { throw SSHError.invalid("Fixture command failed: \(executable)") }
    }

    private static func unusedLoopbackPort() throws -> Int {
        let fd = socket(AF_INET, SOCK_STREAM, 0)
        guard fd >= 0 else { throw SSHError.system("Fixture socket", errno) }
        defer { Darwin.close(fd) }
        var address = loopbackAddress(port: 0)
        let result = withUnsafePointer(to: &address) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { Darwin.bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) } }
        guard result == 0 else { throw SSHError.system("Fixture bind", errno) }
        var length = socklen_t(MemoryLayout<sockaddr_in>.size)
        let read = withUnsafeMutablePointer(to: &address) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(fd, $0, &length) } }
        guard read == 0 else { throw SSHError.system("Fixture getsockname", errno) }
        return Int(UInt16(bigEndian: address.sin_port))
    }
    private static func canConnect(port: Int) -> Bool {
        let fd = socket(AF_INET, SOCK_STREAM, 0); guard fd >= 0 else { return false }; defer { Darwin.close(fd) }
        var address = loopbackAddress(port: port)
        return withUnsafePointer(to: &address) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { Darwin.connect(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) == 0 } }
    }
    private static func loopbackAddress(port: Int) -> sockaddr_in {
        var address = sockaddr_in(); address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size); address.sin_family = sa_family_t(AF_INET)
        address.sin_port = UInt16(port).bigEndian; address.sin_addr.s_addr = inet_addr("127.0.0.1")
        return address
    }
}

private final class SSHFixtureState: @unchecked Sendable {
    private let lock = NSLock()
    private var data = Data()
    private var result: SSHProcessExit?
    func append(_ bytes: Data) { lock.lock(); data.append(bytes); lock.unlock() }
    func finish(_ exit: SSHProcessExit) { lock.lock(); result = exit; lock.unlock() }
    var text: String { lock.lock(); defer { lock.unlock() }; return String(decoding: data, as: UTF8.self) }
    var exit: SSHProcessExit? { lock.lock(); defer { lock.unlock() }; return result }
}
