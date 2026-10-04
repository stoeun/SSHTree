import XCTest
import Darwin
@testable import SSHTreeCore

final class SSHLaunchTests: XCTestCase {
    func testRejectsOptionAndURIInjection() throws {
        let runtime = try SSHRuntimeDirectory(); defer { runtime.cleanup() }
        for host in ["-oProxyCommand=id", "ssh://root@evil", "host\nProxyCommand id", "$(touch /tmp/pwn)"] {
            XCTAssertThrowsError(try SSHLaunchPlan.make(connection: SSHConnection(host: host, username: "root"), helperURL: URL(fileURLWithPath: "/helper"), runtime: runtime))
        }
        XCTAssertThrowsError(try SSHLaunchPlan.make(connection: SSHConnection(host: "host", username: "-oProxyCommand=id"), helperURL: URL(fileURLWithPath: "/helper"), runtime: runtime))
        XCTAssertThrowsError(try SSHLaunchPlan.make(connection: SSHConnection(host: "host", port: 0, username: "root"), helperURL: URL(fileURLWithPath: "/helper"), runtime: runtime))
    }

    func testLaunchRequiresHostConfirmationAndDoesNotPutCredentialsInProcessArguments() throws {
        let runtime = try SSHRuntimeDirectory(); defer { runtime.cleanup() }
        let plan = try SSHLaunchPlan.make(connection: SSHConnection(host: "host.example", port: 2222, username: "root", authentication: .password), helperURL: URL(fileURLWithPath: "/Applications/SSHTree.app/Contents/MacOS/SSHTreeAskPass"), runtime: runtime)
        XCTAssertEqual(plan.executable, "/usr/bin/ssh")
        XCTAssertTrue(plan.arguments.contains("StrictHostKeyChecking=ask"))
        XCTAssertTrue(plan.arguments.contains("ControlPersist=no"))
        XCTAssertTrue(plan.arguments.contains("ControlMaster=yes"))
        XCTAssertTrue(plan.arguments.contains("PermitLocalCommand=no"))
        XCTAssertTrue(plan.arguments.contains("PubkeyAuthentication=no"))
        XCTAssertEqual(plan.arguments.suffix(2), ["--", "host.example"])
        XCTAssertEqual(plan.environment["SSH_ASKPASS_REQUIRE"], "force")
        XCTAssertFalse(plan.environment.keys.contains { $0.contains("TOKEN") || $0.contains("PASSWORD") })
        XCTAssertEqual(plan.probeArguments.prefix(2), ["-F", "none"])
        XCTAssertTrue(plan.probeArguments.contains("check"))
    }

    func testStoredCredentialsPreserveWhitespaceAndUnknownPromptsNeverAutofill() throws {
        let credential = SSHCredential(password: "  password \t", passphrase: " passphrase ")
        let connection = SSHConnection(host: "host.example", username: "root", authentication: .password)
        XCTAssertEqual(SSHAuthenticationPrompt.savedResponse(prompt: "root@host.example's password: ", connection: connection, credential: credential, privateKeyPath: nil), "  password \t")
        for prompt in ["Password: ", "OTP: ", "other@host.example's password: ", "root@different.example's password: ", "root@host.example's password: \nOTP:"] {
            XCTAssertNil(SSHAuthenticationPrompt.savedResponse(prompt: prompt, connection: connection, credential: credential, privateKeyPath: nil))
        }
        var keyConnection = connection; keyConnection.authentication = .privateKey
        XCTAssertEqual(SSHAuthenticationPrompt.savedResponse(prompt: "Enter passphrase for key '/tmp/owned/key': ", connection: keyConnection, credential: credential, privateKeyPath: "/tmp/owned/key"), " passphrase ")
        XCTAssertNil(SSHAuthenticationPrompt.savedResponse(prompt: "Enter passphrase for key '/tmp/other': ", connection: keyConnection, credential: credential, privateKeyPath: "/tmp/owned/key"))
    }

    func testHostFingerprintRequestNeedsNoAskpassHintAndKeepsFullPrompt() {
        let prompt = "The authenticity of host 'host.example (192.0.2.1)' can't be established.\nED25519 key fingerprint is SHA256:abcdefghijklmnopqrstuv.\nThis key is not known by any other names.\nAre you sure you want to continue connecting (yes/no/[fingerprint])? "
        XCTAssertEqual(SSHAuthenticationPrompt.classify(prompt), .hostConfirmation)
        XCTAssertEqual(SSHAuthenticationPrompt.classify(prompt.replacingOccurrences(of: "key fingerprint is SHA256:", with: "key fingerprint is: SHA256:")), .hostConfirmation)
        XCTAssertEqual(SSHAuthenticationPrompt.classify("root@host.example's password: "), .password)
        XCTAssertEqual(SSHAuthenticationPrompt.classify("Enter passphrase for key '/tmp/key': "), .passphrase)
        XCTAssertEqual(SSHAuthenticationPrompt.classify("Verification code: "), .other)
        XCTAssertEqual(SSHAuthenticationPrompt.classify("Are you sure?"), .other)
    }
}

final class SSHRuntimeTests: XCTestCase {
    func testPrivateKeyPermissionsAndIdempotentCleanup() throws {
        let runtime = try SSHRuntimeDirectory()
        let key = try runtime.materializePrivateKey(Data("RAW PRIVATE KEY".utf8))
        XCTAssertEqual(try Data(contentsOf: key), Data("RAW PRIVATE KEY".utf8))
        let directoryAttributes = try FileManager.default.attributesOfItem(atPath: runtime.directoryURL.path)
        let keyAttributes = try FileManager.default.attributesOfItem(atPath: key.path)
        XCTAssertEqual((directoryAttributes[.posixPermissions] as? NSNumber)?.intValue, 0o700)
        XCTAssertEqual((keyAttributes[.posixPermissions] as? NSNumber)?.intValue, 0o600)
        XCTAssertLessThan(runtime.controlSocketURL.path.utf8.count, 90)
        runtime.removePrivateKey()
        XCTAssertFalse(FileManager.default.fileExists(atPath: key.path))
        runtime.cleanup(); runtime.cleanup()
        XCTAssertFalse(FileManager.default.fileExists(atPath: runtime.directoryURL.path))
    }

    func testCleanupDoesNotRemoveAnActiveRuntimeOrUnrelatedDirectory() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let active = try SSHRuntimeDirectory(rootDirectory: root)
        defer { active.cleanup() }
        let unrelated = root.appendingPathComponent("unrelated")
        try FileManager.default.createDirectory(at: unrelated, withIntermediateDirectories: false)
        SSHRuntimeDirectory.cleanupStale(in: root)
        XCTAssertTrue(FileManager.default.fileExists(atPath: active.directoryURL.path))
        XCTAssertTrue(FileManager.default.fileExists(atPath: unrelated.path))
    }

    func testDecodesWaitStatusInsteadOfShowingRawWaitBits() {
        XCTAssertEqual(SSHProcessExit(waitStatus: 255 << 8).exitCode, 255)
        XCTAssertEqual(SSHProcessExit(waitStatus: 0).exitCode, 0)
        XCTAssertNil(SSHProcessExit(waitStatus: SIGTERM).exitCode)
        XCTAssertEqual(SSHProcessExit(waitStatus: SIGTERM).signal, SIGTERM)
    }

    func testCrashRecoveryRemovesOnlyDeadOwnedRuntimeAndDoesNotFollowSymlinks() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let stale = try SSHRuntimeDirectory(rootDirectory: root)
        _ = try stale.materializePrivateKey(Data("FIXTURE KEY".utf8))
        try Data("SSHTree-runtime-v1\n999999\n".utf8).write(to: stale.directoryURL.appendingPathComponent("owner"))
        let protected = try SSHRuntimeDirectory(rootDirectory: root)
        defer { protected.cleanup() }
        let link = root.appendingPathComponent("sshtree-\(getuid())-link")
        try FileManager.default.createSymbolicLink(at: link, withDestinationURL: protected.directoryURL)
        SSHRuntimeDirectory.cleanupStale(in: root)
        XCTAssertFalse(FileManager.default.fileExists(atPath: stale.directoryURL.path))
        XCTAssertTrue(FileManager.default.fileExists(atPath: protected.directoryURL.path))
        XCTAssertEqual(try FileManager.default.destinationOfSymbolicLink(atPath: link.path), protected.directoryURL.path)
    }
}

final class SSHIPCTests: XCTestCase, @unchecked Sendable {
    func testRepeatedRequestsDoNotRaceTheFirstWrite() async throws {
        let runtime = try SSHRuntimeDirectory(); defer { runtime.cleanup() }
        let server = try SSHAskPassServer(socketURL: runtime.askpassSocketURL) { _, respond in respond("accepted") }
        server.start(ancestorPID: getpid(), helperExecutablePath: nil)
        defer { server.stop() }
        let socketURL = runtime.askpassSocketURL
        for _ in 0..<200 {
            let result = try await Task.detached {
                try SSHAskPassClient.request(socketURL: socketURL, ownerPID: getpid(), prompt: "test", hint: nil)
            }.value
            XCTAssertEqual(result, "accepted")
        }
    }

    func testUnixSocketPreservesRawResponseAndCancellation() async throws {
        let runtime = try SSHRuntimeDirectory(); defer { runtime.cleanup() }
        let server = try SSHAskPassServer(socketURL: runtime.askpassSocketURL) { query, respond in
            respond(query.prompt == "cancel" ? nil : "  literal response \t")
        }
        server.start(ancestorPID: getpid(), helperExecutablePath: nil)
        defer { server.stop() }
        let socketURL = runtime.askpassSocketURL
        let value = try await Task.detached { try SSHAskPassClient.request(socketURL: socketURL, ownerPID: getpid(), prompt: "password", hint: nil) }.value
        XCTAssertEqual(value, "  literal response \t")
        let cancelled = try await Task.detached { try SSHAskPassClient.request(socketURL: socketURL, ownerPID: getpid(), prompt: "cancel", hint: nil) }.value
        XCTAssertNil(cancelled)
    }

    func testStoppingServerCancelsAnOutstandingRequest() async throws {
        let runtime = try SSHRuntimeDirectory(); defer { runtime.cleanup() }
        let received = expectation(description: "received request")
        let server = try SSHAskPassServer(socketURL: runtime.askpassSocketURL) { _, _ in received.fulfill() }
        server.start(ancestorPID: getpid(), helperExecutablePath: nil)
        let socketURL = runtime.askpassSocketURL
        let request = Task.detached { try SSHAskPassClient.request(socketURL: socketURL, ownerPID: getpid(), prompt: "wait", hint: nil) }
        await fulfillment(of: [received], timeout: 3)
        server.stop()
        do { let value = try await request.value; XCTAssertNil(value) } catch { /* Closed IPC is also cancellation. */ }
    }

    func testRejectsCallerOutsideAuthorizedProcessTree() async throws {
        let runtime = try SSHRuntimeDirectory(); defer { runtime.cleanup() }
        let server = try SSHAskPassServer(socketURL: runtime.askpassSocketURL) { _, _ in XCTFail("Unauthorized caller reached credentials") }
        server.start(ancestorPID: 999_999, helperExecutablePath: nil)
        defer { server.stop() }
        let socketURL = runtime.askpassSocketURL
        do {
            _ = try await Task.detached { try SSHAskPassClient.request(socketURL: socketURL, ownerPID: getpid(), prompt: "root@host's password: ", hint: nil) }.value
            XCTFail("Unauthorized caller was accepted")
        } catch {}
    }
}

final class SSHPTYTests: XCTestCase, @unchecked Sendable {
    func testContinuousOutputStillAllowsControlCInput() async throws {
        let finished = expectation(description: "Ctrl-C reaches busy terminal")
        let process = try SSHPTYProcess(executable: "/bin/sh", arguments: ["-c", "trap 'exit 0' INT; while :; do printf 'abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789\\n'; done"],
            environment: ["PATH=/usr/bin:/bin"], columns: 80, rows: 24,
            onOutput: { _ in usleep(1_000) }, onExit: { _ in finished.fulfill() })
        defer { process.close() }
        try await Task.sleep(for: .milliseconds(300))
        process.send(Data([3]))
        await fulfillment(of: [finished], timeout: 1.2)
        process.close()
    }

    func testConcurrentPTYsKeepIndependentInputAndLifetime() async throws {
        let firstFinished = expectation(description: "first session finished")
        let secondFinished = expectation(description: "second session finished")
        let firstOutput = SSHTestOutput(), secondOutput = SSHTestOutput()
        let first = try SSHPTYProcess(executable: "/bin/sh", arguments: ["-c", "read value; printf 'FIRST:%s' \"$value\"; exit 6"], environment: ["PATH=/usr/bin:/bin"], columns: 80, rows: 24,
            onOutput: { firstOutput.append($0) }, onExit: { exit in XCTAssertEqual(exit.exitCode, 6); firstFinished.fulfill() })
        let second = try SSHPTYProcess(executable: "/bin/sh", arguments: ["-c", "read value; printf 'SECOND:%s' \"$value\"; exit 8"], environment: ["PATH=/usr/bin:/bin"], columns: 100, rows: 30,
            onOutput: { secondOutput.append($0) }, onExit: { exit in XCTAssertEqual(exit.exitCode, 8); secondFinished.fulfill() })
        defer { first.close(); second.close() }
        first.send(Data("alpha\n".utf8))
        await fulfillment(of: [firstFinished], timeout: 3)
        XCTAssertEqual(kill(second.pid, 0), 0)
        XCTAssertFalse(String(decoding: secondOutput.data, as: UTF8.self).contains("alpha"))
        second.send(Data("beta\n".utf8))
        await fulfillment(of: [secondFinished], timeout: 3)
        XCTAssertTrue(String(decoding: firstOutput.data, as: UTF8.self).contains("FIRST:alpha"))
        XCTAssertTrue(String(decoding: secondOutput.data, as: UTF8.self).contains("SECOND:beta"))
    }

    func testInputAndResizeReachTheControllingTerminal() async throws {
        let finished = expectation(description: "input completed")
        let output = SSHTestOutput()
        let process = try SSHPTYProcess(executable: "/bin/sh", arguments: ["-c", "IFS= read -r value; printf 'INPUT:%s\\n' \"$value\"; stty size"], environment: ["PATH=/usr/bin:/bin"], columns: 80, rows: 24,
            onOutput: { output.append($0) }, onExit: { exit in XCTAssertEqual(exit.exitCode, 0); finished.fulfill() })
        process.resize(columns: 132, rows: 43)
        process.send(Data("  literal input  \n".utf8))
        await fulfillment(of: [finished], timeout: 3)
        let text = String(decoding: output.data, as: UTF8.self)
        XCTAssertTrue(text.contains("INPUT:  literal input  "))
        XCTAssertTrue(text.contains("43 132"))
    }

    func testExecFailureIsReapedAs127() async throws {
        let finished = expectation(description: "failed exec reaped")
        let process = try SSHPTYProcess(executable: "/does-not-exist/sshtree-fixture", arguments: [], environment: [], columns: 80, rows: 24,
            onOutput: { _ in }, onExit: { exit in XCTAssertEqual(exit.exitCode, 127); finished.fulfill() })
        await fulfillment(of: [finished], timeout: 3)
        var status: Int32 = 0
        XCTAssertEqual(waitpid(process.pid, &status, WNOHANG), -1)
        XCTAssertEqual(errno, ECHILD)
    }

    func testCloseEscalatesAndReapsATermIgnoringChild() async throws {
        let ready = expectation(description: "TERM handler installed")
        let finished = expectation(description: "force kill reaped")
        let process = try SSHPTYProcess(executable: "/bin/sh", arguments: ["-c", "trap '' TERM; printf READY; while :; do sleep 1; done"], environment: ["PATH=/usr/bin:/bin"], columns: 80, rows: 24,
            onOutput: { _ in ready.fulfill() }, onExit: { exit in XCTAssertEqual(exit.signal, SIGKILL); finished.fulfill() })
        await fulfillment(of: [ready], timeout: 3)
        process.close()
        await fulfillment(of: [finished], timeout: 4)
        var status: Int32 = 0
        XCTAssertEqual(waitpid(process.pid, &status, WNOHANG), -1)
        XCTAssertEqual(errno, ECHILD)
    }

    func testImmediateCloseDoesNotWaitForTheForceKillDeadline() async throws {
        let finished = expectation(description: "immediate close reaped")
        let start = ContinuousClock.now
        let process = try SSHPTYProcess(executable: "/bin/sh", arguments: ["-c", "sleep 60"], environment: ["PATH=/usr/bin:/bin"], columns: 80, rows: 24, onOutput: { _ in }, onExit: { _ in finished.fulfill() })
        process.close()
        await fulfillment(of: [finished], timeout: 4)
        XCTAssertLessThan(start.duration(to: .now), .seconds(1))
    }

    func testPTYHasRealTTYAndReapsFastChildExit() async throws {
        let finished = expectation(description: "child reaped")
        let output = SSHTestOutput()
        let process = try SSHPTYProcess(executable: "/bin/sh", arguments: ["-c", "test -t 0 && test -t 1 && printf REAL_TTY; exit 7"], environment: ["PATH=/usr/bin:/bin", "TERM=xterm-256color"], columns: 80, rows: 24, onOutput: { output.append($0) }, onExit: { exit in
            XCTAssertEqual(exit.exitCode, 7); finished.fulfill()
        })
        await fulfillment(of: [finished], timeout: 3)
        XCTAssertTrue(String(decoding: output.data, as: UTF8.self).contains("REAL_TTY"))
        var status: Int32 = 0
        XCTAssertEqual(waitpid(process.pid, &status, WNOHANG), -1)
        XCTAssertEqual(errno, ECHILD)
    }

    func testClosingPTYTerminatesAndReapsChild() async throws {
        let finished = expectation(description: "closed child reaped")
        let process = try SSHPTYProcess(executable: "/bin/sh", arguments: ["-c", "sleep 60"], environment: ["PATH=/usr/bin:/bin"], columns: 80, rows: 24, onOutput: { _ in }, onExit: { _ in finished.fulfill() })
        process.close()
        await fulfillment(of: [finished], timeout: 4)
        var status: Int32 = 0
        XCTAssertEqual(waitpid(process.pid, &status, WNOHANG), -1)
        XCTAssertEqual(errno, ECHILD)
    }
}

private final class SSHTestOutput: @unchecked Sendable {
    private let lock = NSLock()
    private var bytes = Data()
    func append(_ data: Data) { lock.lock(); bytes.append(data); lock.unlock() }
    var data: Data { lock.lock(); defer { lock.unlock() }; return bytes }
}
