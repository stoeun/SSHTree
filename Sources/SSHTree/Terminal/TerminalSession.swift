import AppKit
import Foundation
import Observation
import SSHTreeCore
import SwiftTerm

enum TerminalPhase: Equatable { case idle, connecting, connected, exited }

@MainActor
final class AuthenticationRequest: Identifiable {
    let id: UUID
    let prompt: String
    let kind: SSHAuthenticationPromptKind
    private var completion: ((String?) -> Void)?

    init(id: UUID, prompt: String, kind: SSHAuthenticationPromptKind, completion: @escaping (String?) -> Void) {
        self.id = id; self.prompt = prompt; self.kind = kind; self.completion = completion
    }
    func respond(_ value: String?) {
        guard let completion else { return }
        self.completion = nil
        completion(value)
    }
}

@MainActor @Observable
final class TerminalSession: Identifiable, @preconcurrency TerminalViewDelegate {
    let id = UUID()
    let connection: SSHConnection
    private(set) var phase: TerminalPhase = .idle
    private(set) var errorMessage: String?
    var onAuthenticationRequest: ((AuthenticationRequest) -> Void)?
    @ObservationIgnored let terminalView: TerminalView
    @ObservationIgnored private let credential: SSHCredential?
    @ObservationIgnored private var process: SSHPTYProcess?
    @ObservationIgnored private var runtime: SSHRuntimeDirectory?
    @ObservationIgnored private var askpass: SSHAskPassServer?
    @ObservationIgnored private var authenticationTask: Task<Void, Never>?
    @ObservationIgnored private var pendingRequests: [UUID: AuthenticationRequest] = [:]
    @ObservationIgnored private var generation = UUID()
    @ObservationIgnored private var usedSavedCredential = false

    init(connection: SSHConnection, credential: SSHCredential?) {
        self.connection = connection; self.credential = credential
        terminalView = TerminalView(frame: NSRect(x: 0, y: 0, width: 900, height: 560))
        terminalView.terminalDelegate = self
        terminalView.optionAsMetaKey = true
        applyPreferences()
    }

    func start() {
        guard phase == .idle else { return }
        phase = .connecting; errorMessage = nil; usedSavedCredential = false
        let attempt = UUID(); generation = attempt
        do {
            guard let executableURL = Bundle.main.executableURL else { throw SSHError.invalid("找不到应用程序路径。") }
            let helperURL = executableURL.deletingLastPathComponent().appendingPathComponent("SSHTreeAskPass")
            guard FileManager.default.isExecutableFile(atPath: helperURL.path) else { throw SSHError.invalid("应用程序缺少认证组件。请重新安装 SSHTree。") }
            let runtime = try SSHRuntimeDirectory()
            self.runtime = runtime
            if connection.authentication == .privateKey {
                guard let key = credential?.privateKey else { throw SSHError.invalid("这条连接没有导入的私钥。") }
                _ = try runtime.materializePrivateKey(key)
            }
            let privateKeyPath = runtime.privateKeyURL?.path
            let plan = try SSHLaunchPlan.make(connection: connection, helperURL: helperURL, runtime: runtime)
            let server = try SSHAskPassServer(socketURL: runtime.askpassSocketURL) { [weak self] query, respond in
                Task { @MainActor [weak self] in
                    self?.authenticationRequested(query, respond: respond, privateKeyPath: privateKeyPath, attempt: attempt)
                    if self == nil { respond(nil) }
                }
            }
            askpass = server
            let terminal = terminalView.getTerminal()
            let process = try SSHPTYProcess(executable: plan.executable, arguments: plan.arguments,
                environment: plan.environment.map { "\($0.key)=\($0.value)" }, columns: terminal.cols, rows: terminal.rows,
                onOutput: { [weak self] data in
                    // Backpressure: a noisy child cannot build an unbounded
                    // queue of pending UI chunks while main-thread rendering
                    // falls behind. Core PTY output always runs off-main.
                    DispatchQueue.main.sync {
                        MainActor.assumeIsolated {
                            guard let self, self.generation == attempt else { return }
                            self.terminalView.feed(byteArray: Array(data)[...])
                        }
                    }
                }, onExit: { [weak self] exit in
                    server.stop(); runtime.cleanup()
                    DispatchQueue.main.async {
                        guard let self, self.generation == attempt else { return }
                        self.processExited(exit)
                    }
                })
            self.process = process
            server.start(ancestorPID: process.pid, helperExecutablePath: helperURL.path)
            authenticationTask = Task { [weak self] in
                while !Task.isCancelled {
                    guard let self, self.generation == attempt, self.phase == .connecting else { return }
                    let connected = await Self.checkAuthentication(arguments: plan.probeArguments)
                    guard !Task.isCancelled, self.generation == attempt, self.phase == .connecting else { return }
                    if connected {
                        runtime.removePrivateKey()
                        self.phase = .connected
                        return
                    }
                    try? await Task.sleep(for: .milliseconds(200))
                }
            }
        } catch {
            askpass?.stop(); askpass = nil
            runtime?.cleanup(); runtime = nil
            process?.close(); process = nil
            errorMessage = error.localizedDescription
            phase = .exited
        }
    }

    func close() {
        generation = UUID()
        phase = .exited
        authenticationTask?.cancel(); authenticationTask = nil
        for request in Array(pendingRequests.values) { request.respond(nil) }
        pendingRequests.removeAll()
        askpass?.stop(); askpass = nil
        process?.close(); process = nil
        runtime?.cleanup(); runtime = nil
    }

    func reconnect() {
        close()
        terminalView.feed(text: "\u{1b}c")
        phase = .idle
        start()
    }

    func applyPreferences() {
        let defaults = UserDefaults.standard
        let name = defaults.string(forKey: "terminal.fontName") ?? "Menlo"
        let requested = defaults.object(forKey: "terminal.fontSize") as? Double ?? 13
        let size = CGFloat(min(48, max(9, requested.isFinite ? requested : 13)))
        let font = NSFont(name: name, size: size) ?? NSFont.monospacedSystemFont(ofSize: size, weight: .regular)
        // SwiftTerm's setter recomputes metrics and clears selection even if
        // the font is identical; ordinary SwiftUI refreshes must preserve it.
        if terminalView.font != font { terminalView.font = font }
        switch defaults.string(forKey: "terminal.appearance") ?? "system" {
        case "light": terminalView.appearance = NSAppearance(named: .aqua)
        case "dark": terminalView.appearance = NSAppearance(named: .darkAqua)
        default: terminalView.appearance = nil
        }
        terminalView.effectiveAppearance.performAsCurrentDrawingAppearance {
            terminalView.nativeBackgroundColor = NSColor.textBackgroundColor.usingColorSpace(.sRGB) ?? .textBackgroundColor
            terminalView.nativeForegroundColor = NSColor.textColor.usingColorSpace(.sRGB) ?? .textColor
            terminalView.caretColor = NSColor.textColor.usingColorSpace(.sRGB) ?? .textColor
            terminalView.selectedTextBackgroundColor = NSColor.selectedTextBackgroundColor
        }
    }

    private func authenticationRequested(_ query: SSHAskPassQuery, respond: @escaping @Sendable (String?) -> Void, privateKeyPath: String?, attempt: UUID) {
        guard generation == attempt, phase == .connecting || phase == .connected else { respond(nil); return }
        if !usedSavedCredential, phase == .connecting,
           let value = SSHAuthenticationPrompt.savedResponse(prompt: query.prompt, connection: connection, credential: credential, privateKeyPath: privateKeyPath) {
            usedSavedCredential = true
            respond(value)
            return
        }
        let request = AuthenticationRequest(id: query.id, prompt: query.prompt, kind: SSHAuthenticationPrompt.classify(query.prompt)) { [weak self] value in
            respond(value)
            guard let self, self.generation == attempt else { return }
            self.pendingRequests.removeValue(forKey: query.id)
            if value == nil, self.phase == .connecting { self.close() }
        }
        pendingRequests[query.id] = request
        if let onAuthenticationRequest { onAuthenticationRequest(request) }
        else { request.respond(nil) }
    }

    private func processExited(_ exit: SSHProcessExit) {
        authenticationTask?.cancel(); authenticationTask = nil
        let wasConnecting = phase == .connecting
        phase = .exited
        for request in Array(pendingRequests.values) { request.respond(nil) }
        pendingRequests.removeAll()
        askpass = nil; process = nil; runtime = nil
        if let code = exit.exitCode, code != 0 {
            errorMessage = wasConnecting ? "SSH 连接失败（退出码 \(code)）。请查看终端中的详细原因。" : "SSH 会话已结束（退出码 \(code)）。"
        } else if let signal = exit.signal {
            errorMessage = "SSH 会话已结束（信号 \(signal)）。"
        } else if wasConnecting {
            errorMessage = "服务器在认证完成前关闭了连接。"
        }
    }

    /// This is an actual mux protocol round trip. A spawned child or a socket
    /// file alone never marks authentication successful. -F none keeps this
    /// probe from evaluating user Match/LocalCommand and from opening a network
    /// connection. A deadline also bounds a stalled mux response.
    private nonisolated static func checkAuthentication(arguments: [String]) async -> Bool {
        await Task.detached(priority: .userInitiated) {
            SSHControlMasterProbe.check(arguments: arguments)
        }.value
    }

    func sizeChanged(source: TerminalView, newCols: Int, newRows: Int) { process?.resize(columns: newCols, rows: newRows) }
    func send(source: TerminalView, data: ArraySlice<UInt8>) { process?.send(Data(data)) }
    func setTerminalTitle(source: TerminalView, title: String) {}
    func hostCurrentDirectoryUpdate(source: TerminalView, directory: String?) {}
    func scrolled(source: TerminalView, position: Double) {}
    func rangeChanged(source: TerminalView, startY: Int, endY: Int) {}
}
