import AppKit
import HarborKit
import SwiftTerm

@MainActor
@Observable
final class TerminalSession: LocalProcessTerminalViewDelegate, Identifiable {
    enum Phase: Equatable {
        case idle
        case running
        case exited(Int32?)
    }

    let id = UUID()
    let connectionID: UUID?
    let title: String
    let connection: SSHConnection?
    let view: LocalProcessTerminalView
    private(set) var phase: Phase = .idle
    private(set) var launchError: String?
    var remoteTitle = ""

    private var didStart = false
    private let kind: Kind
    private let vault: LocalVault

    private enum Kind {
        case ssh(SSHConnection)
        case local
    }

    init(connection: SSHConnection, vault: LocalVault, fontSize: CGFloat) {
        self.kind = .ssh(connection)
        self.connection = connection
        self.connectionID = connection.id
        self.title = connection.name
        self.vault = vault
        view = TerminalSession.makeView(fontSize: fontSize, caret: connection.color.nsColor)
        superInitDelegate()
    }

    init(localWith vault: LocalVault, fontSize: CGFloat) {
        kind = .local
        connection = nil
        connectionID = nil
        title = "本地"
        self.vault = vault
        view = TerminalSession.makeView(fontSize: fontSize, caret: HarborPalette.accentNS)
        superInitDelegate()
    }

    private func superInitDelegate() {
        view.processDelegate = self
    }

    func applyFont(size: CGFloat) {
        view.font = NSFont.monospacedSystemFont(ofSize: size, weight: .regular)
    }

    func startIfNeeded() {
        guard !didStart, view.window != nil else { return }
        didStart = true
        switch kind {
        case .local:
            startLocal()
        case .ssh(let connection):
            startSSH(connection)
        }
    }

    func close() {
        view.terminate()
        vault.deleteSecret(named: id.uuidString)
    }

    private func startLocal() {
        let shell = ProcessInfo.processInfo.environment["SHELL"] ?? "/bin/zsh"
        view.startProcess(executable: shell, args: ["-l"], environment: TerminalEnvironment.lines(extra: [:]))
        phase = view.process.running ? .running : .exited(nil)
        if !view.process.running {
            launchError = "本地 Shell 没有启动。"
        }
    }

    private func startSSH(_ connection: SSHConnection) {
        let secretURL = vault.secretsURL.appendingPathComponent(id.uuidString)
        do {
            let plan = try SSHLauncher.plan(
                for: connection,
                askpassPath: vault.askpassURL.path,
                secretPath: secretURL.path
            )
            if let secret = plan.secret {
                _ = try vault.writeSecret(secret, named: id.uuidString)
            }
            view.startProcess(
                executable: plan.executable,
                args: plan.arguments,
                environment: TerminalEnvironment.lines(extra: plan.extraEnvironment)
            )
            phase = view.process.running ? .running : .exited(nil)
            if !view.process.running {
                launchError = "SSH 没有启动。"
                vault.deleteSecret(named: id.uuidString)
            }
        } catch {
            phase = .exited(nil)
            launchError = error.localizedDescription
            vault.deleteSecret(named: id.uuidString)
        }
    }

    nonisolated func sizeChanged(source: LocalProcessTerminalView, newCols: Int, newRows: Int) {}

    nonisolated func setTerminalTitle(source: LocalProcessTerminalView, title: String) {
        Task { @MainActor in
            self.remoteTitle = title
        }
    }

    nonisolated func hostCurrentDirectoryUpdate(source: TerminalView, directory: String?) {}

    nonisolated func processTerminated(source: TerminalView, exitCode: Int32?) {
        Task { @MainActor in
            self.phase = .exited(exitCode)
            self.vault.deleteSecret(named: self.id.uuidString)
        }
    }

    private static func makeView(fontSize: CGFloat, caret: NSColor) -> LocalProcessTerminalView {
        let view = LocalProcessTerminalView(frame: NSRect(x: 0, y: 0, width: 900, height: 560))
        view.font = NSFont.monospacedSystemFont(ofSize: fontSize, weight: .regular)
        view.nativeBackgroundColor = HarborPalette.inkNS
        view.nativeForegroundColor = HarborPalette.textNS
        view.caretColor = caret
        view.selectedTextBackgroundColor = caret.withAlphaComponent(0.35)
        view.optionAsMetaKey = true
        return view
    }
}

enum TerminalEnvironment {
    static func lines(extra: [String: String]) -> [String] {
        var values: [String: String] = [:]
        for line in Terminal.getEnvironmentVariables(termName: "xterm-256color") {
            let parts = line.split(separator: "=", maxSplits: 1)
            if parts.count == 2 {
                values[String(parts[0])] = String(parts[1])
            }
        }
        let parent = ProcessInfo.processInfo.environment
        for key in ["PATH", "SSH_AUTH_SOCK", "SSH_AGENT_PID", "LANG", "LC_ALL", "LC_CTYPE", "HOME", "USER", "LOGNAME", "TMPDIR"] {
            if let value = parent[key], !value.isEmpty {
                values[key] = value
            }
        }
        if extra["SSH_ASKPASS"] != nil, (values["DISPLAY"] ?? "").isEmpty {
            values["DISPLAY"] = "harbor"
        }
        if extra["SSH_ASKPASS"] == nil {
            values.removeValue(forKey: "SSH_ASKPASS")
            values.removeValue(forKey: "SSH_ASKPASS_REQUIRE")
            values.removeValue(forKey: "HARBOR_ASKPASS_FILE")
        }
        for (key, value) in extra {
            values[key] = value
        }
        return values.map { "\($0.key)=\($0.value)" }
    }
}

extension HarborPalette {
    static let accentNS = NSColor(srgbRed: 0.12, green: 0.55, blue: 0.50, alpha: 1)
}
