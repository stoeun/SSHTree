import AppKit
import SwiftUI

@main
struct SSHTreeApp: App {
    @State private var model = AppModel()
    @NSApplicationDelegateAdaptor(SSHTreeAppDelegate.self) private var appDelegate
    var body: some Scene {
        Window("SSHTree", id: "main") {
            MainWindow().environment(model).tint(.teal)
                .onAppear { appDelegate.model = model }
        }
        .defaultSize(width: 1120, height: 740)
        .windowResizability(.contentMinSize)
        .windowToolbarStyle(.unified)
        .commands { SSHTreeCommands(model: model) }
        Settings {
            SettingsView().environment(model)
                .onAppear { appDelegate.model = model }
        }
    }
}

private struct SSHTreeCommands: Commands {
    let model: AppModel
    @Environment(\.openWindow) private var openWindow
    var body: some Commands {
        CommandGroup(replacing: .newItem) {
            Button("添加主机…") { model.edit(nil); openWindow(id: "main") }.keyboardShortcut("n").disabled(!model.canEdit)
            Button("打开 SSHTree") { openWindow(id: "main") }.keyboardShortcut("0")
        }
        CommandGroup(replacing: .saveItem) {
            Button("保存资料") { Task { try? await model.persistNow() } }.keyboardShortcut("s").disabled(!model.hasUnsavedChanges)
        }
        CommandMenu("连接") {
            Button("连接所选主机") { if let connection = model.selectedConnection { model.connect(connection); openWindow(id: "main") } }
                .keyboardShortcut(.return, modifiers: .command).disabled(model.selectedConnection == nil)
            Button("编辑所选主机…") { model.edit(model.selectedConnection); openWindow(id: "main") }
                .keyboardShortcut("e").disabled(model.selectedConnection == nil || !model.canEdit)
            Button("关闭当前终端") {
                if let session = model.sessions.first(where: { $0.id == model.selectedSessionID }) { model.requestClose(session) }
            }.keyboardShortcut("w", modifiers: [.command, .shift]).disabled(model.selectedSessionID == nil)
            Divider()
            Button("立即同步") { Task { await model.sync() } }.keyboardShortcut("r", modifiers: [.command, .shift])
                .disabled(model.launchState != .ready || model.isSyncing)
        }
    }
}

@MainActor
final class SSHTreeAppDelegate: NSObject, NSApplicationDelegate {
    weak var model: AppModel?
    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { false }
    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        guard let model else { return .terminateNow }
        guard confirmSessionClosure(model: model, quitting: true) else { return .terminateCancel }
        if model.activeSessionCount == 0 && !model.hasUnsavedChanges { model.closeAllSessions(); return .terminateNow }
        Task { @MainActor in
            do { try await model.prepareForClosing(); sender.reply(toApplicationShouldTerminate: true) }
            catch { model.errorMessage = AppModel.message(for: error); sender.reply(toApplicationShouldTerminate: false) }
        }
        return .terminateLater
    }
}

@MainActor
private func confirmSessionClosure(model: AppModel, quitting: Bool) -> Bool {
    guard model.activeSessionCount > 0 else { return true }
    let alert = NSAlert()
    alert.messageText = quitting ? "退出并关闭 SSH 连接？" : "关闭窗口并结束 SSH 连接？"
    alert.informativeText = "当前有 \(model.activeSessionCount) 个活跃终端。关闭后会结束这些连接。"
    alert.alertStyle = .warning
    alert.addButton(withTitle: quitting ? "退出并关闭" : "关闭连接与窗口")
    alert.addButton(withTitle: "取消")
    return alert.runModal() == .alertFirstButtonReturn
}

struct MainWindowLifecycle: NSViewRepresentable {
    let model: AppModel
    func makeCoordinator() -> Coordinator { Coordinator(model: model) }
    func makeNSView(context: Context) -> WindowObservationView {
        let view = WindowObservationView()
        view.onWindow = { [weak coordinator = context.coordinator] window in coordinator?.attach(window) }
        return view
    }
    func updateNSView(_ nsView: WindowObservationView, context: Context) { if let window = nsView.window { context.coordinator.attach(window) } }

    @MainActor final class Coordinator: NSObject, NSWindowDelegate {
        let model: AppModel
        weak var observedWindow: NSWindow?
        nonisolated(unsafe) weak var previousDelegate: (any NSWindowDelegate)?
        private var closing = false
        private var allowed = false
        init(model: AppModel) { self.model = model }
        func attach(_ window: NSWindow) {
            guard observedWindow !== window else { return }
            observedWindow = window; previousDelegate = window.delegate; window.delegate = self
        }
        override func responds(to selector: Selector!) -> Bool {
            super.responds(to: selector) || (previousDelegate?.responds(to: selector) ?? false)
        }
        override func forwardingTarget(for selector: Selector!) -> Any? { previousDelegate }
        func windowShouldClose(_ sender: NSWindow) -> Bool {
            if allowed { return previousDelegate?.windowShouldClose?(sender) ?? true }
            guard !closing else { return false }
            guard confirmSessionClosure(model: model, quitting: false) else { return false }
            if model.activeSessionCount == 0 && !model.hasUnsavedChanges {
                model.closeAllSessions()
                return previousDelegate?.windowShouldClose?(sender) ?? true
            }
            closing = true
            Task { @MainActor in
                do {
                    try await model.prepareForClosing()
                    allowed = true; sender.performClose(nil); allowed = false
                } catch { model.errorMessage = AppModel.message(for: error) }
                closing = false
            }
            return false
        }
    }
}

@MainActor final class WindowObservationView: NSView {
    var onWindow: ((NSWindow) -> Void)?
    override func viewDidMoveToWindow() { super.viewDidMoveToWindow(); if let window { onWindow?(window) } }
}
