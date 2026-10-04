import AppKit
import SwiftUI

struct TerminalHost: NSViewRepresentable {
    var session: TerminalSession
    var isActive: Bool = true
    @AppStorage("terminal.fontName") private var fontName = "Menlo"
    @AppStorage("terminal.fontSize") private var fontSize = 13.0
    @AppStorage("terminal.appearance") private var terminalAppearance = "system"
    @Environment(\.colorScheme) private var colorScheme

    func makeNSView(context: Context) -> TerminalContainer {
        let container = TerminalContainer()
        container.setActive(isActive)
        container.attach(session.terminalView)
        session.applyPreferences()
        return container
    }

    func updateNSView(_ container: TerminalContainer, context: Context) {
        // Reading the stored preferences establishes SwiftUI invalidation when
        // Settings changes them; the terminal view is retained across tab swaps.
        _ = (fontName, fontSize, terminalAppearance, colorScheme)
        container.setActive(isActive)
        container.attach(session.terminalView)
        session.applyPreferences()
    }

    func sizeThatFits(_ proposal: ProposedViewSize, nsView: TerminalContainer, context: Context) -> CGSize? {
        // Terminal rows follow the available pane size. Never offer a natural
        // size derived from its scrollback document back to SwiftUI/window.
        CGSize(width: max(0, proposal.width ?? 0), height: max(0, proposal.height ?? 0))
    }
}

@MainActor
final class TerminalContainer: NSView {
    private weak var embedded: NSView?
    private var isActive = false
    override init(frame frameRect: NSRect) { super.init(frame: frameRect) }
    required init?(coder: NSCoder) { super.init(coder: coder) }
    override var intrinsicContentSize: NSSize { NSSize(width: NSView.noIntrinsicMetric, height: NSView.noIntrinsicMetric) }

    func attach(_ view: NSView) {
        if embedded !== view {
            embedded?.removeFromSuperview()
            addSubview(view)
            embedded = view
            requestFocus()
        }
        view.frame = bounds
        view.autoresizingMask = [.width, .height]
    }

    override func viewDidMoveToWindow() {
        super.viewDidMoveToWindow()
        NotificationCenter.default.removeObserver(self, name: NSWindow.didEndSheetNotification, object: nil)
        if let window {
            NotificationCenter.default.addObserver(self, selector: #selector(sheetEnded), name: NSWindow.didEndSheetNotification, object: window)
        }
        requestFocus()
    }

    @objc private func sheetEnded(_ notification: Notification) { requestFocus() }

    func setActive(_ active: Bool) {
        let becameActive = active && !isActive
        isActive = active
        if !active, let embedded, window?.firstResponder === embedded { window?.makeFirstResponder(nil) }
        if becameActive { requestFocus() }
    }

    private func requestFocus() {
        guard isActive, let embedded else { return }
        DispatchQueue.main.async { [weak self, weak embedded] in
            guard let self, self.isActive, let embedded,
                  embedded.superview === self, self.window?.attachedSheet == nil else { return }
            self.window?.makeFirstResponder(embedded)
        }
    }
}
