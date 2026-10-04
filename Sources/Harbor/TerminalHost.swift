import AppKit
import SwiftUI

struct TerminalHost: NSViewRepresentable {
    var session: TerminalSession

    func makeCoordinator() -> Coordinator {
        Coordinator()
    }

    func makeNSView(context: Context) -> TerminalContainer {
        let container = TerminalContainer()
        container.attach(session.view)
        return container
    }

    func updateNSView(_ container: TerminalContainer, context: Context) {
        container.attach(session.view)
        guard container.window != nil else { return }
        session.startIfNeeded()
        if context.coordinator.focusedID != session.id {
            container.window?.makeFirstResponder(session.view)
            context.coordinator.focusedID = session.id
        }
    }

    final class Coordinator {
        var focusedID: UUID?
    }
}

final class TerminalContainer: NSView {
    private weak var embedded: NSView?

    override init(frame frameRect: NSRect) {
        super.init(frame: frameRect)
        wantsLayer = true
        layer?.backgroundColor = HarborPalette.inkNS.cgColor
    }

    required init?(coder: NSCoder) {
        return nil
    }

    func attach(_ view: NSView) {
        if embedded !== view {
            embedded?.removeFromSuperview()
            addSubview(view)
            embedded = view
        }
        view.frame = bounds
        view.autoresizingMask = [.width, .height]
    }
}
