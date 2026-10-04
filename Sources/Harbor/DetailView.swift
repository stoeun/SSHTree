import HarborKit
import SwiftUI

struct DetailView: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        VStack(spacing: 0) {
            if !model.sessions.isEmpty {
                SessionTabs()
                    .padding(.horizontal, 16)
                    .padding(.top, 10)
            }
            Group {
                if let session = model.activeSession {
                    TerminalScreen(session: session)
                } else if let connection = model.selectedConnection {
                    ConnectionHero(connection: connection)
                } else {
                    WelcomeView()
                }
            }
            .padding(16)
            .frame(maxWidth: .infinity, maxHeight: .infinity)
        }
        .navigationTitle(model.windowTitle)
        .navigationSubtitle(model.windowSubtitle)
    }
}

private struct SessionTabs: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        ScrollView(.horizontal, showsIndicators: false) {
            HStack(spacing: 6) {
                ForEach(model.sessions) { session in
                    let active = session.id == model.activeSessionID
                    HStack(spacing: 6) {
                        Circle()
                            .fill(dotColor(session))
                            .frame(width: 7, height: 7)
                        Button {
                            model.focus(session)
                        } label: {
                            Text(model.tabTitle(session))
                                .font(.callout.weight(active ? .semibold : .regular))
                                .lineLimit(1)
                        }
                        .buttonStyle(.plain)
                        Button {
                            model.closeSession(session.id)
                        } label: {
                            Image(systemName: "xmark")
                                .font(.caption2.weight(.bold))
                                .foregroundStyle(.secondary)
                        }
                        .buttonStyle(.plain)
                        .help("关闭会话")
                    }
                    .padding(.horizontal, 10)
                    .padding(.vertical, 6)
                    .background(active ? AnyShapeStyle(.thinMaterial) : AnyShapeStyle(.clear), in: Capsule())
                    .overlay {
                        Capsule().strokeBorder(.separator.opacity(active ? 0.5 : 0.25), lineWidth: 1)
                    }
                }
            }
            .padding(.vertical, 2)
        }
    }

    private func dotColor(_ session: TerminalSession) -> Color {
        switch session.phase {
        case .running: .green
        case .idle: .orange
        case .exited: .secondary
        }
    }
}

private struct TerminalScreen: View {
    @Environment(AppModel.self) private var model
    var session: TerminalSession

    var body: some View {
        VStack(spacing: 0) {
            HStack(spacing: 8) {
                Text(statusText)
                    .font(.caption.monospaced())
                    .foregroundStyle(.white.opacity(0.72))
                Spacer()
                if let connection = session.connection {
                    Text(connection.endpointLabel)
                        .font(.caption.monospaced())
                        .foregroundStyle(.white.opacity(0.55))
                }
            }
            .padding(.horizontal, 14)
            .padding(.vertical, 8)
            .background(HarborPalette.inkRaised)

            ZStack(alignment: .bottom) {
                TerminalHost(session: session)
                switch session.phase {
                case .idle:
                    statusBanner(text: "正在连接…", action: nil)
                case .running:
                    EmptyView()
                case .exited(let code):
                    statusBanner(
                        text: session.launchError ?? (code.map { "会话已结束，退出码 \($0)" } ?? "会话已结束"),
                        action: "重新连接"
                    ) {
                        model.reconnect(session.id)
                    }
                }
            }
        }
        .clipShape(RoundedRectangle(cornerRadius: 18, style: .continuous))
        .overlay {
            RoundedRectangle(cornerRadius: 18, style: .continuous)
                .strokeBorder(.separator.opacity(0.35), lineWidth: 1)
        }
    }

    private var statusText: String {
        switch session.phase {
        case .idle: "连接中"
        case .running: "已连接"
        case .exited: "已断开"
        }
    }

    private func statusBanner(text: String, action: String?, perform: (() -> Void)? = nil) -> some View {
        HStack(spacing: 12) {
            Text(text)
                .font(.callout)
                .foregroundStyle(.primary)
            Spacer()
            if let action, let perform {
                Button(action, action: perform)
                    .harborPrimary()
            }
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 10)
        .background(.ultraThinMaterial)
    }
}

private struct ConnectionHero: View {
    @Environment(AppModel.self) private var model
    var connection: SSHConnection

    var body: some View {
        VStack(spacing: 18) {
            Text(harborMonogram(connection.name))
                .font(.system(size: 36, weight: .semibold))
                .foregroundStyle(.white)
                .frame(width: 84, height: 84)
                .background(connection.color.color.gradient, in: Circle())
            VStack(spacing: 6) {
                Text(connection.name)
                    .font(.title.weight(.semibold))
                Text(connection.endpointLabel)
                    .font(.title3.monospaced())
                    .foregroundStyle(.secondary)
                    .textSelection(.enabled)
            }
            HStack(spacing: 8) {
                meta(connection.auth.title)
                if !connection.group.isEmpty { meta(connection.group) }
                if connection.port != 22 { meta("端口 \(connection.port)") }
            }
            if let date = connection.lastConnectedAt {
                Text("上次连接 \(HarborFormat.relative(date))")
                    .font(.callout)
                    .foregroundStyle(.secondary)
            }
            if !connection.notes.isEmpty {
                Text(connection.notes)
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
                    .lineLimit(4)
                    .frame(maxWidth: 420)
            }
            HStack(spacing: 10) {
                Button {
                    model.connect(connection.id)
                } label: {
                    Label("连接", systemImage: "bolt.horizontal")
                }
                .harborPrimary()
                .keyboardShortcut(.defaultAction)
                Button("编辑") { model.beginEdit(connection.id) }
                    .harborGlassButton()
            }
            .padding(.top, 4)
        }
        .padding(32)
        .harborCard()
        .frame(maxWidth: 560)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    private func meta(_ text: String) -> some View {
        Text(text)
            .font(.caption.weight(.medium))
            .padding(.horizontal, 8)
            .padding(.vertical, 4)
            .background(.thinMaterial, in: Capsule())
    }
}

private struct WelcomeView: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        VStack(spacing: 16) {
            Image(systemName: "point.3.connected.trianglepath.dotted")
                .font(.system(size: 42, weight: .light))
                .foregroundStyle(HarborPalette.accent)
            Text(model.connections.isEmpty ? "把服务器留在左边" : "选一个连接")
                .font(.title2.weight(.semibold))
            Text(model.connections.isEmpty
                 ? "列表保存 SSH 连接。点一台，右边就是终端。连接库可以加密后放到阿里云 OSS。"
                 : "双击列表，或点工具栏里的连接。终端会在这里打开。")
                .font(.body)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .frame(maxWidth: 420)
            if model.connections.isEmpty {
                HStack(spacing: 10) {
                    Button("新建连接") { model.beginCreate() }
                        .harborPrimary()
                    Button("导入 SSH 配置…") { model.importSSHConfig() }
                        .harborGlassButton()
                }
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}
