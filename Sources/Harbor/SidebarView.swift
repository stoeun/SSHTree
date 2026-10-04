import HarborKit
import SwiftUI

struct SidebarView: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        @Bindable var model = model
        Group {
            if model.connections.isEmpty && model.searchText.isEmpty {
                ContentUnavailableView {
                    Label("还没有连接", systemImage: "server.rack")
                } description: {
                    Text("新建一台，或从 ~/.ssh/config 导入。")
                } actions: {
                    Button("新建连接") { model.beginCreate() }
                        .harborPrimary()
                    Button("导入 SSH 配置…") { model.importSSHConfig() }
                }
            } else {
                List(selection: $model.selection) {
                    ForEach(model.sidebarSections) { section in
                        Section(section.title) {
                            ForEach(section.connections) { connection in
                                ConnectionRow(connection: connection)
                                    .tag(connection.id)
                                    .contextMenu { rowMenu(connection) }
                                    .simultaneousGesture(TapGesture(count: 2).onEnded {
                                        model.connect(connection.id)
                                    })
                            }
                        }
                    }
                }
                .listStyle(.sidebar)
            }
        }
        .navigationTitle("连接")
        .navigationSplitViewColumnWidth(min: 240, ideal: 280, max: 380)
        .searchable(text: $model.searchText, placement: .sidebar, prompt: "搜索主机、名称或备注")
        .safeAreaInset(edge: .bottom) {
            sidebarFooter
        }
    }

    private var sidebarFooter: some View {
        HStack(spacing: 8) {
            Button {
                model.beginCreate()
            } label: {
                Label("新建", systemImage: "plus")
            }
            .harborGlassButton()

            Spacer(minLength: 8)

            Button {
                model.smartSync()
            } label: {
                HStack(spacing: 8) {
                    Image(systemName: model.syncSymbol)
                        .symbolRenderingMode(.hierarchical)
                        .foregroundStyle(HarborPalette.accent)
                    VStack(alignment: .leading, spacing: 1) {
                        Text(model.syncTitle)
                            .font(.callout)
                            .lineLimit(1)
                        Text(model.syncDetail)
                            .font(.caption)
                            .foregroundStyle(.secondary)
                            .lineLimit(1)
                    }
                }
            }
            .buttonStyle(.plain)
            .disabled(model.isSyncing)
            .help("和阿里云 OSS 同步")

            SettingsLink {
                Image(systemName: "gearshape")
            }
            .buttonStyle(.borderless)
            .help("云同步设置")
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 10)
        .background(.bar)
    }

    @ViewBuilder
    private func rowMenu(_ connection: SSHConnection) -> some View {
        Button("连接") { model.connect(connection.id) }
        Button("新开一个会话") { model.connect(connection.id, newSession: true) }
        Button("编辑") { model.beginEdit(connection.id) }
        Button(connection.isFavorite ? "取消收藏" : "收藏") { model.toggleFavorite(connection.id) }
        Button("复制") { model.duplicate(connection.id) }
        Button("复制地址") { model.copyAddress(connection.id) }
        Divider()
        Button("删除", role: .destructive) { model.askDelete(connection.id) }
    }
}

private struct ConnectionRow: View {
    @Environment(AppModel.self) private var model
    var connection: SSHConnection

    var body: some View {
        HStack(spacing: 10) {
            ZStack(alignment: .bottomTrailing) {
                Text(harborMonogram(connection.name))
                    .font(.system(size: 12, weight: .semibold))
                    .foregroundStyle(.white)
                    .frame(width: 28, height: 28)
                    .background(connection.color.color.gradient, in: Circle())
                if model.isRunning(connection.id) {
                    Circle()
                        .fill(.green)
                        .frame(width: 8, height: 8)
                        .overlay(Circle().stroke(Color.black.opacity(0.25), lineWidth: 1))
                        .offset(x: 1, y: 1)
                }
            }
            VStack(alignment: .leading, spacing: 2) {
                HStack(spacing: 4) {
                    Text(connection.name)
                        .font(.body.weight(.medium))
                        .lineLimit(1)
                    if connection.isFavorite {
                        Image(systemName: "star.fill")
                            .font(.caption2)
                            .foregroundStyle(.yellow)
                    }
                }
                Text(connection.endpointLabel)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
            }
        }
        .padding(.vertical, 2)
        .accessibilityLabel("\(connection.name)，\(connection.endpointLabel)")
    }
}
