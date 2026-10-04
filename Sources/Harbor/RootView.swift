import SwiftUI

struct RootView: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        @Bindable var model = model
        NavigationSplitView {
            SidebarView()
        } detail: {
            DetailView()
        }
        .navigationSplitViewStyle(.balanced)
        .tint(HarborPalette.accent)
        .toolbar {
            ToolbarItemGroup(placement: .primaryAction) {
                Button {
                    model.connectSelected()
                } label: {
                    Label("连接", systemImage: "bolt.horizontal")
                }
                .harborPrimary()
                .disabled(model.selectedConnection == nil)
                .help("连接所选主机。已有会话时回到那个会话。")

                Menu {
                    Button("本地 Shell") { model.openLocalShell() }
                    Button("再开一个会话") { model.connectSelected(newSession: true) }
                        .disabled(model.selectedConnection == nil)
                    Divider()
                    Button("字号 小") { model.setFontSize(12) }
                    Button("字号 标准") { model.setFontSize(13) }
                    Button("字号 大") { model.setFontSize(16) }
                    Button("字号 更大") { model.setFontSize(18) }
                } label: {
                    Label("终端", systemImage: "terminal")
                }

                Button {
                    model.smartSync()
                } label: {
                    Label("同步", systemImage: model.syncSymbol)
                }
                .disabled(model.isSyncing)
                .help(model.syncTitle)
            }
        }
        .sheet(isPresented: $model.showingEditor) {
            ConnectionEditor()
                .environment(model)
        }
        .sheet(item: $model.conflict) { conflict in
            ConflictView(conflict: conflict)
                .environment(model)
        }
        .alert(
            model.alert?.title ?? "",
            isPresented: Binding(
                get: { model.alert != nil },
                set: { if !$0 { model.alert = nil } }
            )
        ) {
            Button("好", role: .cancel) {}
        } message: {
            Text(model.alert?.message ?? "")
        }
        .confirmationDialog(
            model.confirmTitle,
            isPresented: Binding(
                get: { model.pendingConfirm != nil },
                set: { if !$0 { model.pendingConfirm = nil } }
            ),
            titleVisibility: .visible
        ) {
            Button(model.confirmActionTitle, role: .destructive) {
                model.performConfirm()
            }
            Button("取消", role: .cancel) {}
        } message: {
            Text(model.confirmMessage)
        }
        .onAppear { model.surfaceStartupProblem() }
        .task { await model.autoSyncIfNeeded() }
    }
}
