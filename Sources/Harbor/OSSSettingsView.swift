import HarborKit
import SwiftUI

struct OSSSettingsView: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        @Bindable var model = model
        Form {
            Section("存储位置") {
                HStack {
                    TextField("地域 ID", text: $model.ossConfig.region, prompt: Text("cn-hangzhou"))
                    Menu("常用") {
                        ForEach(OSSRegion.common) { region in
                            Button("\(region.name)  \(region.code)") {
                                model.ossConfig.region = region.code
                            }
                        }
                    }
                    .fixedSize()
                }
                TextField("终端节点，可留空", text: $model.ossConfig.endpointOverride, prompt: Text("oss-cn-hangzhou.aliyuncs.com"))
                TextField("Bucket", text: $model.ossConfig.bucket)
                TextField("对象路径", text: $model.ossConfig.objectKey)
                Text("地域要和 Bucket 所在地域一致。终端节点不要带 Bucket 名，也不要带 https://。")
                    .font(.callout)
                    .foregroundStyle(.secondary)
            }

            Section("访问密钥") {
                TextField("AccessKey ID", text: $model.ossConfig.accessKeyID)
                SecureField("AccessKey Secret", text: $model.ossSecret)
                Text("密钥只放在这台 Mac 的钥匙串里，不会写进 OSS。")
                    .font(.callout)
                    .foregroundStyle(.secondary)
            }

            Section("加密") {
                SecureField("加密口令", text: $model.ossPassphrase)
                Text("上传前，连接库会用这个口令做 AES-GCM 加密。阿里云看到的是密文。换电脑时填写同一口令才能解开。口令本身不会上传，丢了就解不开。")
                    .font(.callout)
                    .foregroundStyle(.secondary)
            }

            Section("同步") {
                Toggle("打开 SSHTree 时自动同步", isOn: $model.ossConfig.autoSync)
                HStack {
                    Button("测试访问") { model.testAccess() }
                    Button("验证口令") { model.verifyPassphrase() }
                    Spacer()
                    Button("从云端下载") { model.pendingConfirm = .download }
                    Button("上传到云端") { model.pendingConfirm = .upload }
                    Button("双向同步") { model.smartSync() }
                        .harborPrimary()
                }
                .disabled(model.isSyncing)
                if model.isSyncing {
                    ProgressView().controlSize(.small)
                }
                Text(model.syncTitle)
                    .font(.callout)
                    .foregroundStyle(.secondary)
            }

            Section("怎么用") {
                Text("列表里的主机、用户名、密码和私钥路径会放进加密文件。AccessKey 留在本机。另一台 Mac 安装 SSHTree 后，填同一套 AccessKey 和同一口令，点「从云端下载」。双向同步会在两边都改过时停下来问你留哪一份。")
                    .font(.callout)
                    .foregroundStyle(.secondary)
                Text("AccessKey 需要这个对象的读写权限：oss:GetObject、oss:PutObject、oss:HeadObject。")
                    .font(.callout)
                    .foregroundStyle(.secondary)
            }
        }
        .formStyle(.grouped)
        .frame(width: 620, height: 680)
        .navigationTitle("云同步")
        .onDisappear { model.saveCloudSettings() }
    }
}

struct ConflictView: View {
    @Environment(AppModel.self) private var model
    var conflict: SyncConflict

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("两边都有新修改")
                .font(.title2.weight(.semibold))
            Text("这台 Mac 和阿里云 OSS 上的连接库都变了。选一份保留，另一份会被覆盖。")
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            LabeledContent("这台 Mac", value: HarborFormat.dateTime(conflict.localUpdated))
            LabeledContent("云端", value: conflict.remoteUpdated.map(HarborFormat.dateTime) ?? "时间未知")
            HStack {
                Button("取消") { model.conflict = nil }
                Spacer()
                Button("使用云端") { model.resolve(useRemote: true) }
                Button("保留这台 Mac") { model.resolve(useRemote: false) }
                    .harborPrimary()
            }
        }
        .padding(24)
        .frame(width: 460)
    }
}
