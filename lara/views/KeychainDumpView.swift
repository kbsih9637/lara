//
//  KeychainDumpView.swift
//  lara
//
//  临时测试版：本地钥匙串查看器（不上传服务器）。
//  提取 keychain-2.db → 尝试全部密钥后端解码 → 在 app 内直接展示。
//

import SwiftUI

final class KeychainDumpModel: ObservableObject {
    @Published var running = false
    @Published var items: [LaraKeychainItem] = []
    @Published var log: String = ""

    var grouped: [(table: String, items: [LaraKeychainItem])] {
        let order = ["genp", "inet", "keys", "cert"]
        var byTable: [String: [LaraKeychainItem]] = [:]
        for it in items { byTable[it.table, default: []].append(it) }
        var out: [(String, [LaraKeychainItem])] = []
        for t in order where byTable[t] != nil {
            out.append((t, byTable[t]!))
        }
        for (t, v) in byTable where !order.contains(t) {
            out.append((t, v))
        }
        return out
    }

    var decryptedCount: Int { items.filter { $0.decrypted != nil }.count }

    func start() {
        guard !running else { return }
        running = true
        items = []
        log = ""
        appendLog("开始提取钥匙串...")

        keychainmgr.shared.runExtractionAuto(logger: { [weak self] msg in
            DispatchQueue.main.async {
                self?.appendLog(msg)
            }
        }) { [weak self] result in
            DispatchQueue.main.async {
                guard let self = self else { return }
                self.items = result.items
                for m in result.messages { self.appendLog(m) }
                self.appendLog("完成：\(result.items.count) 条，解密 \(self.decryptedCount) 条")
                self.running = false
            }
        }
    }

    private func appendLog(_ s: String) {
        log += s + "\n"
    }
}

struct KeychainDumpView: View {
    @StateObject private var model = KeychainDumpModel()

    var body: some View {
        NavigationView {
            VStack(alignment: .leading, spacing: 0) {
                if !model.running && model.items.isEmpty {
                    Button(action: { model.start() }) {
                        Label("提取并解码钥匙串", systemImage: "key.fill")
                            .font(.headline)
                            .frame(maxWidth: .infinity)
                            .padding()
                            .background(Color.accentColor)
                            .foregroundColor(.white)
                            .cornerRadius(10)
                    }
                    .padding()
                }

                if model.running {
                    HStack {
                        ProgressView()
                        Text("提取中（设备已解锁时解密成功率最高）...")
                            .padding(.leading, 8)
                    }
                    .padding()
                }

                if !model.items.isEmpty {
                    Text("共 \(model.items.count) 条 / 解密 \(model.decryptedCount) 条")
                        .font(.subheadline)
                        .foregroundColor(.secondary)
                        .padding(.horizontal)
                        .padding(.top, 4)

                    List {
                        ForEach(model.grouped, id: \.table) { group in
                            Section(header: Text("\(group.table)（\(group.items.count)）")) {
                                ForEach(group.items) { item in
                                    VStack(alignment: .leading, spacing: 2) {
                                        Text(item.svce.isEmpty ? "(no service)" : item.svce)
                                            .font(.headline)
                                            .lineLimit(1)
                                        if !item.acct.isEmpty {
                                            Text("account: \(item.acct)")
                                                .font(.caption)
                                                .foregroundColor(.secondary)
                                        }
                                        Text("agrp: \(item.agrp)  pdmn: \(item.pdmn)")
                                            .font(.caption2)
                                            .foregroundColor(.secondary)
                                        if let plain = item.decryptedString {
                                            Text("明文: \(plain)")
                                                .font(.system(.caption, design: .monospaced))
                                                .foregroundColor(.green)
                                                .textSelection(.enabled)
                                        } else if item.decrypted != nil {
                                            Text("明文 (二进制 \(item.decrypted!.count)B)")
                                                .font(.caption)
                                                .foregroundColor(.green)
                                        } else {
                                            Text("密文 (\(item.data.count)B，未解密)")
                                                .font(.caption)
                                                .foregroundColor(.orange)
                                        }
                                    }
                                    .padding(.vertical, 2)
                                }
                            }
                        }
                    }
                    .listStyle(.insetGrouped)
                }

                ScrollView {
                    Text(model.log)
                        .font(.system(.caption2, design: .monospaced))
                        .foregroundColor(.secondary)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(8)
                }
                .frame(maxHeight: 160)
                .background(Color(.systemGray6))
            }
            .navigationTitle("钥匙串测试")
            .toolbar {
                if !model.items.isEmpty {
                    ToolbarItem(placement: .navigationBarTrailing) {
                        Button("重新提取") { model.start() }
                    }
                }
            }
        }
    }
}
