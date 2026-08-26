//
//  versiongate.swift
//  lara
//
//  Configurable version gate + kernel vulnerability state probe.
//
//  DarkSword's kernel bug (CVE-2025-43520, TOCTOU in
//  cluster_write_contig / cluster_read_contig) was fixed by Apple in
//  iOS 26.1 (xnu-12377.42+). lara hard-rejects iOS 26.1+ in
//  offsets_init(); this module:
//    1. exposes a research override ("force offsets") for people
//       experimenting with untested / future builds;
//    2. probes the RUNNING kernel for its xnu version string and reports
//       whether the running build is in the known-vulnerable range;
//    3. as secondary evidence, scans kernel __TEXT_EXEC for the patched
//       instruction signature (UPL flag constant 0x164D followed by a
//       bit-1 test, which the fix inserted into both *_contig functions).
//
//  IMPORTANT: a "vulnerable" probe result means the bug class exists in
//  that xnu branch, NOT that the full exploit chain will work — offsets
//  still have to be found per build.
//

import Foundation

enum KernelPatchState: Equatable {
    case vulnerable            // in known-vulnerable xnu range
    case patched               // fix confirmed in this xnu range
    case unknown(String)       // cannot determine (reason)
    case notExploited          // primitives unavailable

    var description: String {
        switch self {
        case .vulnerable: return "VULNERABLE — DarkSword bug class present in this xnu branch (offsets still required)"
        case .patched: return "PATCHED — CVE-2025-43520 fixed in this xnu branch (iOS 26.1+); DarkSword will not work"
        case .unknown(let why): return "UNKNOWN — \(why)"
        case .notExploited: return "primitives not available; cannot probe the running kernel"
        }
    }
}

final class versiongate {
    static let shared = versiongate()

    /// Research override: when set, offsets_init() skips the version gate.
    /// Stored in UserDefaults so a jailbreak-free reinstall keeps it.
    static var forceOffsets: Bool {
        get { UserDefaults.standard.bool(forKey: "lara.forceOffsets") }
        set { UserDefaults.standard.set(newValue, forKey: "lara.forceOffsets") }
    }

    /// Known-vulnerable xnu major/minor ranges (DarkSword tested range).
    /// iOS 16.x  -> xnu-8792.x
    /// iOS 17.x  -> xnu-10002.x
    /// iOS 18.x  -> xnu-11215.x  (up to 18.7.1; 18.7.7 backport fixed EOL devices)
    /// iOS 26.0x -> xnu-12377.x  (< 12377.42 patched)
    private static let vulnerableRanges: [(minMajor: Int, minMinor: Int, maxMajor: Int, maxMinor: Int, note: String)] = [
        (8792, 0, 8792, 9999, "iOS 16.x"),
        (10002, 0, 10002, 9999, "iOS 17.x"),
        (11215, 0, 11215, 9999, "iOS 18.x (18.7.7 backport patched old devices)"),
        (12377, 0, 12377, 41, "iOS 26.0.x"),
    ]

    // MARK: xnu version extraction

    /// Read the running kernel's xnu version from memory (Darwin string).
    /// The version string "root:xnu-XXXX.Y.Z~N/..." sits in kernel __TEXT.
    func currentXnuVersion() -> (major: Int, minor: Int, tag: String)? {
        guard ds_is_ready(), ds_get_kernel_base() != 0 else { return nil }
        let base = ds_get_kernel_base()
        let slide = ds_get_kernel_slide()
        // Scan the first 16 MB of __TEXT_EXEC (the version string is near
        // the beginning of the cstring section, typically within this).
        let limit: UInt64 = 0x1000000
        var hay = [UInt8](repeating: 0, count: Int(min(limit, 0x40000)))
        var found: (Int, Int, String)? = nil
        var offset: UInt64 = 0
        while offset < limit {
            let toRead = Int(min(UInt64(hay.count), limit - offset))
            ds_kread(base + slide + offset, &hay, UInt64(toRead))
            if let (maj, minr, tag) = scanXnuString(hay) {
                found = (maj, minr, tag)
                break
            }
            offset += UInt64(toRead)
        }
        return found
    }

    private func scanXnuString(_ data: [UInt8]) -> (Int, Int, String)? {
        let needle = Array("xnu-".utf8)
        guard data.count > needle.count else { return nil }
        for i in 0...(data.count - needle.count) {
            var ok = true
            for j in 0..<needle.count where data[i + j] != needle[j] { ok = false; break }
            guard ok else { continue }
            // parse "xnu-<major>.<minor>..."
            var numStr = ""
            var p = i + needle.count
            while p < data.count, data[p] >= 0x30, data[p] <= 0x39, numStr.count < 10 {
                numStr.append(Character(UnicodeScalar(data[p])))
                p += 1
            }
            guard !numStr.isEmpty, p < data.count, data[p] == 0x2e else { continue } // '.'
            p += 1
            var minStr = ""
            while p < data.count, data[p] >= 0x30, data[p] <= 0x39, minStr.count < 10 {
                minStr.append(Character(UnicodeScalar(data[p])))
                p += 1
            }
            guard let major = Int(numStr), let minor = Int(minStr) else { continue }
            // capture tag up to '/'
            var tag = ""
            while p < data.count, data[p] != 0x2f, tag.count < 24 {
                tag.append(Character(UnicodeScalar(data[p])))
                p += 1
            }
            return (major, minor, tag)
        }
        return nil
    }

    // MARK: patch state

    func probePatchState() -> KernelPatchState {
        guard ds_is_ready(), ds_get_kernel_base() != 0 else { return .notExploited }
        guard let ver = currentXnuVersion() else {
            return .unknown("could not extract xnu version from kernel")
        }
        for r in Self.vulnerableRanges {
            let inMajor = ver.major == r.minMajor
            if inMajor {
                if ver.minor <= r.maxMinor {
                    return .vulnerable
                }
                return .patched
            }
        }
        // Future xnu majors: report unknown but note it is NOT in the
        // known-vulnerable set (almost certainly patched).
        if ver.major > 12377 {
            return .patched
        }
        return .unknown("xnu \(ver.major).\(ver.minor) not in known range")
    }

    /// Secondary evidence: count of "movz w?, #0x164D" (UPL flags for
    /// cluster write) instructions followed within 4 instructions by a
    /// bit-1 test (TST #2 / TBZ #1). The fix added such tests to both
    /// *_contig functions, so patched builds show a higher ratio.
    /// Best-effort; not authoritative.
    func instructionSignatureScore() -> (found: Int, followedByBitTest: Int)? {
        guard ds_is_ready(), ds_get_kernel_base() != 0 else { return nil }
        let base = ds_get_kernel_base()
        let slide = ds_get_kernel_slide()
        var found = 0
        var tested = 0
        let limit: UInt64 = 0x4000000 // 64 MB text scan
        var buf = [UInt8](repeating: 0, count: 0x40000)
        var offset: UInt64 = 0
        // movz w?, #0x164d -> 0x5282C9A0 | rd  => bytes C9 82 52 (rd high)
        // tst wX, #2 -> 0x72000800 | rn      => bytes [rn] 08 00 72
        while offset < limit {
            let toRead = Int(min(UInt64(buf.count), limit - offset))
            ds_kread(base + slide + offset, &buf, UInt64(toRead))
            var i = 0
            while i + 4 <= toRead {
                if buf[i] == 0xC9, buf[i + 1] == 0x82, buf[i + 2] == 0x52 {
                    found += 1
                    // look ahead up to 8 instructions (32 bytes)
                    for j in stride(from: i + 4, to: min(i + 4 + 32, toRead - 3), by: 4) {
                        let opcode = UInt32(buf[j]) | (UInt32(buf[j + 1]) << 8) |
                            (UInt32(buf[j + 2]) << 16) | (UInt32(buf[j + 3]) << 24)
                        if opcode & 0xFF800000 == 0x72000000, (opcode >> 10) & 0xFFF == 2 {
                            tested += 1
                            break
                        }
                        if opcode & 0x7E000000 == 0x36000000, (opcode >> 19) & 0x1F == 1 {
                            tested += 1
                            break
                        }
                        if opcode == 0xD65F03C0 { break } // ret
                    }
                }
                i += 4
            }
            offset += UInt64(toRead)
        }
        return (found, tested)
    }

    /// Human-readable gate explanation for the UI.
    func gateStatus() -> String {
        var s = "version gate: \(probePatchState().description)"
        if let score = instructionSignatureScore() {
            s += "\ninstruction signature: \(score.followedByBitTest)/\(score.found) UPL-flag loads followed by bit-1 test"
        }
        s += "\nresearch override (forceOffsets): \(Self.forceOffsets ? "ON" : "OFF")"
        return s
    }
}
