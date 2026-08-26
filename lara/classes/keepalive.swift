//
//  keepalive.swift
//  lara
//
//  "No reboot mid-process" hardening.
//
//  After the DarkSword exploit transfers the kernel R/W primitives into
//  launchd (persistence.m / transfer_krw_to_launchd), they survive app
//  restarts and even app termination — as long as the DEVICE does not
//  reboot. This module:
//    1. auto-recovers the stashed primitives on app launch;
//    2. runs a watchdog that periodically verifies the primitives still
//       answer (ds_kread sanity probe);
//    3. re-runs the in-process exploit as a last resort when the stash is
//       gone but the process is still alive;
//    4. keeps the sockets alive and logs a heartbeat for diagnostics.
//

import Foundation
import Combine

final class keepalive {
    static let shared = keepalive()

    enum State: Equatable {
        case idle
        case recovering
        case runningExploit
        case ready(UInt64)          // kernel base when primitives are live
        case failed(String)
    }

    @Published private(set) var state: State = .idle
    private var timer: Timer?
    private var lastHeartbeat: Date = Date()
    private var heartbeatCount: Int = 0
    private var recoveryAttempts: Int = 0
    private let maxRecoveryAttempts = 3

    private init() {}

    /// Call once on app launch (AppDelegate / SwiftUI .onAppear).
    func start() {
        guard timer == nil else { return }
        // Recover the primitives stashed in launchd, if any.
        if let base = recoverStashed() {
            state = .ready(base)
        } else if ds_is_ready() {
            state = .ready(ds_get_kernel_base())
        } else {
            state = .idle
        }
        timer = Timer.scheduledTimer(withTimeInterval: 5.0, repeats: true) { [weak self] _ in
            self?.tick()
        }
    }

    func stop() {
        timer?.invalidate()
        timer = nil
    }

    private func recoverStashed() -> UInt64? {
        state = .recovering
        let ok = recover_krw_primitives()
        guard ok, ds_is_ready() else {
            state = .idle
            return nil
        }
        return ds_get_kernel_base()
    }

    private func tick() {
        guard ds_is_ready() else {
            // Primitives lost. Try stash recovery, then re-exploit in place.
            recoveryAttempts += 1
            if recoveryAttempts <= maxRecoveryAttempts {
                if let base = recoverStashed() {
                    recoveryAttempts = 0
                    state = .ready(base)
                    log("keepalive: recovered stashed primitives (base 0x\(String(base, radix: 16)))")
                    return
                }
                // In-process re-exploit: only meaningful while the app runs.
                state = .runningExploit
                DispatchQueue.global(qos: .userInitiated).async { [weak self] in
                    let r = ds_run()
                    DispatchQueue.main.async {
                        guard let self = self else { return }
                        if r == 0, ds_is_ready() {
                            self.recoveryAttempts = 0
                            self.state = .ready(ds_get_kernel_base())
                            self.log("keepalive: exploit re-run succeeded")
                        } else {
                            self.state = .failed("exploit re-run failed")
                        }
                    }
                }
            } else {
                state = .failed("primitives unrecoverable; reboot required to re-exploit")
            }
            return
        }

        // Primitives alive: heartbeat + sanity probe.
        heartbeatCount += 1
        let base = ds_get_kernel_base()
        if base != 0, ds_kread32(base) == 0xFEEDFACF {
            lastHeartbeat = Date()
            if heartbeatCount % 12 == 0 {
                log("keepalive: heartbeat #\(heartbeatCount) (kernel alive, slide 0x\(String(ds_get_kernel_slide(), radix: 16)))")
            }
        } else {
            log("keepalive: sanity probe failed at heartbeat #\(heartbeatCount)")
        }
    }

    /// Keep a short diagnostic log so users can verify the keepalive ran.
    private func log(_ msg: String) {
        DispatchQueue.main.async {
            laramgr.shared.logmsg(msg)
        }
    }

    var uptimeDescription: String {
        let secs = Int(Date().timeIntervalSince(lastHeartbeat))
        return "last heartbeat \(secs)s ago (count \(heartbeatCount))"
    }
}
