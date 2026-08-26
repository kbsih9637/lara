//
//  extractmgr.swift
//  lara
//
//  Full-disk file extraction and packaging.
//
//  Walks arbitrary paths through the VFS layer (full disk r/w), streams
//  file contents in chunks, stages them into the app sandbox, then packs
//  everything into a single zip via zipmgr's createZipArchive. The output
//  zip can be handed to uploadmgr for delivery to a server.
//
//  Requires: exploit primitives ready (ds_is_ready) + vfs ready
//            (laramgr.shared.vfsready == true).
//

import Foundation

final class extractmgr {
    static let shared = extractmgr()

    struct ExtractOptions {
        var maxDepth: Int = 12
        var maxFileSize: Int64 = 512 * 1024 * 1024   // per-file cap (512 MB)
        var maxTotalSize: Int64 = 4 * 1024 * 1024 * 1024 // overall cap
        var skipPaths: Set<String> = [
            "/dev", "/proc", "/sys", "/private/var/run", "/private/var/vm",
            "/private/var/log", "/private/var/tmp", "/private/var/folders",
            "/private/var/mobile/Library/Logs", "/System/Library/Caches",
        ]
        var skipNames: Set<String> = [".", ".."]
    }

    struct ExtractProgress {
        var currentPath: String = ""
        var filesDone: Int = 0
        var bytesDone: Int64 = 0
        var totalBytes: Int64 = 0
    }

    typealias ProgressHandler = (ExtractProgress) -> Void

    /// Stream a single file through VFS into a staging location.
    /// Returns the staged file URL or nil on failure.
    private func stageFile(from path: String, to dir: URL, chunkSize: Int = 512 * 1024) -> URL? {
        let size = vfs_filesize(path)
        guard size > 0 else { return nil }
        let name = URL(fileURLWithPath: path).lastPathComponent
        let dest = dir.appendingPathComponent("file_\(abs(name.hashValue))_\(size).bin")
        FileManager.default.createFile(atPath: dest.path, contents: nil)
        guard let fh = FileHandle(forWritingAtPath: dest.path) else { return nil }
        defer { try? fh.close() }

        var offset: off_t = 0
        while offset < size {
            let toRead = Int(min(Int64(chunkSize), size - offset))
            var buf = [UInt8](repeating: 0, count: toRead)
            let n = vfs_read(path, &buf, toRead, offset)
            guard n > 0 else {
                try? FileManager.default.removeItem(at: dest)
                return nil
            }
            fh.write(Data(buf.prefix(Int(n))))
            offset += n
            if n < Int64(toRead) { break }
        }
        return dest
    }

    /// Recursively enumerate a path through VFS.
    /// Returns flattened list of (fullPath, isDir, size?).
    private func enumerate(_ root: String,
                           options: ExtractOptions,
                           progress: ProgressHandler? = nil) -> [(path: String, isDir: Bool, size: Int64)] {
        var out: [(String, Bool, Int64)] = []
        var stack: [(String, Int)] = [(root, 0)]

        while let (dir, depth) = stack.popLast() {
            if depth > options.maxDepth { continue }
            guard let entries = laramgr.shared.vfslistdir(path: dir) else { continue }
            for entry in entries where !options.skipNames.contains(entry.name) {
                let full = dir.hasSuffix("/") ? dir + entry.name : dir + "/" + entry.name
                if entry.isDir {
                    if options.skipPaths.contains(full) { continue }
                    out.append((full, true, 0))
                    stack.append((full, depth + 1))
                } else {
                    let size = vfs_filesize(full)
                    guard size >= 0, size <= options.maxFileSize else { continue }
                    out.append((full, false, size))
                    let totalSoFar = out.reduce(0) { $0 + $1.2 }
                    progress?(ExtractProgress(currentPath: full, filesDone: out.count, bytesDone: totalSoFar, totalBytes: 0))
                }
            }
        }
        return out
    }

    /// Extract a path (file or directory) into a zip archive in the app sandbox.
    /// - Returns: the zip URL, or nil on failure.
    @discardableResult
    func extractToZip(path: String,
                      options: ExtractOptions = ExtractOptions(),
                      progress: ProgressHandler? = nil) -> URL? {
        guard ds_is_ready(), laramgr.shared.vfsready else { return nil }

        let fm = FileManager.default
        let docs = fm.urls(for: .documentDirectory, in: .userDomainMask).first!
        let stamp = Int(Date().timeIntervalSince1970)
        let workDir = docs.appendingPathComponent("extract_\(stamp)")
        let filesDir = workDir.appendingPathComponent("files")
        let zipURL = docs.appendingPathComponent("extract_\(stamp).zip")
        try? fm.createDirectory(at: filesDir, withIntermediateDirectories: true)

        let isDir = vfs_listdir(path, nil, nil) == 0 || (vfs_filesize(path) <= 0 && path != "/")
        let list = isDir ? enumerate(path, options: options, progress: progress)
                         : [(path, false, vfs_filesize(path))]

        var total: Int64 = list.reduce(0) { $0 + $1.size }
        if total > options.maxTotalSize { total = options.maxTotalSize }

        var done: Int64 = 0
        var idx = 0
        for (full, dir, size) in list {
            idx += 1
            progress?(ExtractProgress(currentPath: full, filesDone: idx, bytesDone: done, totalBytes: total))
            if dir {
                let rel = relpath(full, from: path)
                let dst = filesDir.appendingPathComponent(rel)
                try? fm.createDirectory(at: dst, withIntermediateDirectories: true)
                continue
            }
            guard done + size <= options.maxTotalSize else { break }
            if let staged = stageFile(from: full, to: filesDir) {
                let rel = relpath(full, from: path)
                let dst = filesDir.appendingPathComponent(rel)
                try? fm.createDirectory(at: dst.deletingLastPathComponent(), withIntermediateDirectories: true)
                try? fm.moveItem(at: staged, to: dst)
                done += size
            }
        }

        defer { try? fm.removeItem(at: workDir) }
        do {
            try createZipArchive(fromDirectory: filesDir, to: zipURL, compressionMethod: 8)
            progress?(ExtractProgress(currentPath: zipURL.path, filesDone: idx, bytesDone: done, totalBytes: total))
            return zipURL
        } catch {
            return nil
        }
    }

    /// Compute a relative path for zip entry naming (safe subset).
    private func relpath(_ full: String, from root: String) -> String {
        var r = full
        if r.hasPrefix(root) {
            r = String(r.dropFirst(root.count))
        }
        r = r.replacingOccurrences(of: ":", with: "_")
        r = r.replacingOccurrences(of: "//", with: "/")
        while r.hasPrefix("/") { r = String(r.dropFirst()) }
        return r.isEmpty ? "root" : r
    }
}
