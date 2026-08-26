//
//  uploadmgr.swift
//  lara
//
//  Secure upload of extraction / keychain results to a user-configured
//  server. Supports multipart/form-data (files) and raw JSON POST.
//
//  Configuration (UserDefaults, editable in lara Settings):
//    lara.upload.serverURL    e.g. https://backup.example.com/upload
//    lara.upload.apiToken     shared secret / bearer token
//    lara.upload.deviceID     stable device identifier
//    lara.upload.autoUpload   whether to upload automatically after jobs
//

import Foundation

final class uploadmgr {
    static let shared = uploadmgr()

    enum UploadError: LocalizedError {
        case notConfigured
        case transport(Error)
        case server(Int, String)
        var errorDescription: String? {
            switch self {
            case .notConfigured: return "upload server not configured"
            case .transport(let e): return "transport error: \(e.localizedDescription)"
            case .server(let code, let body): return "server \(code): \(body)"
            }
        }
    }

    struct UploadConfig {
        var serverURL: URL?
        var apiToken: String = ""
        var deviceID: String = ""
        var autoUpload: Bool = false
        var timeout: TimeInterval = 120

        static func load() -> UploadConfig {
            let d = UserDefaults.standard
            return UploadConfig(
                serverURL: d.url(forKey: "lara.upload.serverURL"),
                apiToken: d.string(forKey: "lara.upload.apiToken") ?? "",
                deviceID: d.string(forKey: "lara.upload.deviceID") ?? "",
                autoUpload: d.bool(forKey: "lara.upload.autoUpload"),
                timeout: 120)
        }

        func save() {
            let d = UserDefaults.standard
            d.set(serverURL, forKey: "lara.upload.serverURL")
            d.set(apiToken, forKey: "lara.upload.apiToken")
            d.set(deviceID, forKey: "lara.upload.deviceID")
            d.set(autoUpload, forKey: "lara.upload.autoUpload")
        }
    }

    private init() {}

    /// POST a JSON payload (e.g. keychain export) to the server.
    func uploadJSON(_ json: Data,
                    endpoint: String = "keychain",
                    config: UploadConfig,
                    completion: @escaping (Result<Data, UploadError>) -> Void) {
        guard let base = config.serverURL else {
            completion(.failure(.notConfigured))
            return
        }
        let url = base.appendingPathComponent(endpoint)
        var req = URLRequest(url: url)
        req.httpMethod = "POST"
        req.timeoutInterval = config.timeout
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        req.setValue("Bearer \(config.apiToken)", forHTTPHeaderField: "Authorization")
        req.setValue(config.deviceID, forHTTPHeaderField: "X-Device-ID")
        req.httpBody = json

        URLSession.shared.dataTask(with: req) { data, resp, err in
            if let err = err {
                completion(.failure(.transport(err)))
                return
            }
            let code = (resp as? HTTPURLResponse)?.statusCode ?? 0
            guard (200..<300).contains(code) else {
                let body = data.flatMap { String(data: $0, encoding: .utf8) } ?? ""
                completion(.failure(.server(code, body)))
                return
            }
            completion(.success(data ?? Data()))
        }.resume()
    }

    /// Upload a file as multipart/form-data.
    func uploadFile(_ fileURL: URL,
                    endpoint: String = "files",
                    config: UploadConfig,
                    progress: ((Double) -> Void)? = nil,
                    completion: @escaping (Result<Data, UploadError>) -> Void) {
        guard let base = config.serverURL else {
            completion(.failure(.notConfigured))
            return
        }
        let boundary = "Boundary-\(UUID().uuidString)"
        let url = base.appendingPathComponent(endpoint)
        var req = URLRequest(url: url)
        req.httpMethod = "POST"
        req.timeoutInterval = config.timeout
        req.setValue("multipart/form-data; boundary=\(boundary)", forHTTPHeaderField: "Content-Type")
        req.setValue("Bearer \(config.apiToken)", forHTTPHeaderField: "Authorization")
        req.setValue(config.deviceID, forHTTPHeaderField: "X-Device-ID")

        let fileName = fileURL.lastPathComponent
        let fileData: Data
        do {
            fileData = try Data(contentsOf: fileURL)
        } catch {
            completion(.failure(.transport(error)))
            return
        }

        var body = Data()
        body.append("--\(boundary)\r\n".data(using: .utf8)!)
        body.append("Content-Disposition: form-data; name=\"file\"; filename=\"\(fileName)\"\r\n".data(using: .utf8)!)
        body.append("Content-Type: application/octet-stream\r\n\r\n".data(using: .utf8)!)
        body.append(fileData)
        body.append("\r\n--\(boundary)--\r\n".data(using: .utf8)!)
        req.httpBody = body

        URLSession.shared.dataTask(with: req) { data, resp, err in
            if let err = err {
                completion(.failure(.transport(err)))
                return
            }
            let code = (resp as? HTTPURLResponse)?.statusCode ?? 0
            guard (200..<300).contains(code) else {
                let b = data.flatMap { String(data: $0, encoding: .utf8) } ?? ""
                completion(.failure(.server(code, b)))
                return
            }
            completion(.success(data ?? Data()))
        }.resume()
    }

    // MARK: convenience

    /// Upload the given local file with automatic retry (3 attempts, backoff).
    func uploadFileWithRetry(_ fileURL: URL,
                             endpoint: String = "files",
                             config: UploadConfig,
                             attempts: Int = 3,
                             completion: @escaping (Result<Data, UploadError>) -> Void) {
        var remaining = attempts
        func attempt() {
            uploadFile(fileURL, endpoint: endpoint, config: config) { result in
                switch result {
                case .success: completion(result)
                case .failure(let err):
                    remaining -= 1
                    if remaining > 0 {
                        DispatchQueue.global().asyncAfter(deadline: .now() + 3.0) { attempt() }
                    } else {
                        completion(.failure(err))
                    }
                }
            }
        }
        attempt()
    }
}
