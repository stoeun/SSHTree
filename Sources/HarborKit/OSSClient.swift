import Foundation

public struct OSSHead: Equatable, Sendable {
    public var revision: UUID?
    public var updatedAt: Date?
    public var eTag: String?
}

public struct OSSClient: Sendable {
    public var region: String
    public var endpointHost: String
    public var bucket: String
    public var objectKey: String
    public var accessKeyID: String
    public var accessKeySecret: String
    public var session: URLSession

    public init(config: OSSConfig, accessKeySecret: String, session: URLSession = OSSClient.makeSession()) {
        region = config.region.trimmingCharacters(in: .whitespacesAndNewlines)
        endpointHost = OSSEndpoint.normalizeEndpoint(config.endpointOverride, region: region)
        bucket = config.bucket.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        objectKey = OSSEndpoint.normalizeKey(config.objectKey)
        accessKeyID = config.accessKeyID.trimmingCharacters(in: .whitespacesAndNewlines)
        self.accessKeySecret = accessKeySecret
        self.session = session
    }

    public static func makeSession() -> URLSession {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.timeoutIntervalForRequest = 30
        configuration.httpAdditionalHeaders = ["User-Agent": "Harbor/1.0"]
        configuration.urlCache = nil
        return URLSession(configuration: configuration)
    }

    public func head() async throws -> OSSHead? {
        let response: HTTPURLResponse
        do {
            response = try await send(method: "HEAD", body: nil, metadata: [:]).0
        } catch HarborError.notFound {
            return nil
        } catch {
            throw error
        }
        let headers = normalized(response)
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime]
        return OSSHead(
            revision: headers["x-oss-meta-harbor-revision"].flatMap(UUID.init(uuidString:)),
            updatedAt: headers["x-oss-meta-harbor-updated-at"].flatMap { formatter.date(from: $0) },
            eTag: headers["etag"]
        )
    }

    public func get() async throws -> Data {
        let (_, data) = try await send(method: "GET", body: nil, metadata: [:])
        return data
    }

    public func put(_ body: Data, revision: UUID, updatedAt: Date) async throws {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime]
        let metadata = [
            "x-oss-meta-harbor-revision": revision.uuidString,
            "x-oss-meta-harbor-updated-at": formatter.string(from: updatedAt)
        ]
        _ = try await send(method: "PUT", body: body, metadata: metadata, contentType: "application/octet-stream")
    }

    private func send(method: String, body: Data?, metadata: [String: String], contentType: String? = nil) async throws -> (HTTPURLResponse, Data) {
        guard !bucket.isEmpty, !objectKey.isEmpty, !region.isEmpty, !accessKeyID.isEmpty, !accessKeySecret.isEmpty else {
            throw HarborError.invalid("OSS 还没填完。需要地域、Bucket、对象路径和 AccessKey。")
        }
        guard let url = OSSEndpoint.url(bucket: bucket, endpoint: endpointHost, objectKey: objectKey) else {
            throw HarborError.invalid("OSS 地址组不起来。检查 Bucket 和终端节点。")
        }
        var headers = metadata
        if let contentType {
            headers["content-type"] = contentType
        }
        let signed = OSSSigner.sign(OSSSignInput(
            method: method,
            bucket: bucket,
            objectKey: objectKey,
            region: region,
            accessKeyID: accessKeyID,
            accessKeySecret: accessKeySecret,
            date: Date(),
            headers: headers
        ))
        var request = URLRequest(url: url)
        request.httpMethod = method
        for (key, value) in signed.headers {
            request.setValue(value, forHTTPHeaderField: key)
        }
        request.setValue(rfc1123(Date()), forHTTPHeaderField: "Date")
        request.httpBody = body
        let data: Data
        let response: URLResponse
        do {
            (data, response) = try await session.data(for: request)
        } catch {
            throw HarborError.invalid("网络错误。\(error.localizedDescription)")
        }
        guard let http = response as? HTTPURLResponse else {
            throw HarborError.invalid("OSS 没有返回 HTTP 响应。")
        }
        if http.statusCode == 404 {
            throw HarborError.notFound
        }
        guard (200...299).contains(http.statusCode) else {
            throw HarborError.oss(status: http.statusCode, code: xmlValue("Code", in: data), message: xmlValue("Message", in: data))
        }
        return (http, data)
    }

    private func normalized(_ response: HTTPURLResponse) -> [String: String] {
        var headers: [String: String] = [:]
        for (key, value) in response.allHeaderFields {
            guard let name = key as? String, let text = value as? String else { continue }
            headers[name.lowercased()] = text
        }
        return headers
    }

    private func xmlValue(_ tag: String, in data: Data) -> String {
        let text = String(data: data, encoding: .utf8) ?? ""
        guard let start = text.range(of: "<\(tag)>"), let end = text.range(of: "</\(tag)>") else {
            return text.trimmingCharacters(in: .whitespacesAndNewlines).prefix(180).description
        }
        return String(text[start.upperBound..<end.lowerBound])
    }

    private func rfc1123(_ date: Date) -> String {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.timeZone = TimeZone(secondsFromGMT: 0)
        formatter.dateFormat = "EEE, dd MMM yyyy HH:mm:ss 'GMT'"
        return formatter.string(from: date)
    }
}
