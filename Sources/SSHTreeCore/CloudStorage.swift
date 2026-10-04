import Foundation
#if canImport(FoundationXML)
import FoundationXML
#endif
import CryptoKit
import CommonCrypto

protocol ObjectStore: Sendable {
    func get(_ key: String) async throws -> Data?
    func put(_ data: Data, key: String, createOnly: Bool) async throws
    func list(prefix: String) async throws -> [String]
}

enum CloudSigner {
    static func encode(_ string: String, slash: Bool = false) -> String {
        string.utf8.map { byte in
            if (65...90).contains(byte) || (97...122).contains(byte) || (48...57).contains(byte) || [45, 46, 95, 126].contains(byte) || (slash && byte == 47) { return String(UnicodeScalar(byte)) }
            return String(format: "%%%02X", byte)
        }.joined()
    }
    static func sha1(_ data: Data) -> Data {
        var output = [UInt8](repeating: 0, count: Int(CC_SHA1_DIGEST_LENGTH))
        data.withUnsafeBytes { _ = CC_SHA1($0.baseAddress, CC_LONG(data.count), &output) }
        return Data(output)
    }
    static func hmacSHA1(_ key: Data, _ data: Data) -> Data {
        var output = [UInt8](repeating: 0, count: Int(CC_SHA1_DIGEST_LENGTH))
        key.withUnsafeBytes { keyBytes in data.withUnsafeBytes { bytes in CCHmac(CCHmacAlgorithm(kCCHmacAlgSHA1), keyBytes.baseAddress, key.count, bytes.baseAddress, data.count, &output) } }
        return Data(output)
    }
    static func hmac256(_ key: Data, _ message: String) -> Data { Data(HMAC<SHA256>.authenticationCode(for: Data(message.utf8), using: SymmetricKey(data: key))) }
    static func queryString(_ query: [String: String], emptyEquals: Bool = true, lowerKeys: Bool = false) -> String {
        query.map { (encode(lowerKeys ? $0.key.lowercased() : $0.key), encode($0.value)) }.sorted { $0.0 < $1.0 }.map { $0.0 + ((!emptyEquals && $0.1.isEmpty) ? "" : "=" + $0.1) }.joined(separator: "&")
    }
    static func ossCanonical(method: String, resource: String, query: [String: String], headers: [String: String], additional: [String] = []) -> String {
        let required = headers.map { ($0.key.lowercased(), $0.value.trimmingCharacters(in: .whitespacesAndNewlines)) }.filter { $0.0.hasPrefix("x-oss-") || ["content-type", "content-md5"].contains($0.0) || additional.contains($0.0) }
        let canonicalHeaders = required.sorted { $0.0 < $1.0 }.map { "\($0.0):\($0.1)\n" }.joined()
        return "\(method)\n\(encode(resource, slash: true))\n\(queryString(query, emptyEquals: false))\n\(canonicalHeaders)\n\(additional.sorted().joined(separator: ";"))\nUNSIGNED-PAYLOAD"
    }
    static func ossAuthorization(method: String, resource: String, query: [String: String], headers: [String: String], credentials: CloudCredentials, region: String, timestamp: String, additional: [String] = []) -> String {
        let date = String(timestamp.prefix(8)); let scope = "\(date)/\(region)/oss/aliyun_v4_request"
        let canonical = ossCanonical(method: method, resource: resource, query: query, headers: headers, additional: additional)
        let toSign = "OSS4-HMAC-SHA256\n\(timestamp)\n\(scope)\n\(Data(canonical.utf8).sha256)"
        let dateKey = hmac256(Data(("aliyun_v4" + credentials.secretKey).utf8), date)
        let signing = hmac256(hmac256(hmac256(dateKey, region), "oss"), "aliyun_v4_request")
        let extra = additional.isEmpty ? "" : ",AdditionalHeaders=\(additional.sorted().joined(separator: ";"))"
        return "OSS4-HMAC-SHA256 Credential=\(credentials.accessKeyID)/\(scope)\(extra),Signature=\(hmac256(signing, toSign).hex)"
    }
    static func cosAuthorization(method: String, path: String, query: [String: String], headers: [String: String], credentials: CloudCredentials, keyTime: String) -> String {
        let lowered = Dictionary(uniqueKeysWithValues: headers.map { ($0.key.lowercased(), $0.value.trimmingCharacters(in: .whitespacesAndNewlines)) })
        let headerList = lowered.keys.map { encode($0).lowercased() }.sorted().joined(separator: ";")
        let paramList = query.keys.map { encode($0.lowercased()).lowercased() }.sorted().joined(separator: ";")
        // COS signs the decoded path; only names in HeaderList/URLParamList are lowercased, not percent-encoded values.
        let http = "\(method.lowercased())\n\(path)\n\(queryString(query, lowerKeys: true))\n\(queryString(lowered))\n"
        let signKey = hmacSHA1(Data(credentials.secretKey.utf8), Data(keyTime.utf8)).hex
        let toSign = "sha1\n\(keyTime)\n\(sha1(Data(http.utf8)).hex)\n"
        let signature = hmacSHA1(Data(signKey.utf8), Data(toSign.utf8)).hex
        return "q-sign-algorithm=sha1&q-ak=\(credentials.accessKeyID)&q-sign-time=\(keyTime)&q-key-time=\(keyTime)&q-header-list=\(headerList)&q-url-param-list=\(paramList)&q-signature=\(signature)"
    }
}

struct ObjectListPage {
    var keys: [String]
    var next: String?
    static func parse(_ bytes: Data, kind: StorageKind) throws -> ObjectListPage {
        guard bytes.count <= VaultCrypto.maxBytes else { throw VaultError.corrupt("列表过大") }
        let delegate = ListXML(); let parser = XMLParser(data: bytes)
        parser.shouldResolveExternalEntities = false; parser.delegate = delegate
        guard parser.parse(), delegate.root == "ListBucketResult", delegate.truncated != nil else { throw VaultError.corrupt("云存储列表 XML 无效") }
        if delegate.truncated == true {
            let cursor = kind == .oss ? delegate.continuation : delegate.marker
            guard let cursor, !cursor.isEmpty else { throw VaultError.corrupt("云存储列表缺少分页标记") }
            return ObjectListPage(keys: delegate.keys, next: cursor)
        }
        return ObjectListPage(keys: delegate.keys, next: nil)
    }
}
private final class ListXML: NSObject, XMLParserDelegate {
    var root: String?; var stack: [String] = []; var text = ""; var keys: [String] = []
    var truncated: Bool?; var marker: String?; var continuation: String?
    func parser(_ parser: XMLParser, didStartElement name: String, namespaceURI: String?, qualifiedName: String?, attributes: [String: String]) {
        if root == nil { root = name }; stack.append(name); text = ""
    }
    func parser(_ parser: XMLParser, foundCharacters string: String) { text += string }
    func parser(_ parser: XMLParser, didEndElement name: String, namespaceURI: String?, qualifiedName: String?) {
        if name == "Key", stack.count >= 2, stack[stack.count - 2] == "Contents" { keys.append(text) }
        if name == "IsTruncated" { if text == "true" { truncated = true }; if text == "false" { truncated = false } }
        if name == "NextMarker" { marker = text }; if name == "NextContinuationToken" { continuation = text }
        _ = stack.popLast(); text = ""
    }
}

private final class VersioningXML: NSObject, XMLParserDelegate {
    var root: String?; var status: String?; var text = ""
    func parser(_ parser: XMLParser, didStartElement name: String, namespaceURI: String?, qualifiedName: String?, attributes: [String: String]) { if root == nil { root = name }; text = "" }
    func parser(_ parser: XMLParser, foundCharacters string: String) { text += string }
    func parser(_ parser: XMLParser, didEndElement name: String, namespaceURI: String?, qualifiedName: String?) { if name == "Status" { status = text.trimmingCharacters(in: .whitespacesAndNewlines) }; text = "" }
}

// Redirects are refused so Authorization never reaches a redirected host.
private final class NoRedirect: NSObject, URLSessionTaskDelegate, Sendable {
    func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse, newRequest request: URLRequest, completionHandler: @escaping @Sendable (URLRequest?) -> Void) { completionHandler(nil) }
}
struct CloudObjectStore: ObjectStore {
    let configuration: StorageConfiguration
    let credentials: CloudCredentials
    private let send: @Sendable (URLRequest) async throws -> (Data, Int)
    init(configuration: StorageConfiguration, credentials: CloudCredentials, transport: (@Sendable (URLRequest) async throws -> (Data, Int))? = nil) throws {
        try Self.validate(configuration, credentials: credentials)
        self.configuration = configuration; self.credentials = credentials
        let options = URLSessionConfiguration.ephemeral; options.timeoutIntervalForRequest = 30; options.timeoutIntervalForResource = 60
        options.urlCache = nil; options.httpCookieStorage = nil
        let session = URLSession(configuration: options, delegate: NoRedirect(), delegateQueue: nil)
        send = transport ?? { request in
            let (data, response) = try await session.data(for: request)
            guard let response = response as? HTTPURLResponse else { throw VaultError.network("无效 HTTP 响应") }
            return (data, response.statusCode)
        }
    }
    static func validate(_ config: StorageConfiguration, credentials: CloudCredentials) throws {
        let valid = CharacterSet(charactersIn: "abcdefghijklmnopqrstuvwxyz0123456789-")
        guard config.kind != .local, !config.bucket.isEmpty, !config.region.isEmpty,
              config.bucket.rangeOfCharacter(from: valid.inverted) == nil, config.region.rangeOfCharacter(from: valid.inverted) == nil,
              !credentials.accessKeyID.isEmpty, !credentials.secretKey.isEmpty,
              !credentials.accessKeyID.contains("\n"), !(credentials.securityToken?.contains("\n") ?? false),
              !config.prefix.hasPrefix("/"), !config.prefix.split(separator: "/").contains(where: { $0 == ".." || $0 == "." }) else { throw VaultError.invalidConfiguration("请检查云存储区域、存储桶、前缀和访问密钥。") }
    }
    var host: String {
        configuration.kind == .oss ? "\(configuration.bucket).oss-\(configuration.region).aliyuncs.com" : "\(configuration.bucket).cos.\(configuration.region).myqcloud.com"
    }
    func request(method: String, key: String, query: [String: String] = [:], body: Data? = nil, createOnly: Bool = false) throws -> URLRequest {
        var parts = URLComponents(); parts.scheme = "https"; parts.host = host
        parts.percentEncodedPath = "/" + CloudSigner.encode(key, slash: true)
        if !query.isEmpty { parts.percentEncodedQuery = CloudSigner.queryString(query) }
        guard let url = parts.url else { throw VaultError.invalidConfiguration("存储地址无效。") }
        var request = URLRequest(url: url); request.httpMethod = method; request.httpBody = body
        var headers = ["host": host]
        if body != nil { headers["content-type"] = "application/octet-stream" }
        if createOnly { headers[configuration.kind == .oss ? "x-oss-forbid-overwrite" : "x-cos-forbid-overwrite"] = "true" }
        if configuration.kind == .oss {
            let formatter = DateFormatter(); formatter.locale = Locale(identifier: "en_US_POSIX"); formatter.timeZone = TimeZone(secondsFromGMT: 0); formatter.dateFormat = "yyyyMMdd'T'HHmmss'Z'"
            let stamp = formatter.string(from: Date()); headers["x-oss-date"] = stamp; headers["x-oss-content-sha256"] = "UNSIGNED-PAYLOAD"
            headers["x-oss-security-token"] = credentials.securityToken
            headers["authorization"] = CloudSigner.ossAuthorization(method: method, resource: "/\(configuration.bucket)/\(key)", query: query, headers: headers, credentials: credentials, region: configuration.region, timestamp: stamp)
        } else {
            headers["x-cos-security-token"] = credentials.securityToken
            let start = Int(Date().timeIntervalSince1970) - 60; let time = "\(start);\(start + 900)"
            headers["authorization"] = CloudSigner.cosAuthorization(method: method, path: "/" + key, query: query, headers: headers, credentials: credentials, keyTime: time)
        }
        for (key, value) in headers { request.setValue(value, forHTTPHeaderField: key) }
        return request
    }
    private func perform(_ request: URLRequest) async throws -> (Data, Int) {
        do {
            let (data, status) = try await send(request)
            guard data.count <= VaultCrypto.maxBytes + 76 else { throw VaultError.corrupt("云文件过大") }
            return (data, status)
        } catch let error as VaultError { throw error }
        catch { throw VaultError.network(error.localizedDescription) }
    }
    func get(_ key: String) async throws -> Data? {
        let (bytes, code) = try await perform(request(method: "GET", key: key))
        if code == 404 { return nil }
        guard (200...299).contains(code) else { throw VaultError.network("HTTP \(code)") }
        return bytes
    }
    func put(_ data: Data, key: String, createOnly: Bool) async throws {
        if createOnly {
            if try await get(key) != nil { throw VaultError.targetExists }
            // Both providers ignore forbid-overwrite after bucket versioning has ever been enabled.
            // Refuse that unsupported bucket state rather than risk replacing the fixed descriptor.
            let (xml, code) = try await perform(request(method: "GET", key: "", query: ["versioning": ""]))
            guard (200...299).contains(code) else { throw VaultError.network("无法检查存储桶版本控制（HTTP \(code)）；需要 GetBucketVersioning 权限。") }
            let delegate = VersioningXML(); let parser = XMLParser(data: xml)
            parser.shouldResolveExternalEntities = false; parser.delegate = delegate
            guard parser.parse(), delegate.root == "VersioningConfiguration" else { throw VaultError.corrupt("存储桶版本控制响应无效") }
            guard delegate.status == nil || delegate.status == "" else { throw VaultError.invalidConfiguration("此保险库需要从未开启版本控制的存储桶，以保证云对象不会被覆盖。") }
        }
        let (_, code) = try await perform(request(method: "PUT", key: key, body: data, createOnly: createOnly))
        if code == 409 || code == 412 { throw VaultError.targetExists }
        guard (200...299).contains(code) else { throw VaultError.network("HTTP \(code)") }
    }
    func list(prefix: String) async throws -> [String] {
        var result: Set<String> = []; var cursor: String?; var seen: Set<String> = []
        repeat {
            var query = ["prefix": prefix, "max-keys": "1000"]
            if configuration.kind == .oss { query["list-type"] = "2"; query["continuation-token"] = cursor }
            else { query["marker"] = cursor }
            let (bytes, code) = try await perform(request(method: "GET", key: "", query: query))
            guard (200...299).contains(code) else { throw VaultError.network("HTTP \(code)") }
            let page = try ObjectListPage.parse(bytes, kind: configuration.kind)
            result.formUnion(page.keys); cursor = page.next
            if let cursor, !seen.insert(cursor).inserted { throw VaultError.corrupt("分页标记重复") }
        } while cursor != nil
        return result.sorted()
    }
}
