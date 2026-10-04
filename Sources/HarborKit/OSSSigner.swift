import CryptoKit
import Foundation

public struct OSSSignInput: Sendable {
    public var method: String
    public var bucket: String
    public var objectKey: String
    public var region: String
    public var accessKeyID: String
    public var accessKeySecret: String
    public var date: Date
    public var headers: [String: String]
    public var additionalHeaders: [String]

    public init(
        method: String,
        bucket: String,
        objectKey: String,
        region: String,
        accessKeyID: String,
        accessKeySecret: String,
        date: Date,
        headers: [String: String] = [:],
        additionalHeaders: [String] = []
    ) {
        self.method = method
        self.bucket = bucket
        self.objectKey = objectKey
        self.region = region
        self.accessKeyID = accessKeyID
        self.accessKeySecret = accessKeySecret
        self.date = date
        self.headers = headers
        self.additionalHeaders = additionalHeaders
    }
}

public struct OSSSignature: Equatable, Sendable {
    public var canonicalRequest: String
    public var signature: String
    public var authorization: String
    public var timestamp: String
    public var headers: [String: String]
}

public enum OSSSigner {
    public static func sign(_ input: OSSSignInput) -> OSSSignature {
        let timestamp = timestampString(input.date)
        var headers: [String: String] = [:]
        for (key, value) in input.headers {
            headers[key.lowercased()] = value.trimmingCharacters(in: .whitespacesAndNewlines)
        }
        headers["x-oss-content-sha256"] = "UNSIGNED-PAYLOAD"
        headers["x-oss-date"] = timestamp

        let additional = Array(Set(input.additionalHeaders.map { $0.lowercased() }))
            .filter { name in
                headers[name] != nil && !name.hasPrefix("x-oss-") && name != "content-type" && name != "content-md5"
            }
            .sorted()
        let additionalJoined = additional.joined(separator: ";")
        let additionalSet = Set(additional)

        let canonicalHeaders = headers.keys.sorted().compactMap { name -> String? in
            let included = name.hasPrefix("x-oss-") || name == "content-type" || name == "content-md5" || additionalSet.contains(name)
            guard included, let value = headers[name] else { return nil }
            return "\(name):\(value)\n"
        }.joined()

        let canonicalURI = encodeURI("/\(input.bucket)/\(input.objectKey)")
        let canonicalRequest = input.method + "\n"
            + canonicalURI + "\n"
            + "\n"
            + canonicalHeaders + "\n"
            + additionalJoined + "\n"
            + "UNSIGNED-PAYLOAD"

        let scope = "\(String(timestamp.prefix(8)))/\(input.region)/oss/aliyun_v4_request"
        let hash = SHA256.hash(data: Data(canonicalRequest.utf8))
        let stringToSign = "OSS4-HMAC-SHA256\n\(timestamp)\n\(scope)\n\(hex(Data(hash)))"
        let signingKey = deriveSigningKey(secret: input.accessKeySecret, date: String(timestamp.prefix(8)), region: input.region)
        let signature = hex(hmac(signingKey, Data(stringToSign.utf8)))
        var authorization = "OSS4-HMAC-SHA256 Credential=\(input.accessKeyID)/\(scope), Signature=\(signature)"
        if !additionalJoined.isEmpty {
            authorization += ", AdditionalHeaders=\(additionalJoined)"
        }
        var outputHeaders = headers
        outputHeaders["authorization"] = authorization
        return OSSSignature(
            canonicalRequest: canonicalRequest,
            signature: signature,
            authorization: authorization,
            timestamp: timestamp,
            headers: outputHeaders
        )
    }

    /// Percent-encode each UTF-8 byte. Leave `/` and unreserved characters alone.
    /// The canonical URI includes the bucket, even when the HTTP path does not.
    public static func encodeURI(_ value: String) -> String {
        var output = ""
        for byte in value.utf8 {
            if byte == UInt8(ascii: "/") || isUnreserved(byte) {
                output.append(Character(UnicodeScalar(byte)))
            } else {
                output.append(String(format: "%%%02X", byte))
            }
        }
        return output
    }

    public static func timestampString(_ date: Date) -> String {
        let formatter = DateFormatter()
        formatter.calendar = Calendar(identifier: .gregorian)
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.timeZone = TimeZone(secondsFromGMT: 0)
        formatter.dateFormat = "yyyyMMdd'T'HHmmss'Z'"
        return formatter.string(from: date)
    }

    private static func deriveSigningKey(secret: String, date: String, region: String) -> Data {
        let dateKey = hmac(Data("aliyun_v4\(secret)".utf8), Data(date.utf8))
        let regionKey = hmac(dateKey, Data(region.utf8))
        let serviceKey = hmac(regionKey, Data("oss".utf8))
        return hmac(serviceKey, Data("aliyun_v4_request".utf8))
    }

    private static func hmac(_ key: Data, _ message: Data) -> Data {
        Data(HMAC<SHA256>.authenticationCode(for: message, using: SymmetricKey(data: key)))
    }

    private static func hex(_ data: Data) -> String {
        data.map { String(format: "%02x", $0) }.joined()
    }

    private static func isUnreserved(_ byte: UInt8) -> Bool {
        switch byte {
        case 48...57, 65...90, 97...122:
            return true
        case UInt8(ascii: "-"), UInt8(ascii: "_"), UInt8(ascii: "."), UInt8(ascii: "~"):
            return true
        default:
            return false
        }
    }
}

public enum OSSEndpoint {
    public static func normalizeEndpoint(_ raw: String, region: String) -> String {
        var host = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        if host.hasPrefix("https://") { host.removeFirst("https://".count) }
        if host.hasPrefix("http://") { host.removeFirst("http://".count) }
        while host.hasSuffix("/") { host.removeLast() }
        if let slash = host.firstIndex(of: "/") {
            host = String(host[..<slash])
        }
        if host.isEmpty {
            return "oss-\(region).aliyuncs.com"
        }
        return host
    }

    public static func normalizeKey(_ raw: String) -> String {
        var key = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        while key.hasPrefix("/") { key.removeFirst() }
        return key
    }

    public static func host(bucket: String, endpoint: String) -> String {
        if endpoint == bucket || endpoint.hasPrefix("\(bucket).") {
            return endpoint
        }
        return "\(bucket).\(endpoint)"
    }

    public static func url(bucket: String, endpoint: String, objectKey: String) -> URL? {
        let encoded = OSSSigner.encodeURI(objectKey)
        let host = host(bucket: bucket, endpoint: endpoint)
        return URL(string: "https://\(host)/\(encoded)")
    }
}
