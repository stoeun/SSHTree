import CryptoKit
import Foundation
import HarborKit

@MainActor
private final class Report {
    var failures = 0

    func check(_ condition: @autoclosure () -> Bool, _ message: String, file: StaticString = #filePath, line: UInt = #line) {
        if !condition() {
            failures += 1
            print("FAIL \(file):\(line) \(message)")
        }
    }

    func checkEqual<T: Equatable>(_ actual: T, _ expected: T, file: StaticString = #filePath, line: UInt = #line) {
        if actual != expected {
            failures += 1
            print("FAIL \(file):\(line)")
            print("  expected: \(expected)")
            print("  actual:   \(actual)")
        }
    }

    func checkThrows(_ body: () throws -> Void, file: StaticString = #filePath, line: UInt = #line) {
        do {
            try body()
            failures += 1
            print("FAIL \(file):\(line) expected an error")
        } catch {}
    }
}

private func exampleDate() -> Date {
    var components = DateComponents()
    components.calendar = Calendar(identifier: .gregorian)
    components.timeZone = TimeZone(secondsFromGMT: 0)
    components.year = 2025
    components.month = 4
    components.day = 11
    components.hour = 6
    components.minute = 41
    components.second = 24
    guard let date = components.date else {
        fatalError("example date")
    }
    return date
}

private extension SHA256.Digest {
    var hex: String { map { String(format: "%02x", Int($0)) }.joined() }
}

@MainActor
private func testSigner(_ report: Report) {
    let signed = OSSSigner.sign(OSSSignInput(
        method: "PUT",
        bucket: "examplebucket",
        objectKey: "exampleobject",
        region: "cn-hangzhou",
        accessKeyID: "LTAI5tTest",
        accessKeySecret: "yourAccessKeySecret",
        date: exampleDate(),
        headers: [
            "content-disposition": "attachment",
            "content-length": "3",
            "content-md5": "ICy5YqxZB1uWSwcVLSNLcA==",
            "content-type": "text/plain"
        ],
        additionalHeaders: ["content-disposition", "content-length"]
    ))
    report.checkEqual(signed.timestamp, "20250411T064124Z")
    report.check(signed.canonicalRequest.hasPrefix("PUT\n/examplebucket/exampleobject\n\n"), "canonical prefix")
    report.checkEqual(SHA256.hash(data: Data(signed.canonicalRequest.utf8)).hex, "c46d96390bdbc2d739ac9363293ae9d710b14e48081fcb22cd8ad54b63136eca")
    report.checkEqual(signed.signature, "d3694c2dfc5371ee6acd35e88c4871ac95a7ba01d3a2f476768fe61218590097")
    report.checkEqual(
        signed.authorization,
        "OSS4-HMAC-SHA256 Credential=LTAI5tTest/20250411/cn-hangzhou/oss/aliyun_v4_request, Signature=d3694c2dfc5371ee6acd35e88c4871ac95a7ba01d3a2f476768fe61218590097, AdditionalHeaders=content-disposition;content-length"
    )

    let empty = OSSSigner.sign(OSSSignInput(
        method: "PUT",
        bucket: "examplebucket",
        objectKey: "harbor/connections.vault",
        region: "cn-hangzhou",
        accessKeyID: "LTAI5tTest",
        accessKeySecret: "yourAccessKeySecret",
        date: exampleDate(),
        headers: [
            "content-type": "application/octet-stream",
            "x-oss-meta-harbor-revision": "11111111-1111-1111-1111-111111111111",
            "x-oss-meta-harbor-updated-at": "2025-04-11T06:41:24Z"
        ]
    ))
    report.checkEqual(SHA256.hash(data: Data(empty.canonicalRequest.utf8)).hex, "d85b1f82929a94b35aabb01cfd1d629684abacb9d9516067d647409313b5cb82")
    report.checkEqual(empty.signature, "d648b332c56c82c3afbad875db538f6677006590fe5efe6b0852b03409800ad2")
    report.check(!empty.authorization.contains("AdditionalHeaders"), "empty additional headers stay out of Authorization")
    report.checkEqual(OSSSigner.encodeURI("/examplebucket/a b/中"), "/examplebucket/a%20b/%E4%B8%AD")
    report.checkEqual(OSSEndpoint.normalizeEndpoint(" https://oss-cn-beijing.aliyuncs.com/ ", region: "cn-hangzhou"), "oss-cn-beijing.aliyuncs.com")
    report.checkEqual(OSSEndpoint.normalizeEndpoint("", region: "cn-shanghai"), "oss-cn-shanghai.aliyuncs.com")
    report.checkEqual(OSSEndpoint.normalizeKey("/harbor/connections.vault"), "harbor/connections.vault")
    report.checkEqual(OSSEndpoint.host(bucket: "demo", endpoint: "oss-cn-hangzhou.aliyuncs.com"), "demo.oss-cn-hangzhou.aliyuncs.com")
    report.checkEqual(OSSEndpoint.host(bucket: "demo", endpoint: "demo.oss-cn-hangzhou.aliyuncs.com"), "demo.oss-cn-hangzhou.aliyuncs.com")
}

@MainActor
private func testCrypto(_ report: Report) throws {
    let stamp = Date(timeIntervalSince1970: 1_700_000_000)
    let original = VaultDocument(
        revision: UUID(uuidString: "11111111-1111-1111-1111-111111111111")!,
        updatedAt: stamp,
        connections: [
            SSHConnection(
                name: "生产",
                host: "10.0.0.8",
                username: "root",
                auth: .password,
                password: "secret",
                createdAt: stamp,
                updatedAt: stamp
            )
        ]
    )
    let sealed = try VaultCrypto.sealCloud(original, passphrase: "正确口令", iterations: 2_000)
    let opened = try VaultCrypto.openCloud(sealed, passphrase: "正确口令")
    report.checkEqual(opened, original)
    report.checkThrows { try VaultCrypto.openCloud(sealed, passphrase: "错误口令") }

    let key = SymmetricKey(size: .bits256)
    let local = VaultDocument(connections: [SSHConnection(name: "跳板", host: "bastion.example", username: "ops", createdAt: stamp, updatedAt: stamp)])
    let localSealed = try VaultCrypto.sealLocal(local, key: key)
    let localOpened = try VaultCrypto.openLocal(localSealed, key: key)
    report.checkEqual(localOpened.connections.map(\.name), ["跳板"])
    report.checkThrows { try VaultCrypto.openLocal(localSealed, key: SymmetricKey(size: .bits256)) }
}

@MainActor
private func testLaunch(_ report: Report) throws {
    let connection = SSHConnection(
        name: "db",
        host: "db.internal",
        port: 2222,
        username: "root",
        auth: .password,
        password: "p@ss word",
        proxyJump: "ops@bastion"
    )
    let plan = try SSHLauncher.plan(for: connection, askpassPath: "/tmp/askpass", secretPath: "/tmp/secret")
    report.checkEqual(plan.executable, "/usr/bin/ssh")
    report.check(!plan.arguments.contains("p@ss word"), "password stays off argv")
    report.checkEqual(plan.secret, "p@ss word")
    report.checkEqual(plan.extraEnvironment["SSH_ASKPASS"], "/tmp/askpass")
    report.checkEqual(plan.extraEnvironment["SSH_ASKPASS_REQUIRE"], "force")
    report.checkEqual(plan.extraEnvironment["HARBOR_ASKPASS_FILE"], "/tmp/secret")
    report.check(plan.arguments.contains("2222"), "port")
    report.check(plan.arguments.contains("PubkeyAuthentication=no"), "password auth disables pubkey")
    guard let jumpIndex = plan.arguments.firstIndex(of: "-J") else {
        report.check(false, "missing -J")
        return
    }
    report.checkEqual(plan.arguments[jumpIndex + 1], "ops@bastion")
    report.checkEqual(plan.arguments.last, "root@db.internal")

    let key = try SSHLauncher.plan(
        for: SSHConnection(name: "web", host: "web", username: "deploy", auth: .publicKey, identityFile: "~/keys/id_ed25519", startupCommand: "cd /srv"),
        askpassPath: "/tmp/askpass",
        secretPath: "/tmp/secret"
    )
    report.check(key.arguments.contains("IdentitiesOnly=yes"), "identities only")
    report.check(key.arguments.contains { $0.hasSuffix("/keys/id_ed25519") }, "expanded identity path")
    report.checkEqual(key.arguments.last, "cd /srv; exec \"${SHELL:-/bin/bash}\" -l")
    report.check(key.secret == nil, "no passphrase means no secret")

    let agent = try SSHLauncher.plan(
        for: SSHConnection(name: "web", host: "web", username: "deploy", auth: .agent),
        askpassPath: "/tmp/askpass",
        secretPath: "/tmp/secret"
    )
    report.check(!agent.arguments.contains("IdentitiesOnly=yes"), "agent does not pin identities")
    report.check(agent.extraEnvironment.isEmpty, "agent has no askpass env")
    report.check(agent.secret == nil, "agent has no secret")

    let bad = SSHConnection(name: "bad", host: "-oProxyCommand=open", username: "root")
    report.check(bad.validationProblem != nil, "flag-like host is rejected")
    report.checkThrows { try SSHLauncher.plan(for: bad, askpassPath: "/tmp/a", secretPath: "/tmp/b") }
}

@MainActor
private func testConfig(_ report: Report) {
    let text = """
    # office
    Host web api
        HostName 10.0.0.5
        User deploy
        Port 2201
        IdentityFile "~/.ssh/id_ed25519"
        ProxyJump ops@bastion

    Host *
        User skipped

    Match host *.example
        User no

    Host quoted
        HostName "db.internal"
        IdentityFile "/Users/me/my key"
    """
    let hosts = SSHConfigParser.parse(text)
    report.checkEqual(hosts.map(\.alias), ["web", "api", "quoted"])
    report.checkEqual(hosts[0].hostName, "10.0.0.5")
    report.checkEqual(hosts[0].user, "deploy")
    report.checkEqual(hosts[0].port, 2201)
    report.checkEqual(hosts[0].identityFile, "~/.ssh/id_ed25519")
    report.checkEqual(hosts[0].proxyJump, "ops@bastion")
    report.checkEqual(hosts[2].hostName, "db.internal")
    report.checkEqual(hosts[2].identityFile, "/Users/me/my key")

    let imported = SSHConfigParser.connections(
        from: hosts,
        defaultUser: "me",
        existing: [SSHConnection(name: "old", host: "10.0.0.5", port: 2201, username: "deploy")]
    )
    report.checkEqual(imported.map(\.name), ["quoted"])
    report.checkEqual(imported[0].auth, .publicKey)
    report.checkEqual(imported[0].group, "SSH 配置")
}

@MainActor
private func testVault(_ report: Report) throws {
    let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
    defer { try? FileManager.default.removeItem(at: directory) }
    let vault = try LocalVault(directory: directory, key: SymmetricKey(size: .bits256))
    var document = VaultDocument(connections: [SSHConnection(name: "一", host: "h", username: "u")])
    try vault.save(document)
    report.checkEqual(try vault.load().connections.map(\.name), ["一"])
    document.connections[0].name = "二"
    try vault.save(document)
    report.checkEqual(try vault.load().connections.map(\.name), ["二"])
}

@main
@MainActor
enum HarborSelfTest {
    static func main() throws {
        let report = Report()
        testSigner(report)
        try testCrypto(report)
        try testLaunch(report)
        testConfig(report)
        try testVault(report)
        if report.failures != 0 {
            fputs("\(report.failures) failed\n", stderr)
            exit(1)
        }
        print("ok")
    }
}
