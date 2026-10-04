import Foundation
import Darwin

public struct SSHAskPassQuery: Codable, Sendable {
    public let id: UUID
    public let prompt: String
    public let hint: String?
    public init(id: UUID = UUID(), prompt: String, hint: String?) { self.id = id; self.prompt = prompt; self.hint = hint }
}

private struct SSHAskPassResponse: Codable { let id: UUID; let value: String? }

/// Peer UID, process ancestry, and the bundled helper's executable path are
/// checked before a request can reach stored credentials. No capability or
/// credential is transported in the environment; only paths and the app PID.
public final class SSHAskPassServer: @unchecked Sendable {
    public typealias Handler = @Sendable (SSHAskPassQuery, @escaping @Sendable (String?) -> Void) -> Void
    private let socketURL: URL
    private let handler: Handler
    private let source: DispatchSourceRead
    private let lock = NSLock()
    private var started = false
    private var stopped = false
    private var ancestorPID: pid_t = 0
    private var helperExecutablePath: String?
    private var clients: [UUID: SSHAskPassConnection] = [:]

    public init(socketURL: URL, handler: @escaping Handler) throws {
        self.socketURL = socketURL; self.handler = handler
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else { throw SSHError.system("创建认证 socket 失败", errno) }
        do {
            _ = fcntl(fd, F_SETFD, FD_CLOEXEC)
            try SSHSocket.bind(fd, path: socketURL.path)
            guard chmod(socketURL.path, 0o600) == 0, listen(fd, 8) == 0 else { throw SSHError.system("监听认证 socket 失败", errno) }
            _ = fcntl(fd, F_SETFL, O_NONBLOCK)
        } catch { Darwin.close(fd); unlink(socketURL.path); throw error }
        source = DispatchSource.makeReadSource(fileDescriptor: fd, queue: DispatchQueue(label: "app.sshtree.askpass.accept"))
        source.setCancelHandler { Darwin.close(fd) }
        source.setEventHandler { [weak self] in self?.acceptRequests(fd) }
    }

    public func start(ancestorPID: pid_t, helperExecutablePath: String?) {
        lock.lock(); defer { lock.unlock() }
        guard !started, !stopped else { return }
        self.ancestorPID = ancestorPID
        self.helperExecutablePath = helperExecutablePath.map { URL(fileURLWithPath: $0).resolvingSymlinksInPath().path }
        started = true
        source.resume()
    }

    public func stop() {
        lock.lock()
        guard !stopped else { lock.unlock(); return }
        stopped = true
        let pending = Array(clients.values); clients.removeAll()
        let mustResume = !started
        lock.unlock()
        source.cancel()
        if mustResume { source.resume() }
        unlink(socketURL.path)
        for connection in pending { connection.cancel() }
    }

    deinit { stop() }

    private func acceptRequests(_ listener: Int32) {
        while true {
            let fd = accept(listener, nil, nil)
            if fd < 0 { if errno == EINTR { continue }; return }
            SSHSocket.configure(fd, timeout: 3)
            let connection = SSHAskPassConnection(fd: fd)
            lock.lock()
            let ancestor = ancestorPID, executable = helperExecutablePath
            let accepted = !stopped && clients.count < 8
            if accepted { clients[connection.id] = connection }
            lock.unlock()
            guard accepted else { connection.cancel(); connection.finishReading(); continue }
            DispatchQueue.global(qos: .userInitiated).async { [weak self] in
                guard let self else { connection.cancel(); connection.finishReading(); return }
                defer { connection.finishReading() }
                do {
                    guard SSHSocket.peerUID(fd) == getuid(), let peer = SSHSocket.peerPID(fd),
                          SSHSocket.isDescendant(peer, of: ancestor),
                          executable == nil || SSHSocket.executablePath(peer) == executable else { throw SSHError.protocolFailure }
                    let query = try JSONDecoder().decode(SSHAskPassQuery.self, from: SSHSocket.readFrame(fd))
                    guard !query.prompt.isEmpty, query.prompt.utf8.count <= 32_768, !query.prompt.contains("\0"), connection.finishReading() else { throw SSHError.protocolFailure }
                    self.handler(query) { [weak self] value in
                        let server = self
                        DispatchQueue.global(qos: .userInitiated).async {
                            connection.respond(SSHAskPassResponse(id: query.id, value: value))
                            server?.remove(connection.id)
                        }
                    }
                } catch { connection.cancel(); self.remove(connection.id) }
            }
        }
    }

    private func remove(_ id: UUID) { lock.lock(); clients.removeValue(forKey: id); lock.unlock() }
}

public enum SSHAskPassClient {
    /// A nil result is explicit cancellation. Transport failure must also be
    /// treated as cancellation by the helper, never as an empty password.
    public static func request(socketURL: URL, ownerPID: pid_t, prompt: String, hint: String?) throws -> String? {
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else { throw SSHError.system("连接认证 socket 失败", errno) }
        defer { Darwin.close(fd) }
        SSHSocket.configure(fd, timeout: 300)
        try SSHSocket.connect(fd, path: socketURL.path)
        guard SSHSocket.peerUID(fd) == getuid(), SSHSocket.peerPID(fd) == ownerPID else { throw SSHError.protocolFailure }
        let query = SSHAskPassQuery(prompt: prompt, hint: hint)
        try SSHSocket.writeFrame(try JSONEncoder().encode(query), fd: fd)
        let response = try JSONDecoder().decode(SSHAskPassResponse.self, from: SSHSocket.readFrame(fd))
        guard response.id == query.id else { throw SSHError.protocolFailure }
        return response.value
    }
}

private final class SSHAskPassConnection: @unchecked Sendable {
    let id = UUID()
    private var fd: Int32
    private let lock = NSLock()
    private var reading = true
    private var finished = false
    init(fd: Int32) { self.fd = fd }
    deinit { if fd >= 0 { Darwin.close(fd) } }

    @discardableResult func finishReading() -> Bool {
        lock.lock(); defer { lock.unlock() }
        reading = false
        if finished { closeDescriptor() }
        return !finished
    }

    func respond(_ response: SSHAskPassResponse) {
        lock.lock(); defer { lock.unlock() }
        guard !finished else { return }
        finished = true
        if let data = try? JSONEncoder().encode(response) { try? SSHSocket.writeFrame(data, fd: fd) }
        closeDescriptor()
    }

    func cancel() {
        lock.lock(); defer { lock.unlock() }
        guard !finished else { return }
        finished = true
        if fd >= 0 { _ = shutdown(fd, SHUT_RDWR) }
        if !reading { closeDescriptor() }
    }

    private func closeDescriptor() {
        if fd >= 0 { _ = shutdown(fd, SHUT_RDWR); Darwin.close(fd); fd = -1 }
    }
}

private enum SSHSocket {
    static let maximumFrameLength = 65_536

    static func configure(_ fd: Int32, timeout: Int) {
        // Darwin accept inherits O_NONBLOCK from the listener. Each worker
        // reads complete bounded frames, so clear it here and use the socket
        // deadline; otherwise a client whose first write has not arrived yet
        // is intermittently rejected with EAGAIN.
        let flags = fcntl(fd, F_GETFL)
        if flags >= 0 { _ = fcntl(fd, F_SETFL, flags & ~O_NONBLOCK) }
        _ = fcntl(fd, F_SETFD, FD_CLOEXEC)
        var enabled: Int32 = 1
        _ = setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &enabled, socklen_t(MemoryLayout<Int32>.size))
        var interval = timeval(tv_sec: timeout, tv_usec: 0)
        _ = setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &interval, socklen_t(MemoryLayout<timeval>.size))
        _ = setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &interval, socklen_t(MemoryLayout<timeval>.size))
    }

    static func withAddress<T>(_ path: String, operation: (UnsafePointer<sockaddr>, socklen_t) throws -> T) throws -> T {
        var address = sockaddr_un()
        let bytes = Array(path.utf8CString)
        guard !path.contains("\0"), bytes.count <= MemoryLayout.size(ofValue: address.sun_path) else { throw SSHError.invalid("认证 socket 路径过长。") }
        address.sun_family = sa_family_t(AF_UNIX)
        address.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)
        withUnsafeMutableBytes(of: &address.sun_path) { target in
            bytes.withUnsafeBytes { target.copyBytes(from: $0) }
        }
        return try withUnsafePointer(to: &address) { pointer in
            try pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { try operation($0, socklen_t(MemoryLayout<sockaddr_un>.size)) }
        }
    }

    static func bind(_ fd: Int32, path: String) throws {
        try withAddress(path) { address, size in guard Darwin.bind(fd, address, size) == 0 else { throw SSHError.system("绑定认证 socket 失败", errno) } }
    }
    static func connect(_ fd: Int32, path: String) throws {
        try withAddress(path) { address, size in guard Darwin.connect(fd, address, size) == 0 else { throw SSHError.system("连接认证 socket 失败", errno) } }
    }

    static func peerUID(_ fd: Int32) -> uid_t? {
        var uid: uid_t = 0, gid: gid_t = 0
        return getpeereid(fd, &uid, &gid) == 0 ? uid : nil
    }
    static func peerPID(_ fd: Int32) -> pid_t? {
        var pid: pid_t = 0, size = socklen_t(MemoryLayout<pid_t>.size)
        return getsockopt(fd, SOL_LOCAL, LOCAL_PEERPID, &pid, &size) == 0 ? pid : nil
    }
    static func isDescendant(_ pid: pid_t, of ancestor: pid_t) -> Bool {
        guard ancestor > 0 else { return false }
        var current = pid
        for _ in 0..<32 {
            if current == ancestor { return true }
            var info = proc_bsdinfo()
            guard current > 1, proc_pidinfo(current, PROC_PIDTBSDINFO, 0, &info, Int32(MemoryLayout<proc_bsdinfo>.size)) == MemoryLayout<proc_bsdinfo>.size else { return false }
            current = pid_t(info.pbi_ppid)
        }
        return false
    }
    static func executablePath(_ pid: pid_t) -> String? {
        // PROC_PIDPATHINFO_MAXSIZE is a C expression macro not imported by
        // Swift; Darwin defines it as 4 * MAXPATHLEN.
        var bytes = [CChar](repeating: 0, count: 4 * Int(MAXPATHLEN))
        guard proc_pidpath(pid, &bytes, UInt32(bytes.count)) > 0 else { return nil }
        let path = String(decoding: bytes.prefix { $0 != 0 }.map { UInt8(bitPattern: $0) }, as: UTF8.self)
        return URL(fileURLWithPath: path).resolvingSymlinksInPath().path
    }

    static func readFrame(_ fd: Int32) throws -> Data {
        let header = try readExactly(fd, count: 4)
        let length = header.reduce(0) { ($0 << 8) | Int($1) }
        guard length > 0, length <= maximumFrameLength else { throw SSHError.protocolFailure }
        return try readExactly(fd, count: length)
    }
    static func readExactly(_ fd: Int32, count: Int) throws -> Data {
        var data = Data(count: count)
        try data.withUnsafeMutableBytes { bytes in
            var offset = 0
            while offset < count {
                let received = Darwin.read(fd, bytes.baseAddress!.advanced(by: offset), count - offset)
                if received < 0 && errno == EINTR { continue }
                guard received > 0 else { throw SSHError.protocolFailure }
                offset += received
            }
        }
        return data
    }
    static func writeFrame(_ data: Data, fd: Int32) throws {
        guard !data.isEmpty, data.count <= maximumFrameLength else { throw SSHError.protocolFailure }
        let length = UInt32(data.count)
        var frame = Data([UInt8((length >> 24) & 255), UInt8((length >> 16) & 255), UInt8((length >> 8) & 255), UInt8(length & 255)])
        frame.append(data)
        try frame.withUnsafeBytes { bytes in
            var offset = 0
            while offset < bytes.count {
                let sent = Darwin.write(fd, bytes.baseAddress!.advanced(by: offset), bytes.count - offset)
                if sent < 0 && errno == EINTR { continue }
                guard sent > 0 else { throw SSHError.protocolFailure }
                offset += sent
            }
        }
    }
}
