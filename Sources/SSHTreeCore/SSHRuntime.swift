import Foundation
import Darwin

/// The directory name stays short enough for Darwin's Unix-domain socket limit.
public final class SSHRuntimeDirectory: @unchecked Sendable {
    public let directoryURL: URL
    public var controlSocketURL: URL { directoryURL.appendingPathComponent("control") }
    public var askpassSocketURL: URL { directoryURL.appendingPathComponent("askpass") }
    public private(set) var privateKeyURL: URL?
    private let lock = NSLock()
    private var removed = false

    public init(rootDirectory: URL = URL(fileURLWithPath: "/tmp", isDirectory: true)) throws {
        var template = Array(rootDirectory.appendingPathComponent("sshtree-\(getuid())-XXXXXX").path.utf8CString)
        let path = template.withUnsafeMutableBufferPointer { buffer -> String? in
            guard let pointer = buffer.baseAddress, mkdtemp(pointer) != nil else { return nil }
            return String(cString: pointer)
        }
        guard let path else { throw SSHError.system("创建会话目录失败", errno) }
        directoryURL = URL(fileURLWithPath: path, isDirectory: true)
        do {
            guard chmod(directoryURL.path, 0o700) == 0 else { throw SSHError.system("设置会话目录权限失败", errno) }
            try Self.createFile(Data("SSHTree-runtime-v1\n\(getpid())\n".utf8), at: directoryURL.appendingPathComponent("owner"))
        } catch {
            try? FileManager.default.removeItem(at: directoryURL)
            throw error
        }
    }

    public func materializePrivateKey(_ data: Data) throws -> URL {
        lock.lock(); defer { lock.unlock() }
        guard !removed, !data.isEmpty, data.count <= 1_048_576 else { throw SSHError.invalid("私钥文件为空或过大。") }
        let url = directoryURL.appendingPathComponent("identity")
        try Self.createFile(data, at: url)
        privateKeyURL = url
        return url
    }

    public func removePrivateKey() {
        lock.lock(); defer { lock.unlock() }
        if let url = privateKeyURL { try? FileManager.default.removeItem(at: url) }
        privateKeyURL = nil
    }

    public func cleanup() {
        lock.lock(); defer { lock.unlock() }
        guard !removed else { return }
        removed = true
        try? FileManager.default.removeItem(at: directoryURL)
        privateKeyURL = nil
    }

    deinit { cleanup() }

    /// Only our marker-bearing, user-owned directories with a dead owner are
    /// removed. Closing the crashed app's PTY also hangs up its ssh process.
    public static func cleanupStale(in root: URL = URL(fileURLWithPath: "/tmp", isDirectory: true)) {
        let prefix = "sshtree-\(getuid())-"
        guard let entries = try? FileManager.default.contentsOfDirectory(at: root, includingPropertiesForKeys: nil) else { return }
        for url in entries where url.lastPathComponent.hasPrefix(prefix) {
            var info = stat()
            guard lstat(url.path, &info) == 0, info.st_uid == getuid(), info.st_mode & S_IFMT == S_IFDIR, info.st_mode & 0o777 == 0o700 else { continue }
            let markerURL = url.appendingPathComponent("owner")
            guard lstat(markerURL.path, &info) == 0, info.st_uid == getuid(), info.st_mode & S_IFMT == S_IFREG, info.st_mode & 0o777 == 0o600,
                  info.st_size < 128, let marker = try? String(contentsOf: markerURL, encoding: .utf8) else { continue }
            let lines = marker.split(separator: "\n")
            guard lines.count == 2, lines[0] == "SSHTree-runtime-v1", let pid = Int32(lines[1]), pid > 0 else { continue }
            if kill(pid, 0) == -1 && errno == ESRCH { try? FileManager.default.removeItem(at: url) }
        }
    }

    private static func createFile(_ data: Data, at url: URL) throws {
        let fd = open(url.path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard fd >= 0 else { throw SSHError.system("创建会话文件失败", errno) }
        defer { Darwin.close(fd) }
        do {
            try data.withUnsafeBytes { bytes in
                var offset = 0
                while offset < bytes.count {
                    let count = Darwin.write(fd, bytes.baseAddress!.advanced(by: offset), bytes.count - offset)
                    if count < 0 && errno == EINTR { continue }
                    guard count > 0 else { throw SSHError.system("写入会话文件失败", errno) }
                    offset += count
                }
            }
        } catch {
            unlink(url.path)
            throw error
        }
    }
}

public struct SSHProcessExit: Sendable, Equatable {
    public let exitCode: Int32?
    public let signal: Int32?
    public init(waitStatus: Int32) {
        let lowBits = waitStatus & 0x7f
        exitCode = lowBits == 0 ? (waitStatus >> 8) & 0xff : nil
        signal = lowBits == 0 ? nil : lowBits
    }
}
