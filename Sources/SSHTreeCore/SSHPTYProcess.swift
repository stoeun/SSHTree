import Foundation
import Darwin

/// A real controlling terminal, with one owner responsible for closing its FD,
/// signalling its process group, and reaping the child exactly once. SwiftTerm
/// renders bytes; this object deliberately owns process lifetime separately.
public final class SSHPTYProcess: @unchecked Sendable {
    public let pid: pid_t
    private let queue = DispatchQueue(label: "app.sshtree.pty", qos: .userInitiated)
    private var descriptor: Int32
    private var reader: DispatchSourceRead?
    private var monitor: DispatchSourceProcess?
    private var exited = false
    private var closing = false
    private let lifetimeLock = NSLock()
    private var hasReaped = false
    private var terminationRequested = false
    private var pendingInput = Data()
    private let onOutput: @Sendable (Data) -> Void
    private let onExit: @Sendable (SSHProcessExit) -> Void

    public init(executable: String, arguments: [String], environment: [String], columns: Int, rows: Int,
                onOutput: @escaping @Sendable (Data) -> Void, onExit: @escaping @Sendable (SSHProcessExit) -> Void) throws {
        guard !executable.contains("\0"), !(arguments + environment).contains(where: { $0.contains("\0") }) else { throw SSHError.invalid("进程参数包含无效字符。") }
        // All strings and pointer arrays are allocated before fork. The child
        // performs only async-signal-safe libc calls and never returns to Swift.
        let argvStrings = ([executable] + arguments).map { strdup($0)! }
        let envStrings = environment.map { strdup($0)! }
        let executableCString = strdup(executable)!
        let argv = UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>.allocate(capacity: argvStrings.count + 1)
        let env = UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>.allocate(capacity: envStrings.count + 1)
        for (index, value) in argvStrings.enumerated() { argv[index] = value }; argv[argvStrings.count] = nil
        for (index, value) in envStrings.enumerated() { env[index] = value }; env[envStrings.count] = nil
        defer { argvStrings.forEach { free($0) }; envStrings.forEach { free($0) }; free(executableCString); argv.deallocate(); env.deallocate() }
        var fd: Int32 = -1
        var size = Self.windowSize(columns: columns, rows: rows)
        var emptySignalMask: sigset_t = 0
        _ = sigemptyset(&emptySignalMask)
        var defaultSignalAction = sigaction()
        defaultSignalAction.__sigaction_u.__sa_handler = SIG_DFL
        _ = sigemptyset(&defaultSignalAction.sa_mask)
        let child = forkpty(&fd, nil, nil, &size)
        if child == 0 {
            // Swift concurrency/XCTest worker threads may block SIGTERM. exec
            // preserves the mask and ignored dispositions; reset them here so
            // ssh has ordinary shell signal behaviour and closes gracefully.
            _ = sigaction(SIGTERM, &defaultSignalAction, nil)
            _ = sigaction(SIGINT, &defaultSignalAction, nil)
            _ = sigaction(SIGHUP, &defaultSignalAction, nil)
            _ = sigaction(SIGQUIT, &defaultSignalAction, nil)
            _ = sigaction(SIGPIPE, &defaultSignalAction, nil)
            _ = sigprocmask(SIG_SETMASK, &emptySignalMask, nil)
            _ = execve(executableCString, argv, env)
            _exit(127)
        }
        guard child > 0 else { throw SSHError.system("启动终端失败", errno) }
        pid = child; descriptor = fd; self.onOutput = onOutput; self.onExit = onExit
        _ = fcntl(fd, F_SETFD, FD_CLOEXEC)
        _ = fcntl(fd, F_SETFL, O_NONBLOCK)
        let source = DispatchSource.makeReadSource(fileDescriptor: fd, queue: queue)
        reader = source
        source.setEventHandler { [weak self] in self?.drainOutput() }
        let fdToClose = fd
        source.setCancelHandler { Darwin.close(fdToClose) }
        // The exit monitor retains the owner until reaping/cleanup completes,
        // even if a closing tab releases its TerminalSession immediately.
        let exitSource = DispatchSource.makeProcessSource(identifier: child, eventMask: .exit, queue: queue)
        monitor = exitSource
        exitSource.setEventHandler { self.reap() }
        source.resume(); exitSource.resume()
    }

    public func send(_ bytes: Data) {
        queue.async {
            guard !self.exited, !self.closing, self.descriptor >= 0 else { return }
            self.pendingInput.append(bytes)
            self.flushInput()
        }
    }

    public func resize(columns: Int, rows: Int) {
        queue.async {
            guard !self.exited, self.descriptor >= 0 else { return }
            var size = Self.windowSize(columns: columns, rows: rows)
            _ = ioctl(self.descriptor, TIOCSWINSZ, &size)
        }
    }

    public func close() {
        lifetimeLock.lock()
        guard !hasReaped, !terminationRequested else { lifetimeLock.unlock(); return }
        terminationRequested = true
        // The parent can return from forkpty before the child has established
        // its process group. In that small interval kill(-pid) returns ESRCH;
        // signal the still-owned child directly instead of waiting 1.5 seconds.
        if kill(-pid, SIGTERM) == -1 && errno == ESRCH { _ = kill(pid, SIGTERM) }
        lifetimeLock.unlock()
        queue.async {
            guard !self.exited, !self.closing else { return }
            self.closing = true
            self.pendingInput.removeAll()
        }
        // Keep escalation independent of rendering/backpressure, including
        // when the main window is closing. Reaping and signalling share a
        // lock so a released/reused PID is never signalled by a late timer.
        DispatchQueue.global(qos: .userInitiated).asyncAfter(deadline: .now() + 1.5) {
            self.lifetimeLock.lock(); defer { self.lifetimeLock.unlock() }
            guard !self.hasReaped else { return }
            if kill(-self.pid, SIGKILL) == -1 && errno == ESRCH { _ = kill(self.pid, SIGKILL) }
        }
    }

    private func flushInput() {
        guard !pendingInput.isEmpty, !exited, descriptor >= 0 else { return }
        let sent = pendingInput.withUnsafeBytes { Darwin.write(descriptor, $0.baseAddress!, $0.count) }
        if sent > 0 { pendingInput.removeFirst(sent) }
        if !pendingInput.isEmpty, sent >= 0 || errno == EAGAIN || errno == EINTR {
            queue.asyncAfter(deadline: .now() + 0.01) { self.flushInput() }
        } else if sent < 0 { pendingInput.removeAll() }
    }

    private func drainOutput(maximumBytes: Int = 128 * 1024) {
        guard descriptor >= 0 else { return }
        var buffer = [UInt8](repeating: 0, count: 32_768)
        var consumed = 0
        // Yield the serial queue after a bounded batch. A continuously noisy
        // child must not prevent queued keyboard input or resize requests.
        while consumed < maximumBytes {
            let count = Darwin.read(descriptor, &buffer, min(buffer.count, maximumBytes - consumed))
            if count > 0 { consumed += count; onOutput(Data(buffer.prefix(count))); continue }
            if count < 0 && errno == EINTR { continue }
            if count == 0 || (count < 0 && errno != EAGAIN) {
                reader?.cancel(); reader = nil
                descriptor = -1
            }
            return
        }
    }

    private func reap() {
        guard !exited else { return }
        var status: Int32 = 0
        var result: pid_t
        lifetimeLock.lock()
        repeat { result = waitpid(pid, &status, WNOHANG) } while result < 0 && errno == EINTR
        if result != 0 { hasReaped = true }
        lifetimeLock.unlock()
        if result == 0 { queue.asyncAfter(deadline: .now() + 0.01) { self.reap() }; return }
        // Drain bytes already buffered by the kernel before delivering exit.
        // A generous final batch drains the bounded kernel backlog while
        // still allowing cleanup if an orphaned descendant keeps writing.
        drainOutput(maximumBytes: 1024 * 1024)
        exited = true
        reader?.cancel(); reader = nil
        monitor?.cancel(); monitor = nil
        descriptor = -1
        onExit(SSHProcessExit(waitStatus: result == pid ? status : 127 << 8))
    }

    private static func windowSize(columns: Int, rows: Int) -> winsize {
        winsize(ws_row: UInt16(clamping: max(1, rows)), ws_col: UInt16(clamping: max(1, columns)), ws_xpixel: 0, ws_ypixel: 0)
    }
}
