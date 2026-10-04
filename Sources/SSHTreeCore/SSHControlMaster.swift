import Foundation
import Darwin

public enum SSHControlMasterProbe {
    /// Call off-main. Socket existence and child spawning are insufficient;
    /// exit zero requires ssh's complete mux hello + alive-response exchange.
    public static func check(arguments: [String]) -> Bool {
        let child = Process()
        child.executableURL = URL(fileURLWithPath: "/usr/bin/ssh")
        child.arguments = arguments
        child.standardInput = FileHandle.nullDevice
        child.standardOutput = FileHandle.nullDevice
        child.standardError = FileHandle.nullDevice
        let exited = DispatchSemaphore(value: 0)
        child.terminationHandler = { _ in exited.signal() }
        do { try child.run() } catch { return false }
        if exited.wait(timeout: .now() + 1) == .timedOut {
            child.terminate()
            if exited.wait(timeout: .now() + 0.2) == .timedOut { kill(child.processIdentifier, SIGKILL) }
            child.waitUntilExit()
            return false
        }
        child.waitUntilExit()
        return child.terminationReason == .exit && child.terminationStatus == 0
    }
}
