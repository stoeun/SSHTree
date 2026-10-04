import Foundation
import SSHTreeCore

// Only protocol data is written to stdout. Failures intentionally do not log
// prompt text, credentials, or an environment dump.
let environment = ProcessInfo.processInfo.environment
guard CommandLine.arguments.count == 2,
      let path = environment["SSHTREE_ASKPASS_SOCKET"],
      let owner = environment["SSHTREE_ASKPASS_OWNER_PID"].flatMap(Int32.init) else { exit(1) }
do {
    guard let response = try SSHAskPassClient.request(socketURL: URL(fileURLWithPath: path), ownerPID: owner, prompt: CommandLine.arguments[1], hint: environment["SSH_ASKPASS_PROMPT"]) else { exit(1) }
    guard !response.contains("\n"), !response.contains("\r"), !response.contains("\0") else { exit(1) }
    FileHandle.standardOutput.write(Data((response + "\n").utf8))
    exit(0)
} catch { exit(1) }
