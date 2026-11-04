import Foundation

public enum ZapretError: LocalizedError {
    case message(String)
    public var errorDescription: String? { if case .message(let s) = self { return s }; return nil }
}

public enum Quoting {
    public static func shell(_ s: String) -> String { "'" + s.replacingOccurrences(of: "'", with: "'\\''") + "'" }
    public static func appleScript(_ s: String) -> String {
        "\"" + s.replacingOccurrences(of: "\\", with: "\\\\").replacingOccurrences(of: "\"", with: "\\\"").replacingOccurrences(of: "\n", with: "\\n") + "\""
    }
}

public struct ProxySnapshot: Codable, Equatable {
    public let service: String
    public let enabled: Bool
    public let server: String
    public let port: Int
    public let authenticated: Bool
    public init(service: String, output: String) throws {
        var fields = [String: String]()
        for line in output.components(separatedBy: .newlines) {
            if let colon = line.firstIndex(of: ":") {
                fields[String(line[..<colon])] = String(line[line.index(after: colon)...]).trimmingCharacters(in: .whitespaces)
            }
        }
        guard let state = fields["Enabled"], ["Yes", "No"].contains(state),
              let server = fields["Server"], let portText = fields["Port"], let port = Int(portText),
              let auth = fields["Authenticated Proxy Enabled"], ["0", "1", "Yes", "No"].contains(auth) else {
            throw ZapretError.message("Cannot read SOCKS settings for \(service). No network settings were changed.")
        }
        self.service = service; self.enabled = state == "Yes"; self.server = server; self.port = port
        self.authenticated = auth == "1" || auth == "Yes"
    }
    public func restoreCommands() -> String {
        let service = Quoting.shell(service)
        var commands = [String]()
        // networksetup uses an empty server and port 0 for an unconfigured service.
        if !server.isEmpty && server != "(null)" && port > 0 {
            commands.append("/usr/sbin/networksetup -setsocksfirewallproxy \(service) \(Quoting.shell(server)) \(port) off")
        } else {
            commands.append("/usr/sbin/networksetup -setsocksfirewallproxy \(service) '' 0 off")
        }
        commands.append("/usr/sbin/networksetup -setsocksfirewallproxystate \(service) \(enabled ? "on" : "off")")
        return commands.joined(separator: "\n")
    }
    public func isOwned(port: Int) -> Bool { enabled && server == "127.0.0.1" && self.port == port && !authenticated }
}

public struct RecoveryJournal: Codable {
    public let original: ProxySnapshot
    public let port: Int
    public init(original: ProxySnapshot, port: Int) { self.original = original; self.port = port }
}

public enum Commands {
    public static func run(_ executable: String, _ arguments: [String]) async throws -> String {
        try await withCheckedThrowingContinuation { continuation in
            DispatchQueue.global(qos: .userInitiated).async {
                do {
                    let p = Process(); p.executableURL = URL(fileURLWithPath: executable); p.arguments = arguments
                    var env = ProcessInfo.processInfo.environment; env["LC_ALL"] = "C"; p.environment = env
                    let pipe = Pipe(); p.standardOutput = pipe; p.standardError = pipe
                    try p.run()
                    let data = pipe.fileHandleForReading.readDataToEndOfFile(); p.waitUntilExit()
                    let text = String(decoding: data, as: UTF8.self)
                    guard p.terminationStatus == 0 else { throw ZapretError.message(text.isEmpty ? "\(executable) exited with \(p.terminationStatus)" : text) }
                    continuation.resume(returning: text)
                } catch { continuation.resume(throwing: error) }
            }
        }
    }
    public static func administrator(_ script: String) async throws {
        _ = try await run("/usr/bin/osascript", ["-e", "do shell script \(Quoting.appleScript("set -e\n" + script)) with administrator privileges"])
    }
}
