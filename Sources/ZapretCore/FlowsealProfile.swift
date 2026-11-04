import Foundation

public struct FlowsealProfile: Codable, Identifiable, Equatable {
    public let id: String
    public let name: String
    public let source: String
    public let sha256: String
    public let tcp: String
    public let udp: String
    public let arguments: [String]
    public var methods: String {
        let modes = arguments.filter { $0.hasPrefix("--dpi-desync=") }.map { String($0.dropFirst(13)) }
        return Array(Set(modes)).sorted().joined(separator: " · ")
    }
    public func expanded(root: URL, game: Bool, ipsetMode: String = "none") -> [String] {
        arguments.map {
            let arg = expand($0, root: root, game: game)
            let original = "--ipset=" + root.appendingPathComponent("lists/ipset-all.txt").path
            if arg == original && ["loaded", "any"].contains(ipsetMode) {
                return "--ipset=" + root.appendingPathComponent("lists/ipset-all.\(ipsetMode).txt").path
            }
            return arg
        }
    }
    public func captureTCP(game: Bool) -> String { expand(tcp, root: URL(fileURLWithPath: "/"), game: game) }
    public func captureUDP(game: Bool) -> String { expand(udp, root: URL(fileURLWithPath: "/"), game: game) }
    private func expand(_ text: String, root: URL, game: Bool) -> String {
        text.replacingOccurrences(of: "{ROOT}", with: root.path)
            .replacingOccurrences(of: "%GameFilterTCP%", with: game ? "1024-65535" : "12")
            .replacingOccurrences(of: "%GameFilterUDP%", with: game ? "1024-65535" : "12")
    }
}
public struct PacketStatus: Decodable {
    public let state: String
    public let reason: String
    public let pid: Int
    public let gui: Int
    public let interface: String
    public let ipv4: Bool
    public let ipv6: Bool
    public let packets: UInt64
    public let emitted: UInt64
    public let suppressed: UInt64
    public let errors: UInt64
    public let overflow: UInt64
    public let stage: String?
    public let detail: String?
    public let errorCode: Int?
    private enum CodingKeys: String, CodingKey {
        case state, reason, pid, gui, interface, ipv4, ipv6, packets, emitted, suppressed, errors, overflow, stage, detail
        case errorCode = "error_code"
    }
}
