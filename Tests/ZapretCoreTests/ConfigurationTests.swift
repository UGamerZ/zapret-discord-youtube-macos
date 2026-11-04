import Foundation
import ZapretCore

final class ConfigurationTests {
    func testParseAndRoundTripRecovery() throws {
        let original = try ProxySnapshot(service: "Wi-Fi", output: "Enabled: Yes\nServer: proxy.example\nPort: 1080\nAuthenticated Proxy Enabled: 0\n")
        expectTrue(original.enabled)
        expectFalse(original.authenticated)
        let journal = RecoveryJournal(original: original, port: 50000)
        let decoded = try JSONDecoder().decode(RecoveryJournal.self, from: JSONEncoder().encode(journal))
        expectEqual(decoded.original, original)
        expectEqual(decoded.port, 50000)
        expectTrue(original.restoreCommands().contains("'proxy.example' 1080 off"))
        expectTrue(original.restoreCommands().hasSuffix("'Wi-Fi' on"))
    }
    func testRejectsUnknownNetworksetupOutput() {
        expectThrows(try ProxySnapshot(service: "missing", output: "not a recognized network service"))
        expectThrows(try ProxySnapshot(service: "Wi-Fi", output: "Enabled: Maybe\nServer: x\nPort: 10\nAuthenticated Proxy Enabled: 0"))
    }
    func testDisabledUnconfiguredProxy() throws {
        let state = try ProxySnapshot(service: "Ethernet", output: "Enabled: No\nServer: \nPort: 0\nAuthenticated Proxy Enabled: 0\n")
        expectFalse(state.enabled)
        expectTrue(state.restoreCommands().contains("'' 0 off"))
    }
    func testOwnershipAndAuthentication() throws {
        let owned = try ProxySnapshot(service: "Wi-Fi", output: "Enabled: Yes\nServer: 127.0.0.1\nPort: 50555\nAuthenticated Proxy Enabled: 0")
        expectTrue(owned.isOwned(port: 50555)); expectFalse(owned.isOwned(port: 50556))
        let auth = try ProxySnapshot(service: "Wi-Fi", output: "Enabled: Yes\nServer: 127.0.0.1\nPort: 50555\nAuthenticated Proxy Enabled: 1")
        expectTrue(auth.authenticated); expectFalse(auth.isOwned(port: 50555))
    }
    func testShellQuotingIsLiteral() async throws {
        let hostile = "Wi-Fi '; $(touch /tmp/zapret-should-never-exist) `id` \"\nsecond line"
        let result = try await Commands.run("/bin/sh", ["-c", "printf %s " + Quoting.shell(hostile)])
        expectEqual(result, hostile)
    }
    func testFlowsealProfilesAndGameExpansion() throws {
        let profiles = try JSONDecoder().decode([FlowsealProfile].self, from: Data(contentsOf: URL(fileURLWithPath: "Resources/flowseal/profiles.json")))
        expectEqual(profiles.count, 22)
        let general = profiles.first { $0.id == "general" }!
        expectTrue(general.methods.contains("multisplit"))
        expectTrue(general.expanded(root: URL(fileURLWithPath: "/path with spaces"), game: false).contains("--dpi-desync-split-seqovl=681"))
        expectTrue(general.expanded(root: URL(fileURLWithPath: "/path with spaces"), game: false).contains("--dpi-desync-split-seqovl-pattern=/path with spaces/bin/tls_clienthello_www_google_com.bin"))
        expectTrue(general.captureTCP(game: false).hasSuffix(",12"))
        expectTrue(general.captureUDP(game: true).hasSuffix(",1024-65535"))
        expectTrue(general.expanded(root: URL(fileURLWithPath: "/resources"), game: false, ipsetMode: "loaded").contains("--ipset=/resources/lists/ipset-all.loaded.txt"))
        expectTrue(general.expanded(root: URL(fileURLWithPath: "/resources"), game: false, ipsetMode: "any").contains("--ipset=/resources/lists/ipset-all.any.txt"))
        for p in profiles { expectFalse(p.expanded(root: URL(fileURLWithPath: "/resources"), game: true).contains { $0.contains("%") || $0.contains("{ROOT}") }) }
    }

    func testStartupErrorsAreActionableAndCompact() {
        let loading = "Loading hostlist /very/long/path\nLoaded 59 hosts from /very/long/path\nloading plain text list"
        let message = StartupDiagnostics.format(summary: "Cannot compile capture filter.", stage: "capture.filter-compile",
            detail: "inbound/outbound not supported on Ethernet", logTail: loading, logPath: "/var/run/zapret/packet.log")
        expectTrue(message.contains("inbound/outbound not supported on Ethernet"))
        expectTrue(message.contains("Stage: capture.filter-compile"))
        expectFalse(message.contains("Loaded 59"))
        expectTrue(message.count < 300)
        let missing = StartupDiagnostics.format(summary: "Setup failed", logTail: loading, logPath: "packet.log")
        expectFalse(missing.contains("Loading hostlist"))
        expectTrue(missing.contains("did not report"))
        let fallback = StartupDiagnostics.format(summary: "Exited", logTail: loading + "\nERROR [capture]: Failed to open device\n", logPath: "packet.log")
        expectTrue(fallback.contains("Failed to open device"))
        let large = StartupDiagnostics.format(summary: "Failed", detail: String(repeating: "x", count: 20000), logPath: "packet.log")
        expectTrue(large.count < 800)
    }

}

func expectTrue(_ value: Bool) { precondition(value, "Expected true") }
func expectFalse(_ value: Bool) { precondition(!value, "Expected false") }
func expectEqual<T: Equatable>(_ a: T, _ b: T) { precondition(a == b, "Values differ: \(a) / \(b)") }
func expectGreater(_ a: Int, _ b: Int) { precondition(a > b) }
func expectThrows(_ expression: @autoclosure () throws -> Any) {
    do { _ = try expression() } catch { return }
    preconditionFailure("Expected an error")
}
@main struct Checks {
    static func main() async throws {
        let t = ConfigurationTests()
        try t.testParseAndRoundTripRecovery()
        t.testRejectsUnknownNetworksetupOutput()
        try t.testDisabledUnconfiguredProxy()
        try t.testOwnershipAndAuthentication()
        try await t.testShellQuotingIsLiteral()
        try t.testFlowsealProfilesAndGameExpansion()
        t.testStartupErrorsAreActionableAndCompact()
        print("PASS: 7 core checks (including concise structured startup errors)")
    }
}
