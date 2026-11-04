import AppKit
import SwiftUI
import ZapretCore
import Darwin

struct ProbeResult: Identifiable {
    let id = UUID()
    let strategy: String
    let target: String
    let passed: Bool
    let detail: String
}

@MainActor final class AppModel: ObservableObject {
    @Published var selectedID = UserDefaults.standard.string(forKey: "packetStrategy") ?? "general" {
        didSet { UserDefaults.standard.set(selectedID, forKey: "packetStrategy") }
    }
    @Published var gameMode = UserDefaults.standard.bool(forKey: "gameMode") {
        didSet { UserDefaults.standard.set(gameMode, forKey: "gameMode") }
    }
    @Published var ipsetMode = UserDefaults.standard.string(forKey: "ipsetMode") ?? "none" {
        didSet { UserDefaults.standard.set(ipsetMode, forKey: "ipsetMode") }
    }
    var ownsSession = false
    @Published var connected = false
    @Published var busy = false
    @Published var testing = false
    @Published var status = "Ready · Flowseal packet engine"
    @Published var error: String?
    @Published var recovery = false
    @Published var results = [ProbeResult]()
    @Published var page = 0
    @Published var picker = false
    @Published var packetStatus: PacketStatus?
    @Published var profiles = [FlowsealProfile]()
    var testTask: Task<Void, Never>?
    var monitor: Timer?
    let resources: URL
    let support: URL
    let session: URL
    let uid = getuid()
    var binary: URL { resources.appendingPathComponent("zapret-packet") }
    var selected: FlowsealProfile? { profiles.first { $0.id == selectedID } ?? profiles.first }
    var selectedName: String { selected?.name ?? "No configs available" }

    init() {
        resources = Bundle.main.resourceURL ?? URL(fileURLWithPath: "Resources")
        support = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0].appendingPathComponent("ZapretMac")
        session = URL(fileURLWithPath: "/var/run/zapret-macos-\(getuid())")
        do {
            try FileManager.default.createDirectory(at: support, withIntermediateDirectories: true)
            profiles = try JSONDecoder().decode([FlowsealProfile].self, from: Data(contentsOf: resources.appendingPathComponent("flowseal/profiles.json")))
            // The earlier SOCKS-only version has its own recovery journal. Never
            // start a packet session on top of a stale loopback proxy.
            recovery = FileManager.default.fileExists(atPath: support.appendingPathComponent("proxy-recovery.json").path)
            if recovery { status = "Restore the earlier SOCKS session first" }
        } catch { self.error = error.localizedDescription }
        monitor = Timer.scheduledTimer(withTimeInterval: 1, repeats: true) { [weak self] _ in
            Task { @MainActor in
                guard let self else { return }
                if let current = self.readStatus() {
                    self.packetStatus = current
                    if current.state == "running" && current.gui == ProcessInfo.processInfo.processIdentifier {
                        self.connected = true; self.ownsSession = true
                    }
                    if self.connected && !self.busy && current.state != "running" {
                        self.connected = false; self.status = "Packet interception stopped"
                        if current.state == "cleanup-required" { self.recovery = true; self.error = current.reason }
                        if current.state == "error" { self.error = current.reason + "\nSee packet.log for details." }
                    }
                }
            }
        }
    }
    func readStatus() -> PacketStatus? {
        guard let data = try? Data(contentsOf: session.appendingPathComponent("status.json")) else { return nil }
        return try? JSONDecoder().decode(PacketStatus.self, from: data)
    }
    func start(_ profile: FlowsealProfile) async throws {
        let args = ["--mac-owner=\(uid):\(ProcessInfo.processInfo.processIdentifier)",
                    "--mac-tcp=\(profile.captureTCP(game: gameMode))", "--mac-udp=\(profile.captureUDP(game: gameMode))"] + profile.expanded(root: resources.appendingPathComponent("flowseal"), game: gameMode, ipsetMode: ipsetMode)
        let command = ([binary.path, "--mac-launch"] + args).map(Quoting.shell).joined(separator: " ")
        status = "Waiting for macOS authorization…"
        // Recovery touches only our own PF anchor and enable reference. The
        // daemon refuses an unsafe session directory or a concurrent instance.
        let script = "\(Quoting.shell(binary.path)) --mac-recover \(uid)\n\(command)"
        // On a first launch the root-owned directory does not exist yet. The
        // recover command creates it, without installing a persistent service.
        try await Commands.administrator(script)
        ownsSession = true
        status = "Opening PFLOG/BPF packet transport…"
        for _ in 0..<200 {
            try Task.checkCancellation()
            try await Task.sleep(nanoseconds: 100_000_000)
            if let current = readStatus() {
                packetStatus = current
                if current.state == "running" && current.gui == ProcessInfo.processInfo.processIdentifier { connected = true; status = "Packet engine active · \(current.interface)"; return }
                if current.state == "cleanup-required" { recovery = true; throw startupFailure(current.reason, reported: current) }
                if current.state == "error" { throw startupFailure(current.reason, reported: current) }
            }
            if launchProcessExited() { throw startupFailure("Packet engine exited during startup.") }
        }
        throw startupFailure("Packet transport did not become ready.")
    }
    func launchProcessExited() -> Bool {
        guard let text = try? String(contentsOf: session.appendingPathComponent("start.pid"), encoding: .utf8),
              let pid = Int32(text.trimmingCharacters(in: .whitespacesAndNewlines)), pid > 1 else { return false }
        return kill(pid, 0) != 0 && errno == ESRCH
    }
    func startupFailure(_ summary: String, reported: PacketStatus? = nil) -> ZapretError {
        let logURL = session.appendingPathComponent("packet.log")
        var detail = ""
        if let handle = try? FileHandle(forReadingFrom: logURL) {
            defer { try? handle.close() }
            if let end = try? handle.seekToEnd() {
                try? handle.seek(toOffset: end > 4096 ? end - 4096 : 0)
                let bytes = handle.readData(ofLength: 4096)
                detail = String(decoding: bytes, as: UTF8.self).components(separatedBy: .newlines)
                    .filter { !$0.trimmingCharacters(in: .whitespaces).isEmpty }.suffix(10).joined(separator: "\n")
            }
        }
        return .message(StartupDiagnostics.format(summary: summary, stage: reported?.stage,
            detail: reported?.detail, errorCode: reported?.errorCode, logTail: detail, logPath: logURL.path))
    }
    func stop() async throws {
        if let current = readStatus(), ["stopped", "error"].contains(current.state) {
            connected = false; ownsSession = false; return
        }
        _ = try await Commands.run(binary.path, ["--mac-stop", String(uid)])
        for _ in 0..<100 {
            // Stop is always allowed to finish, including after test cancellation.
            await withCheckedContinuation { continuation in
                DispatchQueue.main.asyncAfter(deadline: .now() + 0.1) { continuation.resume() }
            }
            if let current = readStatus(), current.state != "running" && current.state != "starting" {
                packetStatus = current; connected = false; ownsSession = false; status = "Ready · Flowseal packet engine"; return
            }
        }
        throw ZapretError.message("The packet session has not confirmed cleanup. Keep the app open and retry Disconnect.")
    }
    func connect() async {
        guard !busy, !connected, !recovery, let profile = selected else { return }
        busy = true; error = nil; defer { busy = false }
        do { try await start(profile) }
        catch {
            self.error = error.localizedDescription
            // A startup timeout must not leave a privileged background session.
            if ownsSession { try? await stop() }; status = "Connection stopped"
        }
    }
    func disconnect() async {
        guard !busy else { return }; busy = true; defer { busy = false }
        do { try await stop() } catch { self.error = error.localizedDescription }
    }
    func recover() async {
        guard !busy else { return }; busy = true; defer { busy = false }
        do {
            let journalURL = support.appendingPathComponent("proxy-recovery.json")
            if !FileManager.default.fileExists(atPath: journalURL.path) {
                try await Commands.administrator(Quoting.shell(binary.path) + " --mac-recover " + String(uid))
                guard readStatus()?.state == "stopped" else { throw ZapretError.message("PF cleanup could not be verified.") }
                recovery = false; status = "Packet session restored"; return
            }
            let journal = try JSONDecoder().decode(RecoveryJournal.self, from: Data(contentsOf: journalURL))
            let current = try await ProxySnapshot(service: journal.original.service, output: Commands.run("/usr/sbin/networksetup", ["-getsocksfirewallproxy", journal.original.service]))
            guard current == journal.original || current.isOwned(port: journal.port) else { throw ZapretError.message("SOCKS settings changed externally. Restore the saved settings manually before removing proxy-recovery.json.") }
            if current != journal.original { try await Commands.administrator(journal.original.restoreCommands()) }
            let verified = try await ProxySnapshot(service: journal.original.service, output: Commands.run("/usr/sbin/networksetup", ["-getsocksfirewallproxy", journal.original.service]))
            guard verified == journal.original else { throw ZapretError.message("SOCKS restoration could not be verified.") }
            try FileManager.default.removeItem(at: journalURL); recovery = false; status = "Ready · Flowseal packet engine"
        } catch { self.error = error.localizedDescription }
    }
    func probe(name: String) async {
        for (label, url) in [("YouTube", "https://www.youtube.com/"), ("Discord", "https://discord.com/api/v10/gateway")] {
            if Task.isCancelled { return }
            let before = readStatus()
            let args = ["--silent", "--show-error", "--location", "--max-redirs", "3", "--connect-timeout", "4", "--max-time", "8", "--noproxy", "*", "--output", "/dev/null", "--write-out", "%{http_code} · %{time_total}s", url]
            do {
                let text = try await Commands.run("/usr/bin/curl", args)
                let code = Int(text.prefix(3)) ?? 0
                let after = readStatus()
                let observed = (after?.emitted ?? 0) > (before?.emitted ?? 0)
                results.append(.init(strategy: name, target: label, passed: (200..<400).contains(code), detail: text + (connected ? " · packet activity \(observed ? "observed" : "not yet observed")" : "")))
            } catch { results.append(.init(strategy: name, target: label, passed: false, detail: error.localizedDescription)) }
        }
    }
    func runTests(all: Bool) {
        guard !busy, !connected, !recovery, let selected else { return }
        busy = true; testing = true; results = []; error = nil; page = 1
        testTask = Task {
            defer { busy = false; testing = false; status = Task.isCancelled ? "Tests cancelled" : "Tests finished"; testTask = nil }
            await probe(name: "Direct baseline")
            var best: (String, Int)?
            for profile in all ? profiles : [selected] {
                if Task.isCancelled { break }
                do {
                    try await start(profile)
                    status = "Testing \(profile.name)…"
                    let first = results.count; await probe(name: profile.name)
                    let score = results.dropFirst(first).filter(\.passed).count
                    if best == nil || score > best!.1 { best = (profile.id, score) }
                    try await stop()
                } catch {
                    self.error = error.localizedDescription
                    if ownsSession { do { try await stop() } catch { self.error = error.localizedDescription; break } }
                    // Setup failures are not silently replaced by a proxy profile.
                    break
                }
            }
            if all, !Task.isCancelled, let best, best.1 > 0 { selectedID = best.0 }
        }
    }
    func exportReport() {
        let panel = NSSavePanel(); panel.nameFieldStringValue = "zapret-packet-diagnostics.txt"
        if panel.runModal() == .OK, let url = panel.url {
            let text = "Zapret macOS 0.2.2 · \(Date())\nFlowseal original profiles, original zapret desync engine, PFLOG/BPF transport.\nHTTP success does not verify ISP bypass or Discord voice.\n\n" + results.map { "\($0.strategy) | \($0.target) | \($0.passed ? "PASS" : "FAIL") | \($0.detail)" }.joined(separator: "\n")
            do { try text.write(to: url, atomically: true, encoding: .utf8) } catch { self.error = error.localizedDescription }
        }
    }
}
