import AppKit
import SwiftUI
import CoreText
import ZapretCore

@MainActor final class AppDelegate: NSObject, NSApplicationDelegate {
    weak var model: AppModel?
    var quitting = false
    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        guard !quitting, let model else { return .terminateNow }
        if model.busy {
            model.error = "Wait for the current operation to finish before quitting. Tests can be cancelled from the Tests tab."
            return .terminateCancel
        }
        guard model.connected || model.recovery else { return .terminateNow }
        Task {
            await model.disconnect()
            if !model.recovery && !model.connected { quitting = true; NSApp.reply(toApplicationShouldTerminate: true) }
            else { NSApp.reply(toApplicationShouldTerminate: false) }
        }
        return .terminateLater
    }
    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { false }
}

@main struct ZapretMacApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) var delegate
    @StateObject private var model = AppModel()
    init() {
        if let font = Bundle.main.url(forResource: "pt-root-ui_vf", withExtension: "ttf") {
            CTFontManagerRegisterFontsForURL(font as CFURL, .process, nil)
        }
    }
    var body: some Scene {
        WindowGroup("zapret") {
            MainView(model: model).onAppear { delegate.model = model }
                .frame(minWidth: 390, idealWidth: 420, maxWidth: 620, minHeight: 650, idealHeight: 740)
                .preferredColorScheme(.dark)
        }.windowStyle(.hiddenTitleBar).defaultSize(width: 420, height: 740)
        .commands {
            CommandGroup(replacing: .newItem) {}
        }
        MenuBarExtra("Zapret", systemImage: model.connected ? "bolt.shield.fill" : "bolt.shield") {
            Text(model.status)
            Button("Show Zapret") { NSApp.activate(ignoringOtherApps: true); NSApp.windows.first { $0.canBecomeMain }?.makeKeyAndOrderFront(nil) }
            Button(model.connected ? "Disconnect" : "Connect") { Task { if model.connected { await model.disconnect() } else { await model.connect() } } }.disabled(model.busy || (model.recovery && !model.connected))
            Divider()
            Button("Quit") { NSApp.terminate(nil) }
        }
    }
}

private let accent = Color(red: 1, green: 0.68, blue: 0.35)
private let appBackground = Color(red: 0.043, green: 0.043, blue: 0.051)
private let card = Color(red: 0.105, green: 0.11, blue: 0.125)

struct MainView: View {
    @ObservedObject var model: AppModel
    var body: some View {
        VStack(spacing: 0) {
            HStack {
                Text("zapret").font(.system(size: 25, weight: .semibold))
                Spacer()
                Text("macOS · packets").font(.system(size: 12)).foregroundColor(.secondary)
            }.padding(.horizontal, 26).padding(.top, 28).padding(.bottom, 18)
            if model.recovery && !model.connected {
                VStack(alignment: .leading, spacing: 10) {
                    Label("Restore a previous session", systemImage: "exclamationmark.arrow.triangle.2.circlepath").foregroundColor(accent)
                    Text("Saved network settings need recovery before connecting again.").font(.caption).foregroundColor(.secondary)
                    Button("Restore network settings") { Task { await model.recover() } }.disabled(model.busy)
                }.padding(16).frame(maxWidth: .infinity, alignment: .leading).background(card).cornerRadius(12).padding(.horizontal, 20)
            }
            Group {
                if model.page == 0 { home }
                else if model.page == 1 { tests }
                else { settings }
            }.frame(maxWidth: .infinity, maxHeight: .infinity)
            Text(model.status).font(.system(size: 11)).foregroundColor(.secondary).lineLimit(2).padding(.horizontal, 20).padding(.vertical, 10)
            HStack {
                navigation("house", title: "Connection", page: 0)
                Spacer()
                navigation("point.3.connected.trianglepath.dotted", title: "Tests", page: 1)
                Spacer()
                navigation("gearshape", title: "Settings", page: 2)
            }.padding(.horizontal, 46).padding(.vertical, 17).background(card)
        }
        .background(appBackground).tint(accent)
        .alert("Zapret", isPresented: Binding(get: { model.error != nil }, set: { if !$0 { model.error = nil } })) {
            Button("OK") { model.error = nil }
            Button("Copy error") {
                let text = model.error ?? ""
                NSPasteboard.general.clearContents()
                NSPasteboard.general.setString(text, forType: .string)
            }
            Button("Open log") { NSWorkspace.shared.open(model.session.appendingPathComponent("packet.log")) }
        } message: { Text(model.error ?? "") }
        .sheet(isPresented: $model.picker) { strategyPicker }
    }
    func navigation(_ icon: String, title: String, page: Int) -> some View {
        Button { model.page = page } label: {
            Image(systemName: icon).font(.system(size: 24, weight: .regular)).foregroundColor(model.page == page ? accent : .secondary).frame(width: 48, height: 30)
        }.buttonStyle(.plain).help(title).accessibilityLabel(title)
    }
    var home: some View {
        VStack(spacing: 0) {
            Spacer(minLength: 20)
            Button {
                Task { if model.connected { await model.disconnect() } else { await model.connect() } }
            } label: {
                ZStack {
                    Circle().fill(Color.white.opacity(0.025))
                    Circle().stroke(model.connected ? accent : Color.gray, lineWidth: 3)
                    if model.busy { ProgressView().controlSize(.large).tint(accent) }
                    else {
                        VStack(spacing: 12) {
                            if model.connected { Image(systemName: "power").font(.system(size: 30)) }
                            Text(model.connected ? "Disconnect" : "Connect").font(.system(size: 20, weight: .semibold))
                        }.foregroundColor(model.connected ? accent : Color(red: 0.75, green: 0.75, blue: 0.79))
                    }
                }.frame(width: 212, height: 212).shadow(color: model.connected ? accent.opacity(0.10) : .clear, radius: 18)
            }.buttonStyle(.plain).disabled(model.busy || (model.recovery && !model.connected)).accessibilityLabel(model.connected ? "Disconnect" : "Connect")
            Text(model.connected ? "Packet interception is active" : "Ready to start").font(.system(size: 13)).foregroundColor(.secondary).padding(.top, 20)
            Spacer(minLength: 25)
            HStack {
                Toggle("Game mode", isOn: $model.gameMode).toggleStyle(.switch).font(.system(size: 14))
                    .disabled(model.busy || model.connected || model.recovery)
            }.padding(.horizontal, 28).padding(.bottom, 15)
            VStack(spacing: 20) {
                Capsule().fill(Color.gray.opacity(0.4)).frame(width: 30, height: 3)
                Button { model.picker = true } label: {
                    HStack { Spacer(); Text(model.selectedName).font(.system(size: 20, weight: .medium)); Spacer(); Image(systemName: "chevron.up").font(.caption).foregroundColor(.secondary) }
                }.buttonStyle(.plain).disabled(model.busy || model.connected || model.recovery)
                Button { model.runTests(all: true) } label: {
                    HStack { Spacer(); Text("Find a strategy").fontWeight(.semibold); Image(systemName: "arrow.right"); Spacer() }.padding(.vertical, 13).foregroundColor(.black).background(accent).cornerRadius(9)
                }.buttonStyle(.plain).disabled(model.busy || model.connected || model.recovery)
            }.padding(.horizontal, 24).padding(.top, 13).padding(.bottom, 20).background(card).clipShape(RoundedRectangle(cornerRadius: 18))
        }
    }
    @State private var search = ""
    var strategyPicker: some View {
        VStack(alignment: .leading, spacing: 20) {
            HStack { Text("Choose a strategy").font(.title2.bold()); Spacer(); Button("Done") { model.picker = false } }
            TextField("Search strategies", text: $search).textFieldStyle(.roundedBorder)
            ScrollView { VStack(spacing: 10) {
            ForEach(model.profiles.filter { search.isEmpty || $0.name.localizedCaseInsensitiveContains(search) }) { s in
                Button { model.selectedID = s.id } label: {
                    HStack {
                        VStack(alignment: .leading, spacing: 7) { Text(s.name).font(.headline); Text(s.methods).font(.caption).foregroundColor(.secondary) }
                        Spacer()
                        if model.selectedID == s.id { Image(systemName: "checkmark.circle.fill").foregroundColor(accent) }
                    }.padding(14).frame(maxWidth: .infinity, alignment: .leading).background(model.selectedID == s.id ? accent.opacity(0.10) : card).cornerRadius(10)
                }.buttonStyle(.plain)
            }
            } }
            Text("Original Flowseal profiles. Matching, fake payloads, sequence overlaps, repeats and fooling use the original zapret packet engine.").font(.caption).foregroundColor(.secondary)
            Spacer()
        }.padding(24).frame(width: 370, height: 510).background(appBackground).preferredColorScheme(.dark)
    }
    var tests: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 18) {
                Text("Connection tests").font(.system(size: 26, weight: .semibold))
                Text("Compare direct HTTPS access with the original Flowseal profiles. Tests temporarily apply packet interception and request macOS administrator authorization.").font(.system(size: 14)).foregroundColor(.secondary)
                HStack {
                    Button("Test selected") { model.runTests(all: false) }.disabled(model.busy || model.connected || model.recovery)
                    Button("Auto-select") { model.runTests(all: true) }.disabled(model.busy || model.connected || model.recovery)
                    if model.testing { Button("Cancel") { model.testTask?.cancel() } }
                }.buttonStyle(.bordered)
                if model.testing { ProgressView().frame(maxWidth: .infinity) }
                if model.results.isEmpty {
                    VStack(spacing: 14) {
                        Image(systemName: "network").font(.system(size: 36)).foregroundColor(accent)
                        Text("Find what works on your network").font(.headline)
                        Text("Disconnect before testing. Each profile tests YouTube and Discord. A pass through all 22 configs can take several minutes. Packet counters include other application traffic.").font(.caption).foregroundColor(.secondary).multilineTextAlignment(.center)
                    }.padding(25).frame(maxWidth: .infinity).background(card).cornerRadius(12)
                }
                ForEach(model.results) { r in
                    HStack(alignment: .top) {
                        Image(systemName: r.passed ? "checkmark.circle" : "xmark.circle").foregroundColor(r.passed ? .green : .orange)
                        VStack(alignment: .leading, spacing: 5) {
                            Text(r.target).font(.headline)
                            Text(r.strategy).font(.caption).foregroundColor(accent)
                            Text(r.detail).font(.caption).foregroundColor(.secondary).textSelection(.enabled)
                        }
                        Spacer()
                    }.padding(14).frame(maxWidth: .infinity, alignment: .leading).background(card).cornerRadius(10)
                }
                Text("A successful HTTP request does not verify video playback, Discord sign-in, voice, or DPI bypass. Auto-select chooses the profile with the most successful requests; confirm it in your apps.").font(.caption).foregroundColor(.secondary)
                Button("Export report…") { model.exportReport() }.disabled(model.results.isEmpty || model.testing)
            }.padding(24)
        }
    }
    var settings: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 18) {
                Text("Settings").font(.system(size: 26, weight: .semibold))
                VStack(alignment: .leading, spacing: 12) {
                    Label("Flowseal packet engine", systemImage: "network")
                    Text("22 original configs · original zapret C methods · bundled fake payloads and include/exclude lists. Administrator authorization is required to capture, suppress, and emit packets.").font(.caption).foregroundColor(.secondary)
                    Text("TCP + UDP · IPv4 + IPv6").font(.caption).foregroundColor(accent)
                    Toggle("Game mode · ports 1024–65535", isOn: $model.gameMode)
                        .disabled(model.busy || model.connected || model.recovery)
                    Picker("IPSet", selection: $model.ipsetMode) {
                        Text("Disabled · upstream sentinel").tag("none")
                        Text("Loaded · bundled IP ranges").tag("loaded")
                        Text("Any · no IP restriction").tag("any")
                    }.disabled(model.busy || model.connected || model.recovery)
                    Text("Disabled mode preserves Flowseal’s port-12 sentinel. Changing this setting changes both capture windows and game profiles.").font(.caption).foregroundColor(.secondary)
                }.padding(16).background(card).cornerRadius(12)
                if let current = model.packetStatus {
                    VStack(alignment: .leading, spacing: 9) {
                        Text("Packet transport").font(.headline)
                        Text("State: \(current.state) · interface: \(current.interface)")
                        Text("Captured \(current.packets) · emitted \(current.emitted)")
                        Text("Suppressed originals \(current.suppressed) · errors \(current.errors)")
                        if !current.reason.isEmpty { Text(current.reason).foregroundColor(.orange) }
                    }.font(.caption).padding(16).frame(maxWidth: .infinity, alignment: .leading).background(card).cornerRadius(12)
                }
                VStack(alignment: .leading, spacing: 10) {
                    Label("Network requirements", systemImage: "info.circle")
                    Text("Uses PFLOG and BPF on an Ethernet-compatible physical uplink, including supported Wi-Fi interfaces. The active PF ruleset must include Apple’s wildcard anchor. Conflicting VPN routes, unsupported link types, capture overflow or uplink changes stop the session. No SOCKS fallback is used.").font(.caption).foregroundColor(.secondary)
                    Text("Existing connections may need restarting. No DNS or hosts changes are made. Packet-method parity does not guarantee bypass on a particular ISP.").font(.caption).foregroundColor(.secondary)
                }.padding(16).background(card).cornerRadius(12)
                HStack {
                    Button("Packet logs") { NSWorkspace.shared.open(model.session) }
                    Button("Licenses") { NSWorkspace.shared.open(model.resources.appendingPathComponent("Licenses")) }
                }
                Text("Zapret macOS 0.2.2\nSwiftUI interface adapted from trankesh\nFlowseal configs · bol-van packet methods\nExperimental PFLOG/BPF transport; live operation requires validation on your Mac.").font(.caption).foregroundColor(.secondary)
            }.padding(24)
        }
    }
}
