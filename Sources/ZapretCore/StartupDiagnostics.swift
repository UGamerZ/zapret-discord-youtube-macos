import Foundation

public enum StartupDiagnostics {
    public static func format(summary: String, stage: String? = nil, detail: String? = nil,
                              errorCode: Int? = nil, logTail: String = "", logPath: String) -> String {
        func bounded(_ text: String, _ limit: Int) -> String {
            text.count > limit ? String(text.prefix(limit)) + "…" : text
        }
        var parts = [bounded(summary, 300)]
        if let stage, !stage.isEmpty { parts.append("Stage: " + bounded(stage, 80)) }
        if let errorCode, errorCode != 0 { parts.append("Error code: \(errorCode)") }
        let reported = (detail ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
        if !reported.isEmpty {
            parts.append(bounded(reported.components(separatedBy: .newlines).suffix(6).joined(separator: "\n"), 700))
        } else {
            let errors = logTail.components(separatedBy: .newlines).filter { line in
                let text = line.trimmingCharacters(in: .whitespaces).lowercased()
                if text.hasPrefix("loading ") || text.hasPrefix("loaded ") { return false }
                return text.hasPrefix("error [") || text.hasPrefix("cannot ") || text.hasPrefix("failed ") ||
                    text.hasPrefix("nohup:") || text.contains(": error:") || text.hasPrefix("pcap ")
            }
            if errors.isEmpty { parts.append("The engine did not report an additional error detail.") }
            else { parts.append(bounded(errors.suffix(3).joined(separator: "\n"), 700)) }
        }
        parts.append("Log: " + logPath)
        return parts.joined(separator: "\n\n")
    }
}
