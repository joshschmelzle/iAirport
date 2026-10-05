import Foundation

public enum Notifier {
    public static func post(title: String, message: String, enabled: Bool) {
        guard enabled else { return }
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/osascript")
        let escapedMessage = message.replacingOccurrences(of: "\\", with: "\\\\").replacingOccurrences(of: "\"", with: "\\\"")
        let escapedTitle = title.replacingOccurrences(of: "\\", with: "\\\\").replacingOccurrences(of: "\"", with: "\\\"")
        process.arguments = ["-e", "display notification \"\(escapedMessage)\" with title \"\(escapedTitle)\""]
        process.standardOutput = Pipe()
        process.standardError = Pipe()
        try? process.run()
    }
}
