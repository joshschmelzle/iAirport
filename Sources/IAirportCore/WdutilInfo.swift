import Foundation
import Darwin

public struct WdutilMetrics: Equatable {
    public var rssi: Int?
    public var noise: Int?
    public var txRate: Double?
    public var phy: String?
    public var mcs: Int?
    public var nss: Int?
    public var guardIntervalNS: Int?
    public var channel: String?
    public var cca: Int?
    public var security: String?
    public var ssid: String?
    public var bssid: String?

    public init() {}
}

public enum WdutilInfo {
    public enum Privilege: Equatable {
        case direct
        case sudo
        case helper
        case unavailable

        public var description: String {
            switch self {
            case .direct: return "wdutil fields: running as root"
            case .sudo: return "wdutil fields: sudo -n available"
            case .helper: return "wdutil fields: root helper from sudo iairport"
            case .unavailable: return "wdutil fields: unavailable (run sudo iairport or sudo -v first)"
            }
        }
    }

    public static func parseInfo(_ text: String) -> WdutilMetrics {
        var metrics = WdutilMetrics()
        for line in text.split(separator: "\n") {
            guard let separator = line.firstIndex(of: ":") else { continue }
            let key = line[..<separator].trimmingCharacters(in: .whitespaces)
            let value = line[line.index(after: separator)...].trimmingCharacters(in: .whitespaces)
            switch key {
            case "RSSI": metrics.rssi = firstInt(String(value))
            case "Noise": metrics.noise = firstInt(String(value))
            case "Tx Rate": metrics.txRate = firstDouble(String(value))
            case "PHY Mode": metrics.phy = String(value)
            case "MCS Index": metrics.mcs = firstInt(String(value))
            case "Guard Interval": metrics.guardIntervalNS = firstInt(String(value))
            case "NSS": metrics.nss = firstInt(String(value))
            case "Channel": metrics.channel = String(value)
            case "CCA": metrics.cca = firstInt(String(value))
            case "Security": metrics.security = String(value)
            case "SSID": metrics.ssid = String(value)
            case "BSSID": metrics.bssid = MACAddress.normalize(String(value))
            default: break
            }
        }
        return metrics
    }

    public static func runInfo(privilege: Privilege, completion: @escaping (WdutilMetrics?, Bool) -> Void) {
        guard privilege != .unavailable else {
            completion(nil, false)
            return
        }
        DispatchQueue.global(qos: .utility).async {
            let result = run(arguments: ["info"], privilege: privilege)
            completion(result.status == 0 ? result.text.map { parseInfo($0) } : nil, result.status == 0)
        }
    }

    public static func toggleDebug() -> Int32 {
        let privilege = effectivePrivilege()
        guard privilege != .unavailable else {
            print("Run: sudo iairport -d")
            return 1
        }
        let before = readDebugState()
        let turnOn = before != "On"
        _ = run(arguments: ["log", turnOn ? "+wifi" : "-wifi"], privilege: privilege)
        let after = readDebugState() ?? "unknown"
        print("Wi-Fi debug logging: \(after)")
        return 0
    }

    public static func readDebugState() -> String? {
        let privilege = effectivePrivilege()
        guard privilege != .unavailable, let text = run(arguments: ["log"], privilege: privilege).text else { return nil }
        for line in text.split(separator: "\n") {
            if line.range(of: "^\\s*Wi-Fi\\s*:\\s*(On|Off)", options: .regularExpression) != nil {
                return line.contains("On") ? "On" : "Off"
            }
        }
        return "unknown"
    }

    public static func effectivePrivilege() -> Privilege {
        if geteuid() == 0 { return .direct }
        if RootHelperClient.shared != nil { return .helper }
        return sudoAvailable() ? .sudo : .unavailable
    }

    public static func sudoAvailable() -> Bool {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/sudo")
        process.arguments = ["-n", "true"]
        process.standardOutput = Pipe()
        process.standardError = Pipe()
        do {
            try process.run()
            process.waitUntilExit()
            return process.terminationStatus == 0
        } catch {
            return false
        }
    }

    private static func run(arguments: [String], privilege: Privilege) -> (text: String?, status: Int32) {
        let process = Process()
        switch privilege {
        case .direct:
            process.executableURL = URL(fileURLWithPath: "/usr/bin/wdutil")
            process.arguments = arguments
        case .sudo:
            process.executableURL = URL(fileURLWithPath: "/usr/bin/sudo")
            process.arguments = ["-n", "/usr/bin/wdutil"] + arguments
        case .helper:
            return RootHelperClient.shared?.run(arguments: arguments) ?? (nil, 1)
        case .unavailable:
            return (nil, 1)
        }
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe
        do {
            try process.run()
            let data = pipe.fileHandleForReading.readDataToEndOfFile()
            process.waitUntilExit()
            return (String(data: data, encoding: .utf8), process.terminationStatus)
        } catch {
            return (nil, 1)
        }
    }

    private static func firstInt(_ text: String) -> Int? {
        guard let match = text.range(of: "-?\\d+", options: .regularExpression) else { return nil }
        return Int(text[match])
    }

    private static func firstDouble(_ text: String) -> Double? {
        guard let match = text.range(of: "-?\\d+(?:\\.\\d+)?", options: .regularExpression) else { return nil }
        return Double(text[match])
    }
}
