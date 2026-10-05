import Foundation

public struct LQMMetrics: Equatable {
    public var rssi: Int?
    public var noise: Int?
    public var snr: Int?
    public var cca: Int?
    public var txRate: Double?
    public var rxRate: Double?
    public var txRetrans: Int?
    public var txFail: Int?
    public var rxRetryFrames: Int?
    public var perAntennaRSSI: [Int]
    public var channel: Int?
    public var bandwidth: Int?
    public var band: String?

    public init(rssi: Int? = nil, noise: Int? = nil, snr: Int? = nil, cca: Int? = nil, txRate: Double? = nil, rxRate: Double? = nil, txRetrans: Int? = nil, txFail: Int? = nil, rxRetryFrames: Int? = nil, perAntennaRSSI: [Int] = [], channel: Int? = nil, bandwidth: Int? = nil, band: String? = nil) {
        self.rssi = rssi
        self.noise = noise
        self.snr = snr
        self.cca = cca
        self.txRate = txRate
        self.rxRate = rxRate
        self.txRetrans = txRetrans
        self.txFail = txFail
        self.rxRetryFrames = rxRetryFrames
        self.perAntennaRSSI = perAntennaRSSI
        self.channel = channel
        self.bandwidth = bandwidth
        self.band = band
    }
}

public struct JoinTiming: Equatable {
    public var values: [String: Int]
    public var uuid: String?
    public var start: Date?

    public init(values: [String: Int], uuid: String? = nil, start: Date? = nil) {
        self.values = values
        self.uuid = uuid
        self.start = start
    }

    public var isComplete: Bool {
        ["assoc", "auth", "linkup", "ipv4", "ipv6"].allSatisfy { values[$0] != nil }
    }

    public func line() -> String {
        let order = ["assoc", "auth", "linkup", "ipv4", "ipv6", "ipv4Primary", "ipv6Primary"]
        let parts = order.compactMap { key -> String? in
            guard let value = values[key] else { return nil }
            return "\(key) \(value) ms"
        }
        return "JOIN TIMING  " + parts.joined(separator: "  ")
    }
}

public struct JoinTimingGate {
    private let launchDate: Date
    private var seen = Set<String>()

    public init(launchDate: Date) {
        self.launchDate = launchDate
    }

    public mutating func accept(_ timing: JoinTiming, now: Date) -> Bool {
        guard timing.isComplete, let start = timing.start else { return false }
        guard start >= launchDate, now.timeIntervalSince(start) >= 0, now.timeIntervalSince(start) <= 30 else { return false }
        let key = timing.uuid ?? String(Int(start.timeIntervalSince1970 * 1000.0))
        guard !seen.contains(key) else { return false }
        seen.insert(key)
        return true
    }
}

public struct AssociatedNetworkInfo: Equatable {
    public var security: String?
    public var ft: Bool
    public var mfp: Bool
}

public struct RoamRequestInfo: Equatable {
    public var bssid: String?
    public var channel: Int?
    public var ssid: String?
    public var flags: Int?

    public var targetDisplay: String {
        guard let bssid else { return "any" }
        return bssid == "ff:ff:ff:ff:ff:ff" ? "any" : bssid
    }
}

public enum RoamRequestCaptureResult: Equatable {
    case collecting
    case finished(RoamRequestInfo)
    case aborted(reprocess: String)
}

public struct RoamRequestCapture: Equatable {
    private var lines: [String] = []
    private let maxLines: Int

    public init(maxLines: Int = 64) {
        self.maxLines = maxLines
    }

    public mutating func consume(_ line: String) -> RoamRequestCaptureResult {
        let trimmed = line.trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmed == "}" {
            return .finished(LogClassifier.parseRoamRequest(lines: lines))
        }
        if LogClassifier.startsWithTimestamp(line) || lines.count >= maxLines {
            return .aborted(reprocess: line)
        }
        lines.append(line)
        return .collecting
    }
}

public enum LogEvent: Equatable {
    case driverRoamed
    case linkSignal
    case lqm(LQMMetrics)
    case deauth(kind: String, source: String?, reason: Int)
    case dhcp(service: String?)
    case dhcpv6(service: String?)
    case ipv6RA
    case joinTiming(JoinTiming)
    case associatedNetwork(AssociatedNetworkInfo)
    case roamRequestBegin
    case scanSummary(String)
    case roamLine(String)
    case problematic(String)
    case log(String)
}

public enum LogClassifier {
    private static let timingPattern = try! NSRegularExpression(pattern: "(assoc|auth|linkup|end|ipv4|ipv4Primary|ipv6|ipv6Primary)=[^(]*\\((\\d+)ms\\)")
    private static let startFormatter: DateFormatter = {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.dateFormat = "yyyy-MM-dd HH:mm:ss.SSS Z"
        return formatter
    }()
    private static let deauthPattern = try! NSRegularExpression(pattern: "Received (Deauth|Disassoc) from (<redacted>|([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}) with Reason ([0-9]+)")
    // The fallback is best-effort because no live deauth sample was observed.
    private static let deauthFallback = try! NSRegularExpression(pattern: "[Dd]eauth.*[Rr]eason[ =:]+([0-9]+)")
    private static let servicePattern = try! NSRegularExpression(pattern: "State:/Network/Service/([^/]+)/")

    public static func classify(line: String, verbose: Bool = false) -> LogEvent? {
        if isNoise(line) { return nil }
        if line.contains("Driver Event:") && line.contains("APPLE80211_M_ROAMED") { return .driverRoamed }
        if line.contains("Driver Event:") && line.contains("APPLE80211_M_LINK_CHANGED") { return .linkSignal }
        if line.contains("AUTO-JOIN: Joining network") { return .linkSignal }
        if line.contains("LQM:") { return .lqm(parseLQM(line)) }
        if let event = parseDeauth(line) { return event }
        if line.contains("DHCPv6") { return .dhcpv6(service: serviceID(in: line)) }
        if line.contains("Processing DHCP:") || line.contains("_processDHCPChanges") || line.contains("DHCP Message") { return .dhcp(service: serviceID(in: line)) }
        if line.contains("AUTO-JOIN: Updated join status") { return .joinTiming(parseJoinTiming(line)) }
        if line.contains("AUTO-JOIN: Updated associated network") { return .associatedNetwork(parseAssociatedNetwork(line)) }
        if line.contains("Requesting Roam : {") { return .roamRequestBegin }
        if line.contains("Completed scan") && line.contains("Scan:") { return .scanSummary(line) }
        if line.contains("manageProblematicNetworks") { return .problematic(line) }
        if line.contains("Roam:") && usefulRoamLine(line) { return .roamLine(line) }
        if verbose { return .log(line) }
        return nil
    }

    public static func startsWithTimestamp(_ line: String) -> Bool {
        line.range(of: "^\\d{4}-\\d{2}-\\d{2} ", options: .regularExpression) != nil
    }

    public static func parseRoamRequest(lines: [String]) -> RoamRequestInfo {
        var info = RoamRequestInfo()
        for line in lines {
            let trimmed = line.trimmingCharacters(in: .whitespacesAndNewlines)
            if let value = quotedValue(named: "BSSID", in: trimmed) {
                info.bssid = MACAddress.normalize(value) ?? value.lowercased()
            } else if let value = intValue(named: "CHANNEL", in: trimmed) {
                info.channel = value
            } else if let value = quotedValue(named: "SSID_STR", in: trimmed) {
                info.ssid = value
            } else if let value = intValue(named: "ROAM_FLAGS", in: trimmed) {
                info.flags = value
            }
        }
        return info
    }

    public static func parseJoinTiming(_ line: String) -> JoinTiming {
        var values: [String: Int] = [:]
        let nsLine = line as NSString
        let range = NSRange(location: 0, length: nsLine.length)
        for match in timingPattern.matches(in: line, range: range) {
            guard match.numberOfRanges == 3 else { continue }
            let key = nsLine.substring(with: match.range(at: 1))
            let raw = nsLine.substring(with: match.range(at: 2))
            values[key] = Int(raw)
        }
        let uuid = firstMatch(line, pattern: "uuid=([^,\\)]+)")
        let startText = firstMatch(line, pattern: "start=(\\d{4}-\\d{2}-\\d{2} \\d{2}:\\d{2}:\\d{2}\\.\\d{3} [-+]\\d{4})")
        return JoinTiming(values: values, uuid: uuid, start: startText.flatMap { startFormatter.date(from: $0) })
    }

    public static func parseAssociatedNetwork(_ line: String) -> AssociatedNetworkInfo {
        let security = firstMatch(line, pattern: "security=([\\w-]+)")
        let auths = firstMatch(line, pattern: "auths=\\{([^}]*)\\}") ?? ""
        let mfp = firstMatch(line, pattern: "mfp=(yes|no)") == "yes"
        let ft = auths.split(whereSeparator: { $0 == " " || $0 == "\t" }).contains { $0.hasPrefix("ft_") }
        return AssociatedNetworkInfo(security: security, ft: ft, mfp: mfp)
    }

    public static func parseLQM(_ line: String) -> LQMMetrics {
        var metrics = LQMMetrics()
        metrics.rssi = intAfterKey("rssi", in: line)
        metrics.noise = intAfterKey("noise", in: line)
        metrics.snr = intAfterKey("snr", in: line)
        if let cca = doubleAfterKey("cca", in: line) { metrics.cca = Int(cca.rounded()) }
        metrics.txRate = doubleAfterKey("txRate", in: line)
        metrics.rxRate = doubleAfterKey("rxRate", in: line)
        metrics.txRetrans = intAfterKey("txRetrans", in: line)
        metrics.txFail = intAfterKey("txFail", in: line)
        metrics.rxRetryFrames = intAfterKey("rxRetryFrames", in: line)
        metrics.perAntennaRSSI = parsePerAntenna(line)
        metrics.channel = intAfterLooseKey("channel", in: line)
        metrics.bandwidth = intAfterLooseKey("BW", in: line)
        if let band = intAfterLooseKey("band", in: line) {
            metrics.band = band == 1 ? "2.4" : band == 2 ? "5" : band == 3 ? "6" : nil
        }
        return metrics
    }

    private static func parseDeauth(_ line: String) -> LogEvent? {
        let nsLine = line as NSString
        let range = NSRange(location: 0, length: nsLine.length)
        if let match = deauthPattern.firstMatch(in: line, range: range), match.numberOfRanges >= 5 {
            let kind = nsLine.substring(with: match.range(at: 1))
            let sourceRange = match.range(at: 2)
            let source = sourceRange.location == NSNotFound ? nil : nsLine.substring(with: sourceRange)
            let reason = Int(nsLine.substring(with: match.range(at: 4))) ?? 0
            return .deauth(kind: kind, source: source == "<redacted>" ? nil : source, reason: reason)
        }
        if let match = deauthFallback.firstMatch(in: line, range: range), match.numberOfRanges >= 2 {
            let reason = Int(nsLine.substring(with: match.range(at: 1))) ?? 0
            return .deauth(kind: "Deauth", source: nil, reason: reason)
        }
        return nil
    }

    private static func serviceID(in line: String) -> String? {
        let nsLine = line as NSString
        let range = NSRange(location: 0, length: nsLine.length)
        if let match = servicePattern.firstMatch(in: line, range: range), match.numberOfRanges > 1 {
            return nsLine.substring(with: match.range(at: 1))
        }
        if let value = firstMatch(line, pattern: "service:([0-9A-Fa-f-]+)") { return value }
        return nil
    }

    private static func usefulRoamLine(_ line: String) -> Bool {
        let lower = line.lowercased()
        if lower.contains("profile") { return false }
        if lower.contains("roaminfo") { return false }
        return lower.contains("triggered") || lower.contains("candidate") || lower.contains("result") || lower.contains("processing apple80211_ioc_roam")
    }

    private static func isNoise(_ line: String) -> Bool {
        let filters = [
            "Processed events",
            "Health check alive",
            "BEGIN REQ",
            "END REQ",
            "Transaction created",
            "Transaction released",
            "Scan offloads will be",
            "Using default interface role",
            "RoamInfo -"
        ]
        return filters.contains { line.contains($0) }
    }

    private static func intAfterKey(_ key: String, in line: String) -> Int? {
        guard let value = firstMatch(line, pattern: "\\b\(NSRegularExpression.escapedPattern(for: key))=(-?\\d+(?:\\.\\d+)?)") else { return nil }
        return Int(Double(value) ?? 0)
    }

    private static func doubleAfterKey(_ key: String, in line: String) -> Double? {
        guard let value = firstMatch(line, pattern: "\\b\(NSRegularExpression.escapedPattern(for: key))=(-?\\d+(?:\\.\\d+)?)") else { return nil }
        return Double(value)
    }

    private static func intAfterLooseKey(_ key: String, in line: String) -> Int? {
        guard let value = firstMatch(line, pattern: "\(NSRegularExpression.escapedPattern(for: key))\\s*=\\s*(-?\\d+)") else { return nil }
        return Int(value)
    }

    private static func parsePerAntenna(_ line: String) -> [Int] {
        guard let inside = firstMatch(line, pattern: "per_ant_rssi=\\(([^)]*)\\)") else { return [] }
        return inside.split(separator: ",").compactMap { part in
            let cleaned = part.trimmingCharacters(in: .whitespaces).replacingOccurrences(of: "dBm", with: "")
            return Int(cleaned)
        }
    }

    private static func quotedValue(named name: String, in line: String) -> String? {
        firstMatch(line, pattern: "\\\"?\(NSRegularExpression.escapedPattern(for: name))\\\"?\\s*=\\s*\\\"([^\\\"]*)\\\"")
    }

    private static func intValue(named name: String, in line: String) -> Int? {
        guard let value = firstMatch(line, pattern: "\\\"?\(NSRegularExpression.escapedPattern(for: name))\\\"?\\s*=\\s*(-?\\d+)") else { return nil }
        return Int(value)
    }

    private static func firstMatch(_ line: String, pattern: String) -> String? {
        guard let regex = try? NSRegularExpression(pattern: pattern) else { return nil }
        let nsLine = line as NSString
        let range = NSRange(location: 0, length: nsLine.length)
        guard let match = regex.firstMatch(in: line, range: range), match.numberOfRanges > 1 else { return nil }
        let matchRange = match.range(at: 1)
        guard matchRange.location != NSNotFound else { return nil }
        return nsLine.substring(with: matchRange)
    }
}
