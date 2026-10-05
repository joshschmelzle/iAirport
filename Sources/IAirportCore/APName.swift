import CoreWLAN
import Foundation

/// One tagged 802.11 information element from a beacon or probe response.
public struct InformationElement: Equatable {
    public var id: UInt8
    public var body: Data

    public init(id: UInt8, body: Data) {
        self.id = id
        self.body = body
    }
}

public enum InformationElements {
    /// Splits an IE blob into elements. Stops at the first truncated element.
    public static func parse(_ data: Data) -> [InformationElement] {
        var elements: [InformationElement] = []
        var index = data.startIndex
        while index + 1 < data.endIndex {
            let id = data[index]
            let length = Int(data[index + 1])
            let bodyStart = index + 2
            let bodyEnd = bodyStart + length
            guard bodyEnd <= data.endIndex else { break }
            elements.append(InformationElement(id: id, body: Data(data[bodyStart..<bodyEnd])))
            index = bodyEnd
        }
        return elements
    }
}

/// Decodes the AP name vendors put in their beacons.
///
/// Layouts come from the Wireshark dissector (epan/dissectors/packet-ieee80211.c,
/// read 2026-10-05). Aruba was also checked against beacons on a live network.
/// Offsets below are into the vendor IE body, right after the 3-byte OUI.
public enum APNameDecoder {
    public static let maxLength = 64

    /// How a vendor lays out the name after its OUI.
    enum Layout {
        /// `[type] name...`
        case typed(UInt8)
        /// `[type] [subtype] [skip] name...`
        case typedSubtyped(UInt8, UInt8)
        /// `[type] [version] [subtype] [len] name...`
        case aerohive
        /// `[type] 7 bytes [len] name...`
        case extreme
        /// `[subtype LE16] then TLVs [type][len][value], type 1 = AP name`
        case fortinet
        /// `[type] name...` or `[0] [type] [skip] name...`, both seen in the wild
        case arista
    }

    struct Vendor {
        let oui: (UInt8, UInt8, UInt8)
        let layout: Layout
    }

    static let vendors: [Vendor] = [
        Vendor(oui: (0x00, 0x0b, 0x86), layout: .typedSubtyped(0x01, 0x03)),   // Aruba / HPE
        Vendor(oui: (0x00, 0x40, 0x96), layout: .typed(47)),                   // Cisco Aironet v2, Meraki
        Vendor(oui: (0x00, 0xe0, 0xfc), layout: .typedSubtyped(0x01, 0x01)),   // Huawei
        Vendor(oui: (0x00, 0x19, 0x77), layout: .aerohive),                    // Aerohive / Extreme
        Vendor(oui: (0x00, 0xa0, 0xf8), layout: .extreme),                     // Extreme WiNG / Zebra
        Vendor(oui: (0x00, 0x09, 0x0f), layout: .fortinet),                    // Fortinet
        Vendor(oui: (0x00, 0x11, 0x74), layout: .arista),                      // Arista / Mojo
        Vendor(oui: (0x5c, 0x5b, 0x35), layout: .typed(1)),                    // Juniper Mist
        Vendor(oui: (0x00, 0x15, 0x6d), layout: .typed(1)),                    // Ubiquiti UniFi
        Vendor(oui: (0x00, 0x13, 0x92), layout: .typed(3)),                    // Ruckus
        Vendor(oui: (0xdc, 0x08, 0x56), layout: .typed(1)),                    // Alcatel-Lucent
        Vendor(oui: (0x48, 0xd0, 0x17), layout: .typed(2)),                    // Telecom Infra Project
        Vendor(oui: (0x3c, 0xb9, 0xa6), layout: .typed(1)),                    // Belden
        Vendor(oui: (0x84, 0x80, 0x94), layout: .typed(0)),                    // Meter
    ]

    public static func apName(in data: Data) -> String? {
        apName(elements: InformationElements.parse(data))
    }

    public static func apName(elements: [InformationElement]) -> String? {
        for element in elements {
            if let name = decode(element) { return name }
        }
        return nil
    }

    private static func decode(_ element: InformationElement) -> String? {
        let body = [UInt8](element.body)
        switch element.id {
        case 0xdd:
            guard body.count >= 4 else { return nil }
            let oui = (body[0], body[1], body[2])
            guard let vendor = vendors.first(where: { $0.oui == oui }) else { return nil }
            return decode(layout: vendor.layout, payload: Array(body[3...]))
        case 0x85:
            // Cisco CCX1 CKIP + Device Name: 10 unknown bytes, 16-byte name, client count.
            guard body.count >= 26 else { return nil }
            return clean(body[10..<26])
        default:
            return nil
        }
    }

    static func decode(layout: Layout, payload p: [UInt8]) -> String? {
        switch layout {
        case .typed(let type):
            guard p.count > 1, p[0] == type else { return nil }
            return clean(p[1...])
        case .typedSubtyped(let type, let subtype):
            guard p.count > 3, p[0] == type, p[1] == subtype else { return nil }
            return clean(p[3...])
        case .aerohive:
            guard p.count > 4, p[0] == 33 else { return nil }
            return clean(prefixed(p, lengthAt: 3))
        case .extreme:
            guard p.count > 9, p[0] == 1 else { return nil }
            return clean(prefixed(p, lengthAt: 8))
        case .fortinet:
            guard p.count > 4, p[0] == 10, p[1] == 0 else { return nil }
            var index = 2
            while index + 2 <= p.count {
                let type = p[index], length = Int(p[index + 1])
                let start = index + 2, end = min(start + length, p.count)
                if type == 1 { return clean(p[start..<end]) }
                index = end
            }
            return nil
        case .arista:
            if p.count > 1, p[0] == 6 { return clean(p[1...]) }
            guard p.count > 3, p[0] == 0, p[1] == 6 else { return nil }
            return clean(p[3...])
        }
    }

    private static func prefixed(_ p: [UInt8], lengthAt index: Int) -> ArraySlice<UInt8> {
        let start = index + 1
        let end = min(start + Int(p[index]), p.count)
        return p[start..<end]
    }

    /// Trims NUL and space padding and rejects names with control characters.
    static func clean<S: Sequence>(_ bytes: S) -> String? where S.Element == UInt8 {
        var trimmed = Array(bytes)
        while let last = trimmed.last, last == 0 || last == 0x20 { trimmed.removeLast() }
        guard !trimmed.isEmpty, trimmed.count <= maxLength else { return nil }
        guard let name = String(bytes: trimmed, encoding: .utf8) else { return nil }
        guard name.unicodeScalars.allSatisfy({ $0.value >= 0x20 && $0.value != 0x7f }) else { return nil }
        return name
    }
}

/// Learns BSSID to AP name pairs from the scan caches and answers lookups.
///
/// Live mode reads CoreWLAN's cached scan results, which hold the beacon IEs of
/// every BSS seen. Cache mode only sees the scan record of the current BSS.
public final class APNameResolver {
    private let interfaceName: String
    private let client: CWWiFiClient
    private var names: [String: String] = [:]
    private var attempts: [String: Int] = [:]
    private var lastRefresh: Date = .distantPast

    static let maxAttempts = 5
    static let minRefreshInterval: TimeInterval = 2

    public init(interfaceName: String, client: CWWiFiClient = .shared()) {
        self.interfaceName = interfaceName
        self.client = client
    }

    public var count: Int { names.count }

    public func name(for bssid: String?) -> String? {
        guard let bssid = MACAddress.normalize(bssid) else { return nil }
        return names[bssid]
    }

    /// Returns the name for `bssid`, refreshing the caches when it is unknown.
    /// Gives up on a BSSID after a few misses so APs without a name IE do not
    /// cost a scan-cache read every sample. `force` skips the interval check.
    public func resolve(_ bssid: String?, force: Bool = false, now: Date = Date()) -> String? {
        guard let bssid = MACAddress.normalize(bssid) else { return nil }
        if let known = names[bssid] { return known }
        let tried = attempts[bssid, default: 0]
        guard force || tried < Self.maxAttempts else { return nil }
        guard force || now.timeIntervalSince(lastRefresh) >= Self.minRefreshInterval else { return nil }
        attempts[bssid] = tried + 1
        refresh(now: now)
        return names[bssid]
    }

    public func refresh(now: Date = Date()) {
        lastRefresh = now
        let iface = client.interface(withName: interfaceName) ?? client.interface()
        for network in iface?.cachedScanResults() ?? [] {
            guard let bssid = MACAddress.normalize(network.bssid),
                  let data = network.informationElementData,
                  let name = APNameDecoder.apName(in: data) else { continue }
            learn(bssid: bssid, name: name)
        }
        if let record = CachedScanRecord.read(interface: interfaceName),
           let bssid = record.bssid,
           let data = record.informationElements,
           let name = APNameDecoder.apName(in: data) {
            learn(bssid: bssid, name: name)
        }
    }

    public func learn(bssid: String, name: String) {
        guard let bssid = MACAddress.normalize(bssid) else { return }
        names[bssid] = name
        attempts[bssid] = nil
    }
}
