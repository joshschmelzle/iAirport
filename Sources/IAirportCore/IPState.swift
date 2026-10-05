import Foundation
import SystemConfiguration

public enum IPv6Kind: String, Equatable {
    case linkLocal
    case slaac
    case temporary
    case dhcpv6
    case `static`
    case deprecated
}

public struct IPv6AddressInfo: Equatable {
    public var address: String
    public var prefix: Int?
    public var flags: Int

    public init(address: String, prefix: Int?, flags: Int) {
        self.address = address
        self.prefix = prefix
        self.flags = flags
    }

    public var kind: IPv6Kind {
        let lower = address.lowercased()
        if lower.hasPrefix("fe80:") { return .linkLocal }
        if flags & 0x0010 != 0 { return .deprecated }
        if flags & 0x0080 != 0 { return .temporary }
        if flags & 0x0100 != 0 { return .dhcpv6 }
        if flags & 0x0040 != 0 { return .slaac }
        return .static
    }

    public var isGlobal: Bool {
        kind != .linkLocal
    }
}

public struct IPState: Equatable {
    public var ipv4: [String]
    public var ipv4Prefixes: [Int?]
    public var ipv4Router: String?
    public var ipv6: [IPv6AddressInfo]
    public var ipv6Router: String?
    public var primaryV4: Bool
    public var primaryV6: Bool

    public init(ipv4: [String] = [], ipv4Prefixes: [Int?] = [], ipv4Router: String? = nil, ipv6: [IPv6AddressInfo] = [], ipv6Router: String? = nil, primaryV4: Bool = false, primaryV6: Bool = false) {
        self.ipv4 = ipv4
        self.ipv4Prefixes = ipv4Prefixes
        self.ipv4Router = ipv4Router
        self.ipv6 = ipv6
        self.ipv6Router = ipv6Router
        self.primaryV4 = primaryV4
        self.primaryV6 = primaryV6
    }

    public var hasIPv4: Bool { !ipv4.isEmpty }

    public var hasGlobalIPv6: Bool {
        ipv6.contains { $0.isGlobal && $0.kind != .deprecated }
    }

    public var displayIPv6: IPv6AddressInfo? {
        let globals = ipv6.filter { $0.isGlobal }
        if let stable = globals.first(where: { ($0.kind == .slaac || $0.kind == .dhcpv6) && $0.kind != .deprecated }) {
            return stable
        }
        if let nonDeprecated = globals.first(where: { $0.kind != .deprecated }) {
            return nonDeprecated
        }
        return globals.first
    }

    public var temporaryIPv6CountForDisplay: Int {
        let display = displayIPv6?.address
        return ipv6.filter { $0.isGlobal && $0.kind == .temporary && $0.address != display }.count
    }

    public func displayLine() -> String {
        let v4 = ipv4.first.map { addr in
            let prefix = ipv4Prefixes.first.flatMap { $0 }.map { "/\($0)" } ?? ""
            return "v4 \(addr)\(prefix) gw \(ipv4Router ?? "none")"
        } ?? "v4 none"
        let v6: String
        if let shown = displayIPv6 {
            let prefix = shown.prefix.map { "/\($0)" } ?? ""
            var temp = ""
            let tempCount = temporaryIPv6CountForDisplay
            if tempCount > 0 { temp = " (+\(tempCount) temp)" }
            v6 = "v6 \(shown.address)\(prefix) \(shown.kind.rawValue)\(temp) gw \(ipv6Router ?? "none")"
        } else {
            v6 = "v6 none"
        }
        return "IP  \(v4)  |  \(v6)"
    }

    public func compactTag() -> String {
        let v4 = hasIPv4 ? "v4" : "-"
        let v6 = hasGlobalIPv6 ? "v6" : "-"
        return "\(v4) \(v6)"
    }

    public func jsonObject() -> [String: Any] {
        var object: [String: Any] = [
            "v4": ipv4,
            "v4_prefix": ipv4Prefixes.map { item in item.map { $0 as Any } ?? NSNull() },
            "v6": ipv6.map { item in
                var entry: [String: Any] = ["addr": item.address, "kind": item.kind.rawValue, "flags": item.flags]
                if let prefix = item.prefix { entry["prefix"] = prefix }
                return entry
            }
        ]
        if let gw = ipv4Router { object["v4_gw"] = gw }
        if let gw = ipv6Router { object["v6_gw"] = gw }
        object["primary_v4"] = primaryV4
        object["primary_v6"] = primaryV6
        return object
    }
}

public enum IPAfterRoam: Equatable {
    case kept
    case changed(milliseconds: Int)
    case renewed(milliseconds: Int)

    public var csvValue: String {
        switch self {
        case .kept: return "kept"
        case .changed: return "changed"
        case .renewed: return "renewed"
        }
    }

    public var milliseconds: Int? {
        switch self {
        case .kept: return nil
        case .changed(let ms), .renewed(let ms): return ms
        }
    }

    public func display(family: String) -> String {
        switch self {
        case .kept:
            return "\(family) kept"
        case .changed(let ms):
            return String(format: "\(family) changed %.1f s", Double(ms) / 1000.0)
        case .renewed(let ms):
            return String(format: "\(family) renewed %.1f s", Double(ms) / 1000.0)
        }
    }
}

public enum IPStateComparator {
    public static func compareV4(before: IPState, after: IPState, milliseconds: Int) -> IPAfterRoam {
        if Set(before.ipv4) == Set(after.ipv4) { return .kept }
        return .renewed(milliseconds: milliseconds)
    }

    public static func compareV6(before: IPState, after: IPState, milliseconds: Int) -> IPAfterRoam {
        let beforeSet = Set(before.ipv6.filter { $0.isGlobal }.map { $0.address })
        let afterSet = Set(after.ipv6.filter { $0.isGlobal }.map { $0.address })
        if beforeSet == afterSet { return .kept }
        return .changed(milliseconds: milliseconds)
    }
}

public final class IPStateReader {
    private let interfaceName: String

    public init(interfaceName: String) {
        self.interfaceName = interfaceName
    }

    public func read() -> IPState {
        let v4Key = "State:/Network/Interface/\(interfaceName)/IPv4"
        let v6Key = "State:/Network/Interface/\(interfaceName)/IPv6"
        let globalV4 = dictionary(for: "State:/Network/Global/IPv4")
        let globalV6 = dictionary(for: "State:/Network/Global/IPv6")
        let serviceV4 = serviceDictionary(suffix: "IPv4")
        let serviceV6 = serviceDictionary(suffix: "IPv6")
        let v4Dict = dictionary(for: v4Key)
        let v6Dict = dictionary(for: v6Key)
        let v4 = stringArray(v4Dict?["Addresses"])
        let v4Masks = stringArray(v4Dict?["SubnetMasks"])
        let v4Prefixes = v4Masks.map { Self.ipv4Prefix(mask: $0) }
        let v6Addresses = stringArray(v6Dict?["Addresses"])
        let prefixes = intArray(v6Dict?["PrefixLength"])
        let flags = intArray(v6Dict?["Flags"])
        let v6 = v6Addresses.enumerated().map { index, address in
            IPv6AddressInfo(
                address: address,
                prefix: index < prefixes.count ? prefixes[index] : nil,
                flags: index < flags.count ? flags[index] : 0
            )
        }
        let primaryV4 = (globalV4?["PrimaryInterface"] as? String) == interfaceName
        let primaryV6 = (globalV6?["PrimaryInterface"] as? String) == interfaceName
        return IPState(
            ipv4: v4,
            ipv4Prefixes: v4Prefixes,
            ipv4Router: (serviceV4?["Router"] as? String) ?? (globalV4?["Router"] as? String),
            ipv6: v6,
            ipv6Router: (serviceV6?["Router"] as? String) ?? (globalV6?["Router"] as? String),
            primaryV4: primaryV4,
            primaryV6: primaryV6
        )
    }

    private func dictionary(for key: String) -> [String: Any]? {
        SCDynamicStoreCopyValue(nil, key as CFString) as? [String: Any]
    }

    private func serviceDictionary(suffix: String) -> [String: Any]? {
        let pattern = "State:/Network/Service/.*/\(suffix)" as CFString
        guard let keys = SCDynamicStoreCopyKeyList(nil, pattern) as? [String] else { return nil }
        for key in keys {
            guard let value = dictionary(for: key) else { continue }
            if value["InterfaceName"] as? String == interfaceName || value["ConfirmedInterfaceName"] as? String == interfaceName {
                return value
            }
        }
        return nil
    }

    private func stringArray(_ value: Any?) -> [String] {
        if let strings = value as? [String] { return strings }
        if let array = value as? [Any] { return array.compactMap { $0 as? String } }
        return []
    }

    private static func ipv4Prefix(mask: String) -> Int? {
        let parts = mask.split(separator: ".").compactMap { Int($0) }
        guard parts.count == 4 else { return nil }
        return parts.reduce(0) { total, part in total + part.nonzeroBitCount }
    }

    private func intArray(_ value: Any?) -> [Int] {
        if let ints = value as? [Int] { return ints }
        if let nums = value as? [NSNumber] { return nums.map { $0.intValue } }
        if let array = value as? [Any] {
            return array.compactMap { item in
                if let num = item as? NSNumber { return num.intValue }
                if let int = item as? Int { return int }
                return nil
            }
        }
        return []
    }
}
