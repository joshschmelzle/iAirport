import Foundation
import SystemConfiguration

public struct CachedScanRecord: Equatable {
    public var bssid: String?
    public var ssid: String?
    public var channel: Int?
    public var rssi: Int?
    public var noise: Int?
    /// Raw beacon information elements of the recorded BSS.
    public var informationElements: Data?

    public init(bssid: String? = nil, ssid: String? = nil, channel: Int? = nil, rssi: Int? = nil, noise: Int? = nil, informationElements: Data? = nil) {
        self.bssid = bssid
        self.ssid = ssid
        self.channel = channel
        self.rssi = rssi
        self.noise = noise
        self.informationElements = informationElements
    }

    public static func decode(from data: Data) -> CachedScanRecord? {
        guard data.count <= 1_048_576 else { return nil }
        let allowed: [AnyClass] = [NSDictionary.self, NSString.self, NSNumber.self, NSData.self, NSArray.self, NSDate.self]
        guard let object = try? NSKeyedUnarchiver.unarchivedObject(ofClasses: allowed, from: data) as? NSDictionary else {
            return nil
        }
        var ssid = object["SSID_STR"] as? String
        if (ssid == nil || ssid == ""), let data = object["SSID"] as? Data {
            ssid = String(data: data, encoding: .utf8)
        }
        let bssid = MACAddress.normalize(object["BSSID"] as? String)
        return CachedScanRecord(
            bssid: bssid,
            ssid: ssid,
            channel: (object["CHANNEL"] as? NSNumber)?.intValue,
            rssi: (object["RSSI"] as? NSNumber)?.intValue,
            noise: (object["NOISE"] as? NSNumber)?.intValue,
            informationElements: object["IE"] as? Data
        )
    }

    public static func read(interface: String) -> CachedScanRecord? {
        let key = "State:/Network/Interface/\(interface)/AirPort" as CFString
        guard let state = SCDynamicStoreCopyValue(nil, key) as? [String: Any],
              let data = state["CachedScanRecord"] as? Data else {
            return nil
        }
        return decode(from: data)
    }
}
