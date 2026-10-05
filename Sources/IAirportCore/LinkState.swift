import Foundation
import CoreWLAN

public enum RadioStatus: Equatable {
    case off
    case disconnected
    case associated

    public var csvValue: String {
        switch self {
        case .off: return "off"
        case .disconnected: return "disconnected"
        case .associated: return "associated"
        }
    }
}

public struct LinkMetrics: Equatable {
    public var mcs: Int?
    public var nss: Int?
    public var guardIntervalNS: Int?
    public var ccaPct: Int?
    public var snrDB: Int?
    public var txRetrans: Int?
    public var txFail: Int?
    public var rxRetry: Int?
    public var perAntennaRSSI: [Int]
    public var security: String?
    public var ft: Bool
    public var mfp: Bool
    public var phy: String?
    public var band: String?

    public init(mcs: Int? = nil, nss: Int? = nil, guardIntervalNS: Int? = nil, ccaPct: Int? = nil, snrDB: Int? = nil, txRetrans: Int? = nil, txFail: Int? = nil, rxRetry: Int? = nil, perAntennaRSSI: [Int] = [], security: String? = nil, ft: Bool = false, mfp: Bool = false, phy: String? = nil, band: String? = nil) {
        self.mcs = mcs
        self.nss = nss
        self.guardIntervalNS = guardIntervalNS
        self.ccaPct = ccaPct
        self.snrDB = snrDB
        self.txRetrans = txRetrans
        self.txFail = txFail
        self.rxRetry = rxRetry
        self.perAntennaRSSI = perAntennaRSSI
        self.security = security
        self.ft = ft
        self.mfp = mfp
        self.phy = phy
        self.band = band
    }

    public mutating func clearBSSIDScoped() {
        mcs = nil
        nss = nil
        guardIntervalNS = nil
        ccaPct = nil
        snrDB = nil
        txRetrans = nil
        txFail = nil
        rxRetry = nil
        perAntennaRSSI = []
    }
}

public struct LinkSample: Equatable {
    public var timestamp: Date
    public var interfaceName: String
    public var status: RadioStatus
    public var ssid: String?
    public var bssid: String?
    public var vendor: String?
    /// Friendly AP name from the beacon, when the vendor advertises one.
    public var apName: String?
    public var channel: Int?
    public var widthMHz: Int?
    public var band: String?
    public var phy: String?
    public var security: String?
    public var ft: Bool
    public var mfp: Bool
    public var mcs: Int?
    public var nss: Int?
    public var guardIntervalNS: Int?
    public var txRateMbps: Double?
    public var rssiDBM: Int?
    public var noiseDBM: Int?
    public var snrDB: Int?
    public var ccaPct: Int?
    public var txRetrans: Int?
    public var txFail: Int?
    public var rxRetry: Int?
    public var perAntennaRSSI: [Int]
    public var bytesIn: UInt64?
    public var bytesOut: UInt64?
    public var bpsIn: UInt64?
    public var bpsOut: UInt64?
    public var ipState: IPState
    public var bssidSource: BSSIDSource
    // True when the radio is associated (channel and RSSI present) but CoreWLAN
    // withheld the BSSID. airportd does that when the Location grant is missing.
    public var liveBSSIDWithheld: Bool = false

    public init(timestamp: Date = Date(), interfaceName: String, status: RadioStatus, ssid: String? = nil, bssid: String? = nil, vendor: String? = nil, channel: Int? = nil, widthMHz: Int? = nil, band: String? = nil, phy: String? = nil, security: String? = nil, ft: Bool = false, mfp: Bool = false, mcs: Int? = nil, nss: Int? = nil, guardIntervalNS: Int? = nil, txRateMbps: Double? = nil, rssiDBM: Int? = nil, noiseDBM: Int? = nil, snrDB: Int? = nil, ccaPct: Int? = nil, txRetrans: Int? = nil, txFail: Int? = nil, rxRetry: Int? = nil, perAntennaRSSI: [Int] = [], bytesIn: UInt64? = nil, bytesOut: UInt64? = nil, bpsIn: UInt64? = nil, bpsOut: UInt64? = nil, ipState: IPState = IPState(), bssidSource: BSSIDSource = .cache) {
        self.timestamp = timestamp
        self.interfaceName = interfaceName
        self.status = status
        self.ssid = ssid
        self.bssid = bssid
        self.vendor = vendor
        self.channel = channel
        self.widthMHz = widthMHz
        self.band = band
        self.phy = phy
        self.security = security
        self.ft = ft
        self.mfp = mfp
        self.mcs = mcs
        self.nss = nss
        self.guardIntervalNS = guardIntervalNS
        self.txRateMbps = txRateMbps
        self.rssiDBM = rssiDBM
        self.noiseDBM = noiseDBM
        self.snrDB = snrDB
        self.ccaPct = ccaPct
        self.txRetrans = txRetrans
        self.txFail = txFail
        self.rxRetry = rxRetry
        self.perAntennaRSSI = perAntennaRSSI
        self.bytesIn = bytesIn
        self.bytesOut = bytesOut
        self.bpsIn = bpsIn
        self.bpsOut = bpsOut
        self.ipState = ipState
        self.bssidSource = bssidSource
    }
}

public final class LinkReader {
    private let interfaceName: String
    private let client: CWWiFiClient

    public init(interfaceName: String, client: CWWiFiClient = CWWiFiClient.shared()) {
        self.interfaceName = interfaceName
        self.client = client
    }

    public static func defaultInterfaceName() -> String {
        let client = CWWiFiClient.shared()
        if let name = client.interface()?.interfaceName, !name.isEmpty { return name }
        if let names = client.interfaceNames(), let first = names.first, !first.isEmpty { return first }
        return "en0"
    }

    public func read(metrics: LinkMetrics, ipState: IPState, throughput: ThroughputSample?, oui: OUI, bssidSource: BSSIDSource) -> LinkSample {
        let now = Date()
        let iface = client.interface(withName: interfaceName) ?? client.interface()
        let cached = bssidSource == .cache ? CachedScanRecord.read(interface: interfaceName) : nil
        let powerOn = iface?.powerOn() ?? false
        let coreRSSI = iface?.rssiValue() ?? 0
        let coreNoise = iface?.noiseMeasurement() ?? 0
        let channelObject = iface?.wlanChannel()
        let coreBSSID = MACAddress.normalize(iface?.bssid())
        let cachedBSSID = cached?.bssid
        let bssid = bssidSource == .live ? coreBSSID : cachedBSSID
        let ssid = bssidSource == .live ? nonEmpty(iface?.ssid()) : (cached?.ssid ?? nonEmpty(iface?.ssid()))
        let channel = channelObject?.channelNumber ?? cached?.channel
        let width = channelObject.flatMap { widthMHz($0.channelWidth.rawValue) }
        let band = metrics.band ?? channelObject.flatMap { bandName($0.channelBand.rawValue) }
        let phy = metrics.phy ?? iface.flatMap { phyName($0.activePHYMode().rawValue) }
        let security = metrics.security ?? iface.flatMap { securityName($0.security().rawValue) }
        let rssi = coreRSSI == 0 ? nil : coreRSSI
        let noise = coreNoise == 0 ? nil : coreNoise
        let snr: Int? = {
            if let rssi, let noise { return rssi - noise }
            return metrics.snrDB
        }()
        let status: RadioStatus
        if !powerOn {
            status = .off
        } else if channelObject == nil || coreRSSI == 0 || bssid == nil {
            status = .disconnected
        } else {
            status = .associated
        }
        let withheld = bssidSource == .live && powerOn && channelObject != nil && coreRSSI != 0 && coreBSSID == nil
        var sample = LinkSample(
            timestamp: now,
            interfaceName: interfaceName,
            status: status,
            ssid: ssid,
            bssid: bssid,
            vendor: oui.vendor(for: bssid),
            channel: channel,
            widthMHz: width,
            band: band,
            phy: phy,
            security: security,
            ft: metrics.ft,
            mfp: metrics.mfp,
            mcs: metrics.mcs,
            nss: metrics.nss,
            guardIntervalNS: metrics.guardIntervalNS,
            txRateMbps: iface?.transmitRate(),
            rssiDBM: rssi,
            noiseDBM: noise,
            snrDB: snr,
            ccaPct: metrics.ccaPct,
            txRetrans: metrics.txRetrans,
            txFail: metrics.txFail,
            rxRetry: metrics.rxRetry,
            perAntennaRSSI: metrics.perAntennaRSSI,
            bytesIn: throughput?.bytesIn,
            bytesOut: throughput?.bytesOut,
            bpsIn: throughput?.bpsIn,
            bpsOut: throughput?.bpsOut,
            ipState: ipState,
            bssidSource: bssidSource
        )
        sample.liveBSSIDWithheld = withheld
        return sample
    }

    public func liveBSSIDAvailable() -> Bool {
        let iface = client.interface(withName: interfaceName) ?? client.interface()
        return MACAddress.normalize(iface?.bssid()) != nil
    }

    private static func widthMHz(_ raw: Int) -> Int? {
        switch raw {
        case 1: return 20
        case 2: return 40
        case 3: return 80
        case 4: return 160
        default: return nil
        }
    }

    private static func bandName(_ raw: Int) -> String? {
        switch raw {
        case 1: return "2.4"
        case 2: return "5"
        case 3: return "6"
        default: return nil
        }
    }

    private static func phyName(_ raw: Int) -> String? {
        switch raw {
        case 1: return "11a"
        case 2: return "11b"
        case 3: return "11g"
        case 4: return "11n"
        case 5: return "11ac"
        case 6: return "11ax"
        case 7: return "11be"
        default: return nil
        }
    }

    private static func securityName(_ raw: Int) -> String? {
        switch raw {
        case 0: return "open"
        case 1: return "wep"
        case 2: return "wpa-personal"
        case 3: return "wpa-mixed"
        case 4: return "wpa2-personal"
        case 5: return "personal"
        case 6: return "dynamic-wep"
        case 7: return "wpa-enterprise"
        case 8: return "wpa-mixed-enterprise"
        case 9: return "wpa2-enterprise"
        case 10: return "enterprise"
        case 11: return "wpa3-personal"
        case 12: return "wpa3-enterprise"
        case 13: return "wpa3-transition"
        case 14: return "owe"
        case 15: return "owe-transition"
        default: return nil
        }
    }

    private func widthMHz(_ raw: Int) -> Int? { Self.widthMHz(raw) }
    private func bandName(_ raw: Int) -> String? { Self.bandName(raw) }
    private func phyName(_ raw: Int) -> String? { Self.phyName(raw) }
    private func securityName(_ raw: Int) -> String? { Self.securityName(raw) }

    private func nonEmpty(_ value: String?) -> String? {
        guard let value, !value.isEmpty else { return nil }
        return value
    }
}
