import Foundation
import Darwin

public struct InterfaceCounters: Equatable {
    public var bytesIn: UInt64
    public var bytesOut: UInt64

    public init(bytesIn: UInt64, bytesOut: UInt64) {
        self.bytesIn = bytesIn
        self.bytesOut = bytesOut
    }
}

public struct ThroughputSample: Equatable {
    public var bytesIn: UInt64
    public var bytesOut: UInt64
    public var bpsIn: UInt64
    public var bpsOut: UInt64

    public init(bytesIn: UInt64, bytesOut: UInt64, bpsIn: UInt64, bpsOut: UInt64) {
        self.bytesIn = bytesIn
        self.bytesOut = bytesOut
        self.bpsIn = bpsIn
        self.bpsOut = bpsOut
    }
}

public enum CounterReader {
    public static func counters(for name: String) -> InterfaceCounters? {
        var first: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&first) == 0 else { return nil }
        defer { freeifaddrs(first) }
        var current = first
        while let item = current {
            let ifa = item.pointee
            if let addr = ifa.ifa_addr,
               Int32(addr.pointee.sa_family) == AF_LINK,
               String(cString: ifa.ifa_name) == name,
               let dataPointer = ifa.ifa_data {
                let data = dataPointer.assumingMemoryBound(to: if_data.self).pointee
                return InterfaceCounters(bytesIn: UInt64(data.ifi_ibytes), bytesOut: UInt64(data.ifi_obytes))
            }
            current = ifa.ifa_next
        }
        return nil
    }
}

public struct CounterTracker {
    private var last: InterfaceCounters?
    private var lastDate: Date?
    private var totalIn: UInt64 = 0
    private var totalOut: UInt64 = 0

    public init() {}

    public mutating func sample(_ counters: InterfaceCounters?, now: Date = Date()) -> ThroughputSample? {
        guard let counters else { return nil }
        defer {
            last = counters
            lastDate = now
        }
        guard let previous = last, let previousDate = lastDate else {
            return ThroughputSample(bytesIn: 0, bytesOut: 0, bpsIn: 0, bpsOut: 0)
        }
        let seconds = max(now.timeIntervalSince(previousDate), 0.001)
        let deltaIn = wrapAwareDelta(current: counters.bytesIn, previous: previous.bytesIn, seconds: seconds)
        let deltaOut = wrapAwareDelta(current: counters.bytesOut, previous: previous.bytesOut, seconds: seconds)
        totalIn += deltaIn
        totalOut += deltaOut
        return ThroughputSample(
            bytesIn: totalIn,
            bytesOut: totalOut,
            bpsIn: UInt64((Double(deltaIn) * 8.0 / seconds).rounded()),
            bpsOut: UInt64((Double(deltaOut) * 8.0 / seconds).rounded())
        )
    }

    private func wrapAwareDelta(current: UInt64, previous: UInt64, seconds: TimeInterval) -> UInt64 {
        if current >= previous { return current - previous }
        let wrap = UInt64(UInt32.max) + 1 - previous + current
        let plausible = max(100_000_000.0, seconds * 1_250_000_000.0)
        return Double(wrap) <= plausible ? wrap : 0
    }
}
