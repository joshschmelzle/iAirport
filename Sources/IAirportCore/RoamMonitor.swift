import Foundation
import CoreWLAN
import SystemConfiguration

public final class CoreWLANEventBridge: NSObject, CWEventDelegate {
    private let interfaceName: String
    private let queue: DispatchQueue
    private let trigger: (String) -> Void
    private let client: CWWiFiClient

    public init(interfaceName: String, queue: DispatchQueue, trigger: @escaping (String) -> Void) {
        self.interfaceName = interfaceName
        self.queue = queue
        self.trigger = trigger
        client = CWWiFiClient.shared()
        super.init()
        client.delegate = self
    }

    public func start() {
        _ = tryStart(.bssidDidChange)
        _ = tryStart(.linkDidChange)
    }

    public func stop() {
        try? client.stopMonitoringAllEvents()
    }

    public func bssidDidChangeForWiFiInterface(withName interfaceName: String) {
        guard interfaceName == self.interfaceName else { return }
        queue.async { self.trigger("corewlan-bssid") }
    }

    public func linkDidChangeForWiFiInterface(withName interfaceName: String) {
        guard interfaceName == self.interfaceName else { return }
        queue.async { self.trigger("corewlan-link") }
    }

    private func tryStart(_ type: CWEventType) -> Bool {
        do {
            try client.startMonitoringEvent(with: type)
            return true
        } catch {
            return false
        }
    }
}

public final class DynamicStoreWatcher {
    private let interfaceName: String
    private let queue: DispatchQueue
    private let callback: ([String]) -> Void
    private var store: SCDynamicStore?

    public init(interfaceName: String, queue: DispatchQueue, callback: @escaping ([String]) -> Void) {
        self.interfaceName = interfaceName
        self.queue = queue
        self.callback = callback
    }

    public func start() {
        var context = SCDynamicStoreContext(
            version: 0,
            info: UnsafeMutableRawPointer(Unmanaged.passUnretained(self).toOpaque()),
            retain: nil,
            release: nil,
            copyDescription: nil
        )
        let created = SCDynamicStoreCreate(nil, "iairport" as CFString, { _, changed, info in
            guard let info else { return }
            let watcher = Unmanaged<DynamicStoreWatcher>.fromOpaque(info).takeUnretainedValue()
            let keys = (changed as? [String]) ?? []
            watcher.callback(keys)
        }, &context)
        guard let created else { return }
        let keys: [String] = [
            "State:/Network/Interface/\(interfaceName)/AirPort",
            "State:/Network/Interface/\(interfaceName)/IPv4",
            "State:/Network/Interface/\(interfaceName)/IPv6",
            "State:/Network/Global/IPv4",
            "State:/Network/Global/IPv6"
        ]
        let patterns: [String] = [
            "State:/Network/Interface/\(interfaceName)/AirPort.*",
            "State:/Network/Service/.*/(DHCP|DHCPv6|IPv4|IPv6)"
        ]
        SCDynamicStoreSetNotificationKeys(created, keys as CFArray, patterns as CFArray)
        SCDynamicStoreSetDispatchQueue(created, queue)
        store = created
    }

    public func stop() {
        if let store {
            SCDynamicStoreSetDispatchQueue(store, nil)
        }
        store = nil
    }
}
