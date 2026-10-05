import Foundation
import CoreWLAN
import CoreLocation

public enum BundleLocator {
    public static func bundleURL(forExecutablePath path: String) -> URL? {
        let normalized = (path as NSString).standardizingPath
        let components = normalized.split(separator: "/", omittingEmptySubsequences: true).map(String.init)
        guard components.count >= 4,
              components[components.count - 2] == "MacOS",
              components[components.count - 3] == "Contents",
              components[components.count - 4].hasSuffix(".app") else { return nil }
        let bundleComponents = components.dropLast(3)
        return URL(fileURLWithPath: "/" + bundleComponents.joined(separator: "/"), isDirectory: true)
    }

    public static func shouldReexec(argv0: String, resolved: String) -> Bool {
        let argvPath = (argv0 as NSString).standardizingPath
        let resolvedPath = (resolved as NSString).standardizingPath
        return argvPath != resolvedPath && bundleURL(forExecutablePath: resolvedPath) != nil
    }

    public static func protectedFolderHint(bundlePath: String, home: String) -> String? {
        let bundle = (bundlePath as NSString).standardizingPath
        let root = (home as NSString).standardizingPath
        for folder in ["Documents", "Desktop", "Downloads"] {
            let prefix = "\(root)/\(folder)/"
            if bundle == "\(root)/\(folder)" || bundle.hasPrefix(prefix) {
                return folder
            }
        }
        return nil
    }
}

public enum BSSIDSource: String, Equatable {
    case live
    case cache
}

public enum LocationCacheReason: String, Equatable {
    case notBundled
    case noGrant
}

public enum LocationAuthorizationState: Equatable {
    case notDetermined
    case authorized
    case denied
    case restricted
    case unknown
}

public enum LocationGateAction: Equatable {
    case live
    case requestPrompt
    case handshake
    case cacheMode(reason: LocationCacheReason)
}

public struct LocationGateDecisionInput: Equatable {
    public var isBundled: Bool
    public var hasBSSID: Bool
    public var authorization: LocationAuthorizationState

    public init(isBundled: Bool, hasBSSID: Bool, authorization: LocationAuthorizationState) {
        self.isBundled = isBundled
        self.hasBSSID = hasBSSID
        self.authorization = authorization
    }
}

public enum LocationGateDecision {
    public static func decide(_ input: LocationGateDecisionInput) -> LocationGateAction {
        if !input.isBundled { return .cacheMode(reason: .notBundled) }
        switch input.authorization {
        case .authorized: return input.hasBSSID ? .live : .handshake
        // A BSSID with no grant comes from a stale grant for an older build.
        // airportd withholds the next one, so ask instead of trusting it.
        case .notDetermined: return .requestPrompt
        case .denied, .restricted, .unknown: return .cacheMode(reason: .noGrant)
        }
    }
}

public struct LocationGateResult: Equatable {
    public var source: BSSIDSource
    public var cacheReason: LocationCacheReason?
    public var canRecheck: Bool
    public var protectedFolder: String?

    public init(source: BSSIDSource, cacheReason: LocationCacheReason? = nil, canRecheck: Bool = false, protectedFolder: String? = nil) {
        self.source = source
        self.cacheReason = cacheReason
        self.canRecheck = canRecheck
        self.protectedFolder = protectedFolder
    }
}

public final class LocationGateRuntime: NSObject, CLLocationManagerDelegate {
    private let interfaceName: String
    private let executablePath: String?
    private let jsonMode: Bool
    private let manager = CLLocationManager()
    private var completion: ((LocationGateResult) -> Void)?
    private var completed = false
    private var handshakeTried = false
    private var promptRequested = false
    private var promptDeadline: Date?

    public init(interfaceName: String, executablePath: String?, jsonMode: Bool = false) {
        self.interfaceName = interfaceName
        self.executablePath = executablePath
        self.jsonMode = jsonMode
        super.init()
        manager.delegate = self
    }

    public func start(completion: @escaping (LocationGateResult) -> Void) {
        self.completion = completion
        DispatchQueue.main.async { self.evaluate() }
    }

    public func locationManagerDidChangeAuthorization(_ manager: CLLocationManager) {
        evaluate()
    }

    // Called by the monitor when live mode loses the BSSID mid-run.
    // Returns true when a prompt was requested.
    public func requestPromptAgain() -> Bool {
        guard authState(manager.authorizationStatus) == .notDetermined else { return false }
        DispatchQueue.main.async { self.manager.requestWhenInUseAuthorization() }
        return true
    }

    private func evaluate() {
        guard !completed else { return }
        let bundle = appBundle()
        let bundled = bundle?.bundleIdentifier != nil
        let hasBSSID = liveBSSID() != nil
        let authorization = authState(manager.authorizationStatus)
        let action = LocationGateDecision.decide(LocationGateDecisionInput(isBundled: bundled, hasBSSID: hasBSSID, authorization: authorization))
        switch action {
        case .live:
            finish(LocationGateResult(source: .live))
        case .cacheMode(let reason):
            finish(LocationGateResult(source: .cache, cacheReason: reason, canRecheck: bundled && reason == .noGrant, protectedFolder: protectedFolderIfNeeded(bundle: bundle, authorization: authorization)))
        case .requestPrompt:
            guard !promptRequested else { return }
            promptRequested = true
            promptDeadline = Date().addingTimeInterval(60)
            // JSON consumers read stdout line by line, so the prompt note goes to stderr there.
            let note = "Waiting for the Location prompt. Click Allow so iairport can read the SSID and BSSID."
            if jsonMode {
                FileHandle.standardError.write(Data((note + "\n").utf8))
            } else {
                print(note)
            }
            manager.requestWhenInUseAuthorization()
            schedulePromptPoll()
            DispatchQueue.main.asyncAfter(deadline: .now() + .seconds(60)) { [weak self] in
                guard let self, !self.completed else { return }
                self.finish(LocationGateResult(source: .cache, cacheReason: .noGrant, canRecheck: true, protectedFolder: self.protectedFolderIfNeeded(bundle: self.appBundle(), authorization: self.authState(self.manager.authorizationStatus))))
            }
        case .handshake:
            startHandshake()
        }
    }

    private func startHandshake() {
        guard !handshakeTried else { return }
        handshakeTried = true
        runHandshakeThenRetry()
    }

    private func runHandshakeThenRetry() {
        DispatchQueue.global(qos: .utility).async {
            let process = Process()
            process.executableURL = URL(fileURLWithPath: "/usr/bin/open")
            process.arguments = ["-g", "-j", self.appBundle()?.bundleURL.path ?? Bundle.main.bundleURL.path, "--args", "--handshake"]
            process.standardOutput = Pipe()
            process.standardError = Pipe()
            do {
                try process.run()
                process.waitUntilExit()
            } catch {}
            DispatchQueue.main.asyncAfter(deadline: .now() + .milliseconds(500)) { [weak self] in
                self?.retryAfterHandshake(secondRetry: false)
            }
        }
    }

    private func schedulePromptPoll() {
        DispatchQueue.main.asyncAfter(deadline: .now() + .seconds(1)) { [weak self] in
            self?.pollPrompt()
        }
    }

    private func pollPrompt() {
        guard !completed else { return }
        switch authState(manager.authorizationStatus) {
        case .authorized:
            if liveBSSID() != nil {
                finish(LocationGateResult(source: .live))
            } else {
                startHandshake()
            }
        case .denied, .restricted, .unknown:
            finish(LocationGateResult(source: .cache, cacheReason: .noGrant, canRecheck: true))
        case .notDetermined:
            if let promptDeadline, Date() >= promptDeadline {
                finish(LocationGateResult(source: .cache, cacheReason: .noGrant, canRecheck: true))
            } else {
                schedulePromptPoll()
            }
        }
    }

    private func retryAfterHandshake(secondRetry: Bool) {
        guard !completed else { return }
        if liveBSSID() != nil {
            finish(LocationGateResult(source: .live))
            return
        }
        if secondRetry {
            finish(LocationGateResult(source: .cache, cacheReason: .noGrant, canRecheck: true, protectedFolder: protectedFolderIfNeeded(bundle: appBundle(), authorization: authState(manager.authorizationStatus))))
        } else {
            DispatchQueue.main.asyncAfter(deadline: .now() + .milliseconds(1500)) { [weak self] in
                self?.retryAfterHandshake(secondRetry: true)
            }
        }
    }

    private func finish(_ result: LocationGateResult) {
        guard !completed else { return }
        completed = true
        completion?(result)
        completion = nil
    }

    private func liveBSSID() -> String? {
        let iface = CWWiFiClient.shared().interface(withName: interfaceName) ?? CWWiFiClient.shared().interface()
        return MACAddress.normalize(iface?.bssid())
    }

    private func appBundle() -> Bundle? {
        if Bundle.main.bundleIdentifier != nil {
            return Bundle.main
        }
        guard let executablePath,
              let bundleURL = BundleLocator.bundleURL(forExecutablePath: executablePath) else { return nil }
        return Bundle(url: bundleURL)
    }

    private func protectedFolderIfNeeded(bundle: Bundle?, authorization: LocationAuthorizationState) -> String? {
        guard authorization == .authorized, let path = bundle?.bundleURL.path else { return nil }
        return BundleLocator.protectedFolderHint(bundlePath: path, home: NSHomeDirectory())
    }

    private func authState(_ status: CLAuthorizationStatus) -> LocationAuthorizationState {
        switch status {
        case .notDetermined: return .notDetermined
        case .authorizedAlways, .authorized: return .authorized
        case .denied: return .denied
        case .restricted: return .restricted
        @unknown default: return .unknown
        }
    }
}
