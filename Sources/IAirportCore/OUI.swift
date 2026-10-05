import Foundation

public final class OUI {
    private let vendors: [String: String]
    public let path: String?

    public init(vendors: [String: String] = [:], path: String? = nil) {
        self.vendors = vendors
        self.path = path
    }

    public static func load(explicitPath: String?, executablePath: String? = nil, workingDirectory: String = FileManager.default.currentDirectoryPath) -> (OUI, String?) {
        var candidates: [String] = []
        if let explicitPath { candidates.append(explicitPath) }
        if let bundlePath = Bundle.main.resourceURL?.appendingPathComponent("oui.txt").path {
            candidates.append(bundlePath)
        }
        if let executablePath,
           let bundleURL = BundleLocator.bundleURL(forExecutablePath: executablePath),
           let resourcePath = Bundle(url: bundleURL)?.resourceURL?.appendingPathComponent("oui.txt").path {
            candidates.append(resourcePath)
        }
        candidates.append(workingDirectory + "/oui.txt")
        if let executablePath {
            let dir = URL(fileURLWithPath: executablePath).deletingLastPathComponent().path
            candidates.append(dir + "/oui.txt")
            candidates.append(URL(fileURLWithPath: dir).appendingPathComponent("../../oui.txt").standardizedFileURL.path)
        }
        candidates.append("/usr/local/share/iairport/oui.txt")
        for path in candidates {
            if FileManager.default.fileExists(atPath: path) {
                return (load(path: path), nil)
            }
        }
        return (OUI(), "OUI data file missing. Vendor names will be empty.")
    }

    public static func load(path: String) -> OUI {
        guard let text = try? String(contentsOfFile: path, encoding: .utf8) else {
            return OUI(path: path)
        }
        var values: [String: String] = [:]
        for raw in text.split(separator: "\n", omittingEmptySubsequences: false) {
            let line = raw.trimmingCharacters(in: .whitespacesAndNewlines)
            if line.isEmpty || line.hasPrefix("#") { continue }
            let parts = line.split(whereSeparator: { $0 == " " || $0 == "\t" })
            guard parts.count >= 2 else { continue }
            let key = String(parts[0]).uppercased()
            guard key.range(of: "^([0-9A-F]{2}:){2}[0-9A-F]{2}$", options: .regularExpression) != nil else { continue }
            values[key] = String(parts[1])
        }
        return OUI(vendors: values, path: path)
    }

    public func vendor(for bssid: String?) -> String? {
        guard let key = MACAddress.oui(bssid) else { return nil }
        return vendors[key]
    }
}
