import Foundation
import Darwin

// `sudo iairport` starts as root. Root has no Location grant, so the monitor
// must run as the invoking user. sudo 1.9.14+ runs commands in a new pty and
// ties its ticket to the tty, so the user process cannot call `sudo -n`.
// The root process therefore stays alive as a wdutil helper and spawns the
// user process with one end of a socketpair.

/// Wire format between the user process and the root helper.
/// Request: wdutil arguments joined by spaces, one line.
/// Response: "<status> <byteCount>\n" then byteCount bytes of wdutil output.
public enum RootHelperProtocol {
    public static let allowedCommands: [[String]] = [["info"], ["log"], ["log", "+wifi"], ["log", "-wifi"]]

    public static func encodeRequest(_ arguments: [String]) -> Data? {
        guard allowedCommands.contains(arguments) else { return nil }
        return Data((arguments.joined(separator: " ") + "\n").utf8)
    }

    public static func parseRequest(_ line: String) -> [String]? {
        let arguments = line.trimmingCharacters(in: .newlines).split(separator: " ").map(String.init)
        return allowedCommands.contains(arguments) ? arguments : nil
    }

    public static func encodeResponse(status: Int32, output: Data) -> Data {
        var data = Data("\(status) \(output.count)\n".utf8)
        data.append(output)
        return data
    }

    public static func parseResponseHeader(_ line: String) -> (status: Int32, count: Int)? {
        let parts = line.trimmingCharacters(in: .newlines).split(separator: " ")
        guard parts.count == 2, let status = Int32(parts[0]), let count = Int(parts[1]), count >= 0 else { return nil }
        return (status, count)
    }
}

public struct DropTarget: Equatable {
    public var uid: uid_t
    public var gid: gid_t
    public var user: String
    public var home: String

    public init(uid: uid_t, gid: gid_t, user: String, home: String) {
        self.uid = uid
        self.gid = gid
        self.user = user
        self.home = home
    }

    public static let environmentKey = "IAIRPORT_DROP_TO"

    public var encoded: String { "\(uid):\(gid):\(user):\(home)" }

    public static func decode(_ text: String) -> DropTarget? {
        let parts = text.split(separator: ":", maxSplits: 3, omittingEmptySubsequences: false)
        guard parts.count == 4, let uid = uid_t(parts[0]), let gid = gid_t(parts[1]), uid != 0,
              !parts[2].isEmpty, parts[3].hasPrefix("/") else { return nil }
        return DropTarget(uid: uid, gid: gid, user: String(parts[2]), home: String(parts[3]))
    }

    public static func lookup(uid: uid_t) -> DropTarget? {
        guard uid != 0, let entry = getpwuid(uid) else { return nil }
        return DropTarget(uid: uid, gid: entry.pointee.pw_gid, user: String(cString: entry.pointee.pw_name), home: String(cString: entry.pointee.pw_dir))
    }

    /// Environment for the user child: the parent's environment plus the
    /// helper fd and the user's identity. HOME matters because NSHomeDirectory
    /// drives the protected-folder hint.
    public static func childEnvironment(base: [String: String], target: DropTarget, helperFD: Int32) -> [String: String] {
        var env = base
        env["IAIRPORT_SUDO"] = "1"
        env[RootHelperClient.environmentKey] = String(helperFD)
        env[environmentKey] = target.encoded
        env["HOME"] = target.home
        env["USER"] = target.user
        env["LOGNAME"] = target.user
        return env
    }

    /// Drops root to the target user. Returns false when any step fails.
    public func apply() -> Bool {
        guard initgroups(user, Int32(bitPattern: gid)) == 0, setgid(gid) == 0, setuid(uid) == 0 else { return false }
        return getuid() == uid && geteuid() == uid
    }
}

enum FDIO {
    static func writeAll(_ fd: Int32, _ data: Data) -> Bool {
        var remaining = [UInt8](data)
        while !remaining.isEmpty {
            let written = remaining.withUnsafeBufferPointer { write(fd, $0.baseAddress, $0.count) }
            if written < 0 {
                if errno == EINTR { continue }
                return false
            }
            remaining.removeFirst(written)
        }
        return true
    }

    static func readLine(_ fd: Int32) -> String? {
        var bytes: [UInt8] = []
        var byte: UInt8 = 0
        while true {
            let got = read(fd, &byte, 1)
            if got < 0 {
                if errno == EINTR { continue }
                return nil
            }
            if got == 0 { return bytes.isEmpty ? nil : String(decoding: bytes, as: UTF8.self) }
            if byte == UInt8(ascii: "\n") { return String(decoding: bytes, as: UTF8.self) }
            bytes.append(byte)
            if bytes.count > 4096 { return nil }
        }
    }

    static func readExactly(_ fd: Int32, _ count: Int) -> Data? {
        var data = Data()
        var buffer = [UInt8](repeating: 0, count: 65536)
        while data.count < count {
            let want = min(buffer.count, count - data.count)
            let got = buffer.withUnsafeMutableBufferPointer { read(fd, $0.baseAddress, want) }
            if got < 0 {
                if errno == EINTR { continue }
                return nil
            }
            if got == 0 { return nil }
            data.append(contentsOf: buffer[0..<got])
        }
        return data
    }
}

/// User-process side. Serialises requests because the socket carries one
/// exchange at a time.
public final class RootHelperClient {
    public static let environmentKey = "IAIRPORT_HELPER_FD"
    public static let shared: RootHelperClient? = {
        guard let raw = getenv(environmentKey), let fd = Int32(String(cString: raw)) else { return nil }
        _ = fcntl(fd, F_SETFD, FD_CLOEXEC)
        return RootHelperClient(fd: fd)
    }()

    private let fd: Int32
    private let lock = NSLock()

    public init(fd: Int32) {
        self.fd = fd
    }

    public func run(arguments: [String]) -> (text: String?, status: Int32) {
        guard let request = RootHelperProtocol.encodeRequest(arguments) else { return (nil, 1) }
        lock.lock()
        defer { lock.unlock() }
        guard FDIO.writeAll(fd, request),
              let header = FDIO.readLine(fd),
              let parsed = RootHelperProtocol.parseResponseHeader(header),
              let body = FDIO.readExactly(fd, parsed.count) else { return (nil, 1) }
        return (String(data: body, encoding: .utf8), parsed.status)
    }
}

/// Root side. Spawns the user child, answers its wdutil requests until the
/// socket closes, then exits with the child's status.
public enum RootHelperServer {
    public enum LaunchError: Error, Equatable {
        case noPasswdEntry
        case socketpair(Int32)
        case spawn(Int32)
    }

    public static func launchUserChild(executable: String, arguments: [String], uid: uid_t) -> Result<(pid: pid_t, fd: Int32), LaunchError> {
        guard let target = DropTarget.lookup(uid: uid) else { return .failure(.noPasswdEntry) }
        var pair: [Int32] = [-1, -1]
        guard socketpair(AF_UNIX, SOCK_STREAM, 0, &pair) == 0 else { return .failure(.socketpair(errno)) }
        let parentFD = pair[0]
        let childFD = pair[1]
        _ = fcntl(parentFD, F_SETFD, FD_CLOEXEC)

        let env = DropTarget.childEnvironment(base: ProcessInfo.processInfo.environment, target: target, helperFD: childFD)
        var argv: [UnsafeMutablePointer<CChar>?] = ([executable] + arguments).map { strdup($0) }
        argv.append(nil)
        var envp: [UnsafeMutablePointer<CChar>?] = env.map { strdup("\($0.key)=\($0.value)") }
        envp.append(nil)
        defer {
            for pointer in argv where pointer != nil { free(pointer) }
            for pointer in envp where pointer != nil { free(pointer) }
        }

        var pid: pid_t = 0
        let rc = posix_spawn(&pid, executable, nil, nil, argv, envp)
        close(childFD)
        guard rc == 0 else {
            close(parentFD)
            return .failure(.spawn(rc))
        }
        return .success((pid, parentFD))
    }

    public static func serve(fd: Int32, childPID: pid_t) -> Never {
        // The terminal delivers SIGINT to the whole group; the child handles it
        // and closes the socket. Forward the signals that target only this pid.
        signal(SIGINT, SIG_IGN)
        signal(SIGTERM, SIG_IGN)
        signal(SIGHUP, SIG_IGN)
        // The child may exit while a wdutil request is in flight; the reply
        // then hits a closed socket and must return EPIPE, not kill root.
        signal(SIGPIPE, SIG_IGN)
        let forwarders = [SIGTERM, SIGHUP].map { number -> DispatchSourceSignal in
            let source = DispatchSource.makeSignalSource(signal: number, queue: .global())
            source.setEventHandler { kill(childPID, number) }
            source.resume()
            return source
        }
        defer { _ = forwarders }

        while let line = FDIO.readLine(fd) {
            let response: Data
            if let arguments = RootHelperProtocol.parseRequest(line) {
                let result = runWdutil(arguments)
                response = RootHelperProtocol.encodeResponse(status: result.status, output: result.output)
            } else {
                response = RootHelperProtocol.encodeResponse(status: 2, output: Data())
            }
            guard FDIO.writeAll(fd, response) else { break }
        }
        close(fd)

        var status: Int32 = 0
        while waitpid(childPID, &status, 0) < 0 && errno == EINTR {}
        let signaled = status & 0x7f
        exit(signaled == 0 ? (status >> 8) & 0xff : 128 + signaled)
    }

    private static func runWdutil(_ arguments: [String]) -> (output: Data, status: Int32) {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/wdutil")
        process.arguments = arguments
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe
        do {
            try process.run()
            let data = pipe.fileHandleForReading.readDataToEndOfFile()
            process.waitUntilExit()
            return (data, process.terminationStatus)
        } catch {
            return (Data(), 1)
        }
    }
}
