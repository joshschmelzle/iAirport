import XCTest
@testable import IAirportCore

final class LogClassifierTests: XCTestCase {
    func testLQMLine() {
        let line = "2026-10-04 16:41:34.152 Df airportd[483:e6ea3b] [com.apple.WiFiManager:] [corewifi] LQM: rssi=-59dBm per_ant_rssi=(-60dBm, -61dBm) noise=-90dBm snr=25 cca=11.0% txRate=576.5Mbps txFrames=416582 txFail=46 txRetrans=25709 rxRate=612.5Mbps rxFrames=744616 rxRetryFrames=8084 network = <redacted> bssid = <redacted> channel = 136 BW = 80 band = 2"
        guard case .lqm(let metrics)? = LogClassifier.classify(line: line) else { return XCTFail("expected LQM") }
        XCTAssertEqual(metrics.rssi, -59)
        XCTAssertEqual(metrics.noise, -90)
        XCTAssertEqual(metrics.snr, 25)
        XCTAssertEqual(metrics.cca, 11)
        XCTAssertEqual(metrics.perAntennaRSSI, [-60, -61])
        XCTAssertEqual(metrics.bandwidth, 80)
        XCTAssertEqual(metrics.band, "5")
    }

    func testDriverRoamedLine() {
        let line = "... [com.apple.WiFiManager:] Driver Event: <airport[483]> _bsd_80211_event_callback: APPLE80211_M_ROAMED/32 (en0)"
        XCTAssertEqual(LogClassifier.classify(line: line), .driverRoamed)
    }

    func testDeauthLine() {
        let line = "Received Deauth from aa:bb:cc:dd:ee:ff with Reason 3"
        guard case .deauth(let kind, let source, let reason)? = LogClassifier.classify(line: line) else { return XCTFail("expected deauth") }
        XCTAssertEqual(kind, "Deauth")
        XCTAssertEqual(source, "aa:bb:cc:dd:ee:ff")
        XCTAssertEqual(reason, 3)
        XCTAssertTrue(ReasonCodes.suffix(for: 3).contains("ClientMatch"))
    }

    func testDHCPLine() {
        let line = "... SC: <airport[483]> airportdProcessSystemConfigurationEvent: Processing DHCP: 'State:/Network/Service/102013F8-584E-46C6-8C6E-A645246CFBD7/DHCP'"
        XCTAssertEqual(LogClassifier.classify(line: line), .dhcp(service: "102013F8-584E-46C6-8C6E-A645246CFBD7"))
    }

    func testJoinTimingLine() {
        let line = "AUTO-JOIN: Updated join status (uuid=B1D76, intf=en0, assoc=2026-10-03 19:41:01.328 -0400 (272ms), auth=2026-10-03 19:41:02.004 -0400 (948ms), linkup=2026-10-03 19:41:01.338 -0400 (281ms), ipv4=2026-10-03 19:41:02.392 -0400 (1336ms), ipv4Primary=2026-10-03 19:41:03.886 -0400 (2829ms), ipv6=2026-10-03 19:41:02.599 -0400 (1542ms), ipv6Primary=2026-10-03 19:41:03.591 -0400 (2534ms))"
        guard case .joinTiming(let timing)? = LogClassifier.classify(line: line) else { return XCTFail("expected timing") }
        XCTAssertEqual(timing.values["assoc"], 272)
        XCTAssertEqual(timing.values["auth"], 948)
        XCTAssertEqual(timing.values["ipv4"], 1336)
        XCTAssertEqual(timing.values["ipv6Primary"], 2534)
    }

    func testJoinTimingGateRejectsStaleStart() {
        let launch = Date(timeIntervalSince1970: 1_000)
        var gate = JoinTimingGate(launchDate: launch)
        let timing = JoinTiming(values: ["assoc": 1, "auth": 2, "linkup": 3, "ipv4": 4, "ipv6": 5], uuid: "old", start: Date(timeIntervalSince1970: 900))
        XCTAssertFalse(gate.accept(timing, now: launch.addingTimeInterval(1)))
    }

    func testJoinTimingGateDedupesUUID() {
        let launch = Date(timeIntervalSince1970: 1_000)
        var gate = JoinTimingGate(launchDate: launch)
        let timing = JoinTiming(values: ["assoc": 1, "auth": 2, "linkup": 3, "ipv4": 4, "ipv6": 5], uuid: "same", start: launch.addingTimeInterval(1))
        XCTAssertTrue(gate.accept(timing, now: launch.addingTimeInterval(2)))
        XCTAssertFalse(gate.accept(timing, now: launch.addingTimeInterval(3)))
    }

    func testJoinTimingGateRejectsPartialLine() {
        let launch = Date(timeIntervalSince1970: 1_000)
        var gate = JoinTimingGate(launchDate: launch)
        let timing = JoinTiming(values: ["assoc": 1], uuid: "partial", start: launch.addingTimeInterval(1))
        XCTAssertFalse(gate.accept(timing, now: launch.addingTimeInterval(2)))
    }

    func testAssociatedNetworkFT() {
        let line = "AUTO-JOIN: Updated associated network (<redacted> - ssid=<redacted>, bssid=<redacted>, security=wpa2-enterprise, rsn=[auths={ 8021x ft_8021x }, mfp=no])"
        guard case .associatedNetwork(let info)? = LogClassifier.classify(line: line) else { return XCTFail("expected associated network") }
        XCTAssertEqual(info.security, "wpa2-enterprise")
        XCTAssertTrue(info.ft)
        XCTAssertFalse(info.mfp)
    }

    func testRoamRequest() {
        let info = LogClassifier.parseRoamRequest(lines: [
            "    BSSID = \"ff:ff:ff:ff:ff:ff\";",
            "    CHANNEL = 44;",
            "    \"ROAM_FLAGS\" = 0;",
            "    \"SSID_STR\" = \"ExampleNet\";"
        ])
        XCTAssertEqual(info.targetDisplay, "any")
        XCTAssertEqual(info.channel, 44)
        XCTAssertEqual(info.flags, 0)
        XCTAssertEqual(info.ssid, "ExampleNet")
    }

    func testRoamRequestCaptureAbortsOnTimestamp() {
        var capture = RoamRequestCapture()
        XCTAssertEqual(capture.consume("    BSSID = \"ff:ff:ff:ff:ff:ff\";"), .collecting)
        let line = "2026-10-04 16:41:34.152 Df airportd[483:e6ea3b] next event"
        XCTAssertEqual(capture.consume(line), .aborted(reprocess: line))
    }

    func testRoamRequestCaptureAbortsAfterLimit() {
        var capture = RoamRequestCapture(maxLines: 1)
        XCTAssertEqual(capture.consume("    CHANNEL = 44;"), .collecting)
        XCTAssertEqual(capture.consume("    SSID_STR = \"x\";"), .aborted(reprocess: "    SSID_STR = \"x\";"))
    }

    func testScanSummary() {
        let line = "Scan: <airport[483]> Completed scan for pid 1 (airportd) (error=0, duration=1.0)"
        XCTAssertEqual(LogClassifier.classify(line: line), .scanSummary(line))
    }

    func testRoamInfoLineIsNoise() {
        let line = "(WiFiPolicy) airportd RoamInfo - LastRoam: None for en0"
        XCTAssertNil(LogClassifier.classify(line: line))
    }
}

final class AssociationStateTests: XCTestCase {
    func testTransitions() {
        var tracker = AssociationTracker()
        let t0 = Date(timeIntervalSince1970: 0)
        let a = AssociationSnapshot.associated(AssociationInfo(bssid: "aa:bb:cc:dd:ee:01", ssid: "s", channel: 1, rssi: -60, since: t0))
        let b = AssociationSnapshot.associated(AssociationInfo(bssid: "aa:bb:cc:dd:ee:02", ssid: "s", channel: 6, rssi: -50, since: t0))
        XCTAssertEqual(tracker.commit(a, at: t0)?.kind, .join)
        XCTAssertNil(tracker.commit(a, at: t0.addingTimeInterval(1)))
        XCTAssertEqual(tracker.commit(b, at: t0.addingTimeInterval(2))?.kind, .roam)
        XCTAssertEqual(tracker.commit(a, at: t0.addingTimeInterval(3))?.kind, .roam)
        XCTAssertEqual(tracker.commit(.disconnected, at: t0.addingTimeInterval(4))?.kind, .disconnect)
        XCTAssertEqual(tracker.commit(a, at: t0.addingTimeInterval(5))?.kind, .reconnect)
    }

    func testNilJoin() {
        var tracker = AssociationTracker()
        XCTAssertNil(tracker.commit(.disconnected, at: Date()))
        let join = tracker.commit(.associated(AssociationInfo(bssid: "aa:bb:cc:dd:ee:03", since: Date())), at: Date())
        XCTAssertEqual(join?.kind, .join)
    }

    func testRSSIJitterDoesNotIncrementGeneration() {
        var tracker = AssociationTracker()
        let t0 = Date(timeIntervalSince1970: 0)
        let a1 = AssociationSnapshot.associated(AssociationInfo(bssid: "aa:bb:cc:dd:ee:01", channel: 44, rssi: -50, since: t0))
        let a2 = AssociationSnapshot.associated(AssociationInfo(bssid: "aa:bb:cc:dd:ee:01", channel: 44, rssi: -60, since: t0))
        _ = tracker.commit(a1, at: t0)
        let generation = tracker.generation
        XCTAssertNil(tracker.commit(a2, at: t0.addingTimeInterval(1)))
        XCTAssertEqual(tracker.generation, generation)
    }
}

final class UtilityTests: XCTestCase {
    func testCSVEscaping() {
        XCTAssertEqual(CSV.field("plain"), "plain")
        XCTAssertEqual(CSV.field("a,b"), "\"a,b\"")
        XCTAssertEqual(CSV.field("a\"b"), "\"a\"\"b\"")
    }

    func testCounterRebase() {
        var tracker = CounterTracker()
        _ = tracker.sample(InterfaceCounters(bytesIn: 100, bytesOut: 100), now: Date(timeIntervalSince1970: 0))
        let after = tracker.sample(InterfaceCounters(bytesIn: 90, bytesOut: 120), now: Date(timeIntervalSince1970: 1))
        XCTAssertEqual(after?.bpsIn, 0)
        XCTAssertEqual(after?.bpsOut, 160)
        XCTAssertEqual(after?.bytesIn, 0)
        XCTAssertEqual(after?.bytesOut, 20)
    }

    func testCounterWrapAccumulatesSinceStart() {
        var tracker = CounterTracker()
        _ = tracker.sample(InterfaceCounters(bytesIn: UInt64(UInt32.max) - 10, bytesOut: 200), now: Date(timeIntervalSince1970: 0))
        let after = tracker.sample(InterfaceCounters(bytesIn: 20, bytesOut: 260), now: Date(timeIntervalSince1970: 1))
        XCTAssertEqual(after?.bytesIn, 31)
        XCTAssertEqual(after?.bytesOut, 60)
        XCTAssertEqual(after?.bpsIn, 248)
    }

    func testOUILookup() {
        let oui = OUI(vendors: ["00:0B:86": "Aruba"])
        XCTAssertEqual(oui.vendor(for: "00:0b:86:11:22:01"), "Aruba")
    }

    func testReasonLookup() {
        XCTAssertEqual(ReasonCodes.text(for: 3), "deauthenticated because station is leaving")
        XCTAssertEqual(ReasonCodes.text(for: 999), "unknown")
    }

    func testIPv6KindsAndDisplay() {
        let linkLocal = IPv6AddressInfo(address: "fe80::1", prefix: 64, flags: 1024)
        let stable = IPv6AddressInfo(address: "2600::1", prefix: 64, flags: 1088)
        let temp = IPv6AddressInfo(address: "2600::2", prefix: 64, flags: 192)
        let deprecated = IPv6AddressInfo(address: "2600::3", prefix: 64, flags: 16)
        XCTAssertEqual(linkLocal.kind, .linkLocal)
        XCTAssertEqual(stable.kind, .slaac)
        XCTAssertEqual(temp.kind, .temporary)
        XCTAssertEqual(deprecated.kind, .deprecated)
        let state = IPState(ipv6: [linkLocal, temp, stable])
        XCTAssertEqual(state.displayIPv6?.address, "2600::1")
        XCTAssertEqual(state.temporaryIPv6CountForDisplay, 1)
    }

    func testIPAfterRoamComparison() {
        let before = IPState(ipv4: ["192.0.2.10"], ipv6: [IPv6AddressInfo(address: "2600::1", prefix: 64, flags: 1088)])
        let same = IPState(ipv4: ["192.0.2.10"], ipv6: [IPv6AddressInfo(address: "2600::1", prefix: 64, flags: 1088)])
        let changed = IPState(ipv4: ["192.0.2.11"], ipv6: [IPv6AddressInfo(address: "2600::2", prefix: 64, flags: 1088)])
        XCTAssertEqual(IPStateComparator.compareV4(before: before, after: same, milliseconds: 100), .kept)
        XCTAssertEqual(IPStateComparator.compareV6(before: before, after: same, milliseconds: 100), .kept)
        XCTAssertEqual(IPStateComparator.compareV4(before: before, after: changed, milliseconds: 1300), .renewed(milliseconds: 1300))
        XCTAssertEqual(IPStateComparator.compareV6(before: before, after: changed, milliseconds: 2100), .changed(milliseconds: 2100))
    }

    func testRapidRoamCSVBufferFlushesFirstRow() {
        let t0 = Date(timeIntervalSince1970: 0)
        let a = AssociationInfo(bssid: "aa:bb:cc:dd:ee:01", since: t0)
        let b = AssociationInfo(bssid: "aa:bb:cc:dd:ee:02", since: t0)
        let first = AssociationTransition(kind: .roam, old: a, new: b, at: t0)
        let second = AssociationTransition(kind: .roam, old: b, new: a, at: t0.addingTimeInterval(1))
        var buffer = PendingRoamCSVBuffer()
        XCTAssertNil(buffer.replace(transition: first, timing: nil))
        XCTAssertEqual(buffer.replace(transition: second, timing: nil)?.transition, first)
        XCTAssertEqual(buffer.take()?.transition, second)
    }

    func testCLIRejectsNonFiniteInterval() {
        guard case .failure(let message) = CLIParser.parse(["--interval", "inf"]) else { return XCTFail("expected failure") }
        XCTAssertTrue(message.contains("finite"))
    }

    func testJSONTimestampUsesLocalOffset() {
        let text = TimeFormatter().json(Date(timeIntervalSince1970: 0))
        XCTAssertNotNil(text.range(of: "^\\d{4}-\\d{2}-\\d{2}T", options: .regularExpression))
        XCTAssertNil(text.range(of: "Z$"))
    }

    func testLocationGateDecisions() {
        XCTAssertEqual(LocationGateDecision.decide(LocationGateDecisionInput(isBundled: false, hasBSSID: false, authorization: .authorized)), .cacheMode(reason: .notBundled))
        XCTAssertEqual(LocationGateDecision.decide(LocationGateDecisionInput(isBundled: true, hasBSSID: true, authorization: .authorized)), .live)
        XCTAssertEqual(LocationGateDecision.decide(LocationGateDecisionInput(isBundled: true, hasBSSID: true, authorization: .notDetermined)), .requestPrompt)
        XCTAssertEqual(LocationGateDecision.decide(LocationGateDecisionInput(isBundled: true, hasBSSID: true, authorization: .denied)), .cacheMode(reason: .noGrant))
        XCTAssertEqual(LocationGateDecision.decide(LocationGateDecisionInput(isBundled: true, hasBSSID: false, authorization: .notDetermined)), .requestPrompt)
        XCTAssertEqual(LocationGateDecision.decide(LocationGateDecisionInput(isBundled: true, hasBSSID: false, authorization: .authorized)), .handshake)
        XCTAssertEqual(LocationGateDecision.decide(LocationGateDecisionInput(isBundled: true, hasBSSID: false, authorization: .denied)), .cacheMode(reason: .noGrant))
        XCTAssertEqual(LocationGateDecision.decide(LocationGateDecisionInput(isBundled: true, hasBSSID: false, authorization: .restricted)), .cacheMode(reason: .noGrant))
        XCTAssertEqual(LocationGateDecision.decide(LocationGateDecisionInput(isBundled: true, hasBSSID: false, authorization: .unknown)), .cacheMode(reason: .noGrant))
    }

    func testBundleLocatorFindsAppBundle() {
        let path = "/usr/local/libexec/iairport.app/Contents/MacOS/iairport"
        XCTAssertEqual(BundleLocator.bundleURL(forExecutablePath: path)?.path, "/usr/local/libexec/iairport.app")
        XCTAssertNil(BundleLocator.bundleURL(forExecutablePath: "/tmp/release/iairport"))
    }

    func testBundleLocatorReexecDecision() {
        let resolved = "/usr/local/libexec/iairport.app/Contents/MacOS/iairport"
        XCTAssertTrue(BundleLocator.shouldReexec(argv0: "/usr/local/bin/iairport", resolved: resolved))
        XCTAssertFalse(BundleLocator.shouldReexec(argv0: resolved, resolved: resolved))
        XCTAssertFalse(BundleLocator.shouldReexec(argv0: ".build/release/iairport", resolved: "/tmp/release/iairport"))
    }

    func testProtectedFolderHint() {
        let home = "/Users/example"
        XCTAssertEqual(BundleLocator.protectedFolderHint(bundlePath: "\(home)/Documents/iairport.app", home: home), "Documents")
        XCTAssertEqual(BundleLocator.protectedFolderHint(bundlePath: "\(home)/Desktop/tools/iairport.app", home: home), "Desktop")
        XCTAssertEqual(BundleLocator.protectedFolderHint(bundlePath: "\(home)/Downloads/iairport.app", home: home), "Downloads")
        XCTAssertNil(BundleLocator.protectedFolderHint(bundlePath: "/usr/local/libexec/iairport.app", home: home))
        XCTAssertNil(BundleLocator.protectedFolderHint(bundlePath: "\(home)/src/iairport.app", home: home))
    }

    func testRootHelperProtocolRoundTrip() {
        XCTAssertEqual(RootHelperProtocol.encodeRequest(["log", "+wifi"]), Data("log +wifi\n".utf8))
        XCTAssertNil(RootHelperProtocol.encodeRequest(["scan"]))
        XCTAssertNil(RootHelperProtocol.encodeRequest(["info", "; rm -rf /"]))
        XCTAssertEqual(RootHelperProtocol.parseRequest("info\n"), ["info"])
        XCTAssertNil(RootHelperProtocol.parseRequest("diagnose\n"))
        XCTAssertNil(RootHelperProtocol.parseRequest(""))
        let response = RootHelperProtocol.encodeResponse(status: 0, output: Data("RSSI: -50\n".utf8))
        XCTAssertEqual(String(decoding: response, as: UTF8.self), "0 10\nRSSI: -50\n")
        let header = RootHelperProtocol.parseResponseHeader("1 42\n")
        XCTAssertEqual(header?.status, 1)
        XCTAssertEqual(header?.count, 42)
        XCTAssertNil(RootHelperProtocol.parseResponseHeader("1 -5"))
        XCTAssertNil(RootHelperProtocol.parseResponseHeader("garbage"))
    }

    func testDropTargetEncoding() {
        let target = DropTarget(uid: 501, gid: 20, user: "user", home: "/Users/user")
        XCTAssertEqual(DropTarget.decode(target.encoded), target)
        XCTAssertNil(DropTarget.decode("0:0:root:/var/root"))
        XCTAssertNil(DropTarget.decode("501:20::/Users/user"))
        XCTAssertNil(DropTarget.decode("501:20:user:relative"))
        let env = DropTarget.childEnvironment(base: ["PATH": "/usr/bin", "HOME": "/var/root"], target: target, helperFD: 7)
        XCTAssertEqual(env["HOME"], "/Users/user")
        XCTAssertEqual(env["USER"], "user")
        XCTAssertEqual(env["LOGNAME"], "user")
        XCTAssertEqual(env["IAIRPORT_SUDO"], "1")
        XCTAssertEqual(env["IAIRPORT_HELPER_FD"], "7")
        XCTAssertEqual(env["IAIRPORT_DROP_TO"], "501:20:user:/Users/user")
        XCTAssertEqual(env["PATH"], "/usr/bin")
    }

    func testBSSIDSourceInOutputs() {
        XCTAssertTrue(CSVLogger.sampleHeader.contains("bssid_source"))
        XCTAssertTrue(CSVLogger.roamHeader.contains("bssid_source"))
        let sample = LinkSample(interfaceName: "en0", status: .associated, ssid: "ExampleNet", bssid: "00:0b:86:11:22:01", bssidSource: .cache)
        let json = OutputFormatter.sampleJSON(sample: sample, time: TimeFormatter())
        XCTAssertEqual(json["bssid_source"] as? String, "cache")
    }

    func testCacheModeDriverRoamCreatesUnknownBSSID() {
        let t0 = Date(timeIntervalSince1970: 0)
        let old = AssociationInfo(bssid: "00:0b:86:11:22:01", ssid: "ExampleNet", channel: 44, rssi: -55, since: t0, bssidSource: .cache)
        let transition = CacheModeRoam.transitionFromDriverSignal(old: old, cachedBSSIDAfterSettle: "00:0b:86:11:22:01", at: t0.addingTimeInterval(3))
        XCTAssertEqual(transition?.kind, .roam)
        XCTAssertEqual(transition?.old?.bssid, "00:0b:86:11:22:01")
        XCTAssertEqual(transition?.new?.bssid, "?")
        XCTAssertEqual(transition?.new?.bssidSource, .cache)
        XCTAssertNil(CacheModeRoam.transitionFromDriverSignal(old: old, cachedBSSIDAfterSettle: "00:0b:86:11:22:02", at: t0.addingTimeInterval(3)))
    }
}
