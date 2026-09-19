import Foundation
import MerlinClientCore

/// Root-owned launchd Mach service exporting one read-only method. Authentication
/// is enforced by NSXPC on actual peer messages before dispatch to the object.
final class LocalStatusService: NSObject, NSXPCListenerDelegate, MerlinLocalStatusProtocol {
    private let store: LocalStatusStore
    private let requirement: String
    private let listener: NSXPCListener
    private let queue = DispatchQueue(label: "com.evalops.merlin.local-posture", qos: .utility)
    private var timer: DispatchSourceTimer?

    init(store: LocalStatusStore) throws {
        guard geteuid() == 0 else { throw LocalStatusError.unavailable }
        self.store = store
        requirement = try LocalStatusPeerPolicy.requirement(
            teamID: LocalStatusPeerPolicy.ownTeamID(), identifier: LocalStatusPeerPolicy.appIdentifier)
        listener = NSXPCListener(machServiceName: LocalStatusPeerPolicy.serviceName)
        super.init()
        listener.delegate = self
    }

    func start() {
        listener.resume()
        let timer = DispatchSource.makeTimerSource(queue: queue)
        timer.schedule(deadline: .now(), repeating: LocalDeviceStatus.maxAge)
        let store = store
        timer.setEventHandler { _ = store.currentPostureReport() }
        timer.resume()
        self.timer = timer
    }

    func stop() {
        timer?.cancel()
        timer = nil
        listener.invalidate()
    }

    func listener(_ listener: NSXPCListener, shouldAcceptNewConnection connection: NSXPCConnection) -> Bool {
        connection.setCodeSigningRequirement(requirement)
        connection.exportedInterface = NSXPCInterface(with: MerlinLocalStatusProtocol.self)
        connection.exportedObject = self
        connection.resume()
        return true
    }

    func readStatus(withReply reply: @escaping (Data?) -> Void) {
        // Reads never start expensive commands, inspect files, or mutate enrollment.
        let data = try? JSONEncoder().encode(store.snapshot())
        reply(data.flatMap { $0.count <= LocalDeviceStatus.maxEncodedBytes ? $0 : nil })
    }
}
