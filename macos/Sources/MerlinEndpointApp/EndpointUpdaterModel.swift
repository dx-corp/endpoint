import Combine
import Foundation
import Sparkle

@MainActor
final class EndpointUpdaterModel: ObservableObject {
    @Published private(set) var isAvailable = false
    @Published private(set) var status = "Automatic updates are not configured in this build."
    private var controller: SPUStandardUpdaterController?

    init(bundle: Bundle = .main) {
        guard let feed = bundle.object(forInfoDictionaryKey: "SUFeedURL") as? String,
              let url = URL(string: feed), url.scheme == "https", url.host != nil,
              url.user == nil, url.password == nil,
              let key = bundle.object(forInfoDictionaryKey: "SUPublicEDKey") as? String,
              Data(base64Encoded: key)?.count == 32 else { return }
        controller = SPUStandardUpdaterController(startingUpdater: true, updaterDelegate: nil, userDriverDelegate: nil)
        isAvailable = true
        status = "Updates are checked automatically. Installing an update may require administrator authorization."
    }
    func checkForUpdates() { controller?.checkForUpdates(nil) }
}
