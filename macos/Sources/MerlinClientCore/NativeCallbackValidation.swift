import Foundation

public enum NativeCallbackValidation {
    public static func accepts(_ url: URL) -> Bool {
        guard let parts = URLComponents(url: url, resolvingAgainstBaseURL: false),
              parts.scheme == "http", parts.host == "127.0.0.1", parts.port == 49177,
              parts.path == "/", parts.user == nil, parts.password == nil, parts.fragment == nil else { return false }
        let items = parts.queryItems ?? []
        guard Set(items.map(\.name)).count == items.count else { return false }
        let values = Dictionary(uniqueKeysWithValues: items.map { ($0.name, $0.value ?? "") })
        guard let state = values["state"], !state.isEmpty else { return false }
        return (values["code"].map { !$0.isEmpty } ?? false) != (values["error"].map { !$0.isEmpty } ?? false)
    }
}
