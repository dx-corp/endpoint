import CryptoKit
import Foundation

func fail(_ message: String) -> Never {
    FileHandle.standardError.write(Data((message + "\n").utf8))
    exit(65)
}

guard CommandLine.arguments.count == 3 else {
    fail("Expected a private seed file and the configured public key.")
}
do {
    let encoded = try String(contentsOfFile: CommandLine.arguments[1], encoding: .utf8)
        .trimmingCharacters(in: .whitespacesAndNewlines)
    guard let seed = Data(base64Encoded: encoded), seed.count == 32 else {
        fail("Update signing requires a base64-encoded 32-byte Ed25519 seed.")
    }
    let key = try Curve25519.Signing.PrivateKey(rawRepresentation: seed)
    guard key.publicKey.rawRepresentation.base64EncodedString() == CommandLine.arguments[2] else {
        fail("Update signing key does not match MERLIN_UPDATE_PUBLIC_KEY.")
    }
} catch {
    fail("Cannot read or validate the update signing seed.")
}
