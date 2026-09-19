// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "merlin-macos",
    platforms: [.macOS(.v13)],
    dependencies: [
        .package(url: "https://github.com/openid/AppAuth-iOS.git", exact: "3.0.0"),
        .package(url: "https://github.com/sparkle-project/Sparkle.git", exact: "2.9.6"),
        .package(url: "https://github.com/jpsim/Yams.git", from: "5.0.0"),
        .package(url: "https://github.com/apple/swift-argument-parser.git", from: "1.5.0"),
    ],
    targets: [
        .target(name: "MerlinClientCore"),
        .target(
            name: "MerlinAppAuthCompat",
            dependencies: [.product(name: "AppAuth", package: "AppAuth-iOS")],
            publicHeadersPath: "include"
        ),
        .executableTarget(
            name: "MerlinEndpointApp",
            dependencies: [
                "MerlinClientCore",
                "MerlinAppAuthCompat",
                .product(name: "AppAuth", package: "AppAuth-iOS"),
                .product(name: "Sparkle", package: "Sparkle"),
            ],
            swiftSettings: [.swiftLanguageMode(.v6)],
            linkerSettings: [.unsafeFlags(["-Xlinker", "-rpath", "-Xlinker", "@executable_path/../Frameworks"])]
        ),
        .testTarget(name: "MerlinClientCoreTests", dependencies: ["MerlinClientCore"]),
        .testTarget(name: "MerlinEndpointAppTests", dependencies: ["MerlinEndpointApp", "MerlinClientCore"]),
        .target(
            name: "MerlinEndpointSecurityCompat",
            path: "Sources/MerlinEndpointSecurityCompat",
            publicHeadersPath: "include"
        ),
        .executableTarget(
            name: "MerlinMacOS",
            dependencies: [
                "MerlinEndpointSecurityCompat",
                "MerlinClientCore",
                .product(name: "Yams", package: "Yams"),
                .product(name: "ArgumentParser", package: "swift-argument-parser"),
            ],
            swiftSettings: [.swiftLanguageMode(.v6)],
            linkerSettings: [
                // macOS 27 SDK has no EndpointSecurity.framework anymore;
                // the ES API lives in libEndpointSecurity.dylib.
                .linkedLibrary("EndpointSecurity"),
                .linkedLibrary("bsm"), // audit_token_to_pid/ruid
            ]
        ),
        .testTarget(
            name: "MerlinMacOSTests",
            dependencies: ["MerlinMacOS"]
        ),
    ]
)
