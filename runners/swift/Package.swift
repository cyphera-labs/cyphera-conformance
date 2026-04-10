// swift-tools-version: 5.9

import PackageDescription

let package = Package(
    name: "conformance-runner",
    platforms: [.macOS(.v10_15)],
    dependencies: [
        .package(url: "https://github.com/cyphera-labs/cyphera-swift.git", from: "0.0.1-alpha.2"),
    ],
    targets: [
        .executableTarget(
            name: "run",
            dependencies: [
                .product(name: "Cyphera", package: "cyphera-swift"),
            ],
            path: "Sources"),
    ]
)
