// swift-tools-version: 6.0

import PackageDescription

let package = Package(
    name: "Harbor",
    platforms: [
        .macOS(.v15)
    ],
    products: [
        .library(name: "HarborKit", targets: ["HarborKit"]),
        .executable(name: "Harbor", targets: ["Harbor"]),
        .executable(name: "HarborSelfTest", targets: ["HarborSelfTest"])
    ],
    dependencies: [
        .package(path: "ThirdParty/SwiftTerm")
    ],
    targets: [
        .target(
            name: "HarborKit",
            path: "Sources/HarborKit"
        ),
        .executableTarget(
            name: "Harbor",
            dependencies: [
                "HarborKit",
                .product(name: "SwiftTerm", package: "SwiftTerm")
            ],
            path: "Sources/Harbor"
        ),
        .executableTarget(
            name: "HarborSelfTest",
            dependencies: ["HarborKit"],
            path: "Sources/HarborSelfTest"
        )
    ]
)
