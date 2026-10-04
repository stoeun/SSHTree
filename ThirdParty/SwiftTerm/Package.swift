// swift-tools-version: 6.0

import PackageDescription

// Vendored from SwiftTerm 1.20.0. The Metal shader is not a package resource:
// Command Line Tools have no `metal` compiler, and the Metal renderer stays
// off unless an app calls setUseMetal(true). CoreGraphics rendering is the default.

let package = Package(
    name: "SwiftTerm",
    platforms: [
        .macOS(.v14)
    ],
    products: [
        .library(name: "SwiftTerm", targets: ["SwiftTerm"])
    ],
    targets: [
        .executableTarget(
            name: "SwiftTermBuildInfoGenerator",
            path: "Sources/SwiftTermBuildInfoGenerator"
        ),
        .plugin(
            name: "SwiftTermBuildInfoPlugin",
            capability: .buildTool(),
            dependencies: ["SwiftTermBuildInfoGenerator"]
        ),
        .target(
            name: "SwiftTerm",
            path: "Sources/SwiftTerm",
            plugins: [
                .plugin(name: "SwiftTermBuildInfoPlugin")
            ]
        )
    ],
    swiftLanguageModes: [.v5]
)
