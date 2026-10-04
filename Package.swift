// swift-tools-version: 6.4
import PackageDescription

let package = Package(
    name: "SSHTree",
    platforms: [.macOS("27.0")],
    products: [
        .library(name: "SSHTreeCore", targets: ["SSHTreeCore"]),
        .executable(name: "SSHTree", targets: ["SSHTree"]),
        .executable(name: "SSHTreeAskPass", targets: ["SSHTreeAskPass"])
    ],
    dependencies: [.package(url: "https://github.com/migueldeicaza/SwiftTerm.git", exact: "1.20.0")],
    targets: [
        .target(name: "SSHTreeCore"),
        .executableTarget(name: "SSHTree", dependencies: ["SSHTreeCore", .product(name: "SwiftTerm", package: "SwiftTerm")]),
        .executableTarget(name: "SSHTreeAskPass", dependencies: ["SSHTreeCore"]),
        .testTarget(name: "SSHTreeCoreTests", dependencies: ["SSHTreeCore"])
    ]
)
