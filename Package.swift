// swift-tools-version: 5.9
import PackageDescription
let package = Package(name: "ZapretMac", platforms: [.macOS(.v13)], products: [
    .executable(name: "ZapretMac", targets: ["ZapretMac"])
], targets: [
    .target(name: "ZapretCore"),
    .executableTarget(name: "ZapretMac", dependencies: ["ZapretCore"]),
    .executableTarget(name: "ZapretCoreChecks", dependencies: ["ZapretCore"], path: "Tests/ZapretCoreTests")
])
