// swift-tools-version:5.9
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "KazSign",
    platforms: [
        .iOS(.v13),
        .macOS(.v11)
    ],
    products: [
        .library(
            name: "KazSign",
            targets: ["KazSign"]
        ),
    ],
    targets: [
        // Swift wrapper
        .target(
            name: "KazSign",
            dependencies: ["KazSignNative"],
            path: "Sources/KazSign"
        ),
        // Native library (XCFramework)
        .binaryTarget(
            name: "KazSignNative",
            path: "KazSignNative.xcframework"
        ),
        // Tests
        .testTarget(
            name: "KazSignTests",
            dependencies: ["KazSign"],
            path: "Tests/KazSignTests"
        ),
    ]
)
