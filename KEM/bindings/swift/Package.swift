// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "KazKem",
    platforms: [
        .macOS(.v12),
        .iOS(.v15),
        .tvOS(.v15),
        .watchOS(.v8)
    ],
    products: [
        .library(
            name: "KazKem",
            targets: ["KazKem"]
        ),
    ],
    targets: [
        // C wrapper for the native library
        .target(
            name: "CKazKem",
            dependencies: [],
            path: "Sources/CKazKem",
            publicHeadersPath: "include",
            cSettings: [
                .headerSearchPath("include"),
            ],
            linkerSettings: [
                .linkedLibrary("kazkem"),
                .linkedLibrary("crypto"),
                .unsafeFlags([
                    "-L\(Context.packageDirectory)/lib",
                    "-L/usr/local/lib",
                    "-L/opt/homebrew/lib",
                    "-L/opt/homebrew/opt/openssl@3/lib"
                ]),
            ]
        ),
        // Swift wrapper
        .target(
            name: "KazKem",
            dependencies: ["CKazKem"],
            path: "Sources/KazKem"
        ),
        // Tests
        .testTarget(
            name: "KazKemTests",
            dependencies: ["KazKem"],
            path: "Tests/KazKemTests"
        ),
    ]
)
