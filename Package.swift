// swift-tools-version: 6.4

import PackageDescription

extension String {
    static let rfc6066: Self = "RFC 6066"
}

extension Target.Dependency {
    static var rfc6066: Self { .target(name: .rfc6066) }
    static var rfc8446: Self { .product(name: "RFC 8446", package: "swift-rfc-8446") }
    static var standards: Self { .product(name: "Standard Library Extensions", package: "swift-standard-library-extensions") }
    static var incits41986: Self { .product(name: "ASCII", package: "swift-ascii") }
    static var binary: Self { .product(name: "Binary", package: "swift-binary") }
    static var bytePrimitivesSLI: Self { .product(name: "Byte", package: "swift-byte") }
}

let package = Package(
    name: "swift-rfc-6066",
    platforms: [
        .macOS(.v27),
        .iOS(.v27),
        .tvOS(.v27),
        .watchOS(.v27),
        .visionOS(.v27)
    ],
    products: [
        .library(name: "RFC 6066", targets: ["RFC 6066"]),
        .library(name: "RFC 6066 Standard Library Integration", targets: ["RFC 6066 Standard Library Integration"]),
    ],
    dependencies: [
        .package(url: "https://github.com/swift-ietf/swift-rfc-8446.git", branch: "main"),
        .package(url: "https://github.com/swift-atoms/swift-standard-library-extensions.git", branch: "main"),
        .package(url: "https://github.com/swift-atoms/swift-ascii.git", branch: "main"),
        .package(url: "https://github.com/swift-atoms/swift-binary.git", branch: "main", traits: ["Serializer"]),
        .package(url: "https://github.com/swift-atoms/swift-byte.git", branch: "main")
    ],
    targets: [
        .target(
            name: "RFC 6066",
            dependencies: [
                .rfc8446,
                .standards,
                .incits41986,
                .binary
            ]
        ),
        .target(
            name: "RFC 6066 Standard Library Integration",
            dependencies: [
                .rfc6066,
                .bytePrimitivesSLI,
            ]
        ),
        .testTarget(
            name: "RFC 6066 Tests",
            dependencies: [
                .binary,
                "RFC 6066",
            ]
        ),
        .testTarget(
            name: "RFC 6066 Standard Library Integration Tests",
            dependencies: [
                "RFC 6066",
                "RFC 6066 Standard Library Integration",
            ]
        ),
    ],
    swiftLanguageModes: [.v6]
)

extension String {
    var tests: Self { self + " Tests" }
}

for target in package.targets where ![.system, .binary, .plugin, .macro].contains(target.type) {
    let ecosystem: [SwiftSetting] = [
        .strictMemorySafety(),
        .enableUpcomingFeature("ExistentialAny"),
        .enableUpcomingFeature("InternalImportsByDefault"),
        .enableUpcomingFeature("MemberImportVisibility"),
        .enableUpcomingFeature("NonisolatedNonsendingByDefault"),
        .enableExperimentalFeature("Lifetimes"),
        .enableExperimentalFeature("SuppressedAssociatedTypes"),
    ]

    let package: [SwiftSetting] = []

    target.swiftSettings = (target.swiftSettings ?? []) + ecosystem + package
}
