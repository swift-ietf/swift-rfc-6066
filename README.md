# swift-rfc-6066

![Development Status](https://img.shields.io/badge/status-active--development-blue.svg)

TLS extension definitions, including Server Name Indication, of RFC 6066.

## Standard Reference

- **RFC**: 6066
- **Title**: Transport Layer Security (TLS) Extensions: Extension Definitions

## Installation

Add the package to your `Package.swift` dependencies:

```swift
dependencies: [
    .package(url: "https://github.com/swift-ietf/swift-rfc-6066.git", branch: "main")
]
```

Add the product to a target that needs it:

```swift
.target(
    name: "YourTarget",
    dependencies: [
        .product(name: "RFC 6066", package: "swift-rfc-6066")
    ]
)
```

## License

Apache 2.0. See [LICENSE.md](LICENSE.md).
