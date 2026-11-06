// ===----------------------------------------------------------------------===//
//
// Copyright (c) 2025 Coen ten Thije Boonkkamp
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of project contributors
//
// SPDX-License-Identifier: Apache-2.0
//
// ===----------------------------------------------------------------------===//

// RFC_6066.TruncatedHMAC.swift
// swift-rfc-6066
//
// RFC 6066 Section 7: Truncated HMAC

public import Binary
public import RFC_8446

extension RFC_6066 {
    /// `truncated_hmac` extension payload (`extension_data` body) — **empty**.
    ///
    /// RFC 6066 Section 7 defines no structure: "The 'extension_data' field of
    /// this extension SHALL be empty." Both client and server send the same empty
    /// body; presence alone negotiates a 10-byte truncated HMAC
    /// (`SecurityParameters.mac_length` = 10).
    ///
    /// ## TLS 1.3
    ///
    /// TLS 1.3 does not carry `truncated_hmac` (RFC 8446 Section 4.2) — its AEAD
    /// cipher suites have no separate HMAC to truncate. The type is defined here
    /// for TLS 1.2 peers and specification completeness.
    public struct TruncatedHMAC: Sendable, Hashable {
        /// Creates the empty `truncated_hmac` body.
        public init() {}

        /// The extension type for this payload (`truncated_hmac`).
        public static let extensionType: RFC_8446.Extension.ExtensionType = .truncatedHMAC

        /// Wraps this payload in a generic ``RFC_8446/Extension/Data`` envelope
        /// with an empty `extension_data`.
        public var extensionData: RFC_8446.Extension.Data {
            // Cannot throw: this payload's fixed-size body is under the envelope's 65535-byte limit.
            // swift-format-ignore: NeverUseForceTry
            // swiftlint:disable:next force_try
            try! RFC_8446.Extension.Data(type: Self.extensionType, data: [])
        }
    }
}

// MARK: - Binary.Serializable

extension RFC_6066.TruncatedHMAC: Binary.Serializable {
    /// Appends nothing: the `truncated_hmac` body is empty.
    public static func serialize<Buffer: RangeReplaceableCollection>(
        _ value: Self,
        into buffer: inout Buffer
    ) where Buffer.Element == Byte {
        // The "extension_data" field of this extension SHALL be empty.
    }

    /// Parses a `truncated_hmac` `extension_data` body, which must be empty.
    public init<Bytes: Swift::Collection>(binary bytes: Bytes) throws(Error)
    where Bytes.Element == Byte {
        guard bytes.isEmpty else {
            throw Error.trailingData(bytes.count)
        }
        self.init()
    }
}
