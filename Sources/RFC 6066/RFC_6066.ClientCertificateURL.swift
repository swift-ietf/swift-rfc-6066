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

// RFC_6066.ClientCertificateURL.swift
// swift-rfc-6066
//
// RFC 6066 Section 5: Client Certificate URLs

public import Binary_Serializable_Primitives
public import RFC_8446

extension RFC_6066 {
    /// `client_certificate_url` extension payload (`extension_data` body) —
    /// **empty**.
    ///
    /// RFC 6066 Section 5 defines no structure for the extension itself: "The
    /// 'extension_data' field of this extension SHALL be empty." Presence alone
    /// signals that the client may send a ``RFC_6066/CertificateURL`` handshake
    /// message in place of its Certificate message.
    ///
    /// ## TLS 1.3
    ///
    /// TLS 1.3 does not carry `client_certificate_url` (RFC 8446 Section 4.2).
    /// The type is defined here for TLS 1.2 peers and specification completeness.
    public struct ClientCertificateURL: Sendable, Hashable {
        /// Creates the empty `client_certificate_url` body.
        public init() {}

        /// The extension type for this payload (`client_certificate_url`).
        public static let extensionType: RFC_8446.Extension.ExtensionType = .clientCertificateURL

        /// Wraps this payload in a generic ``RFC_8446/Extension/Data`` envelope
        /// with an empty `extension_data`.
        public var extensionData: RFC_8446.Extension.Data {
            RFC_8446.Extension.Data(type: Self.extensionType, data: [])
        }
    }
}

// MARK: - Binary.Serializable

extension RFC_6066.ClientCertificateURL: Binary.Serializable {
    /// Appends nothing: the `client_certificate_url` body is empty.
    public static func serialize<Buffer: RangeReplaceableCollection>(
        _ value: Self,
        into buffer: inout Buffer
    ) where Buffer.Element == Byte {
        // The "extension_data" field of this extension SHALL be empty.
    }

    /// Parses a `client_certificate_url` `extension_data` body, which must be empty.
    public init<Bytes: Collection>(binary bytes: Bytes) throws(Error)
    where Bytes.Element == Byte {
        guard bytes.isEmpty else {
            throw Error.trailingData(bytes.count)
        }
        self.init()
    }
}
