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

// RFC_6066.ServerNameList.Acknowledgement.swift
// swift-rfc-6066
//
// RFC 6066 Section 3: Server Name Indication (server response)

public import Binary_Serializable_Primitives
public import RFC_8446

extension RFC_6066.ServerNameList {
    /// The server's `server_name` response body — **empty**.
    ///
    /// RFC 6066 Section 3:
    ///
    /// > the server SHALL include an extension of type "server_name" in the
    /// > (extended) server hello. The "extension_data" field of this extension
    /// > SHALL be empty.
    ///
    /// In TLS 1.3 the acknowledgement travels in EncryptedExtensions rather than
    /// ServerHello (RFC 8446 Section 4.2), but the body is the same: zero bytes.
    /// This type exists so that empty body is *representable and round-trippable*
    /// — ``RFC_6066/ServerNameList`` cannot model it, since `server_name_list` is
    /// bounded `<1..2^16-1>` and an empty list is not the same wire form as an
    /// empty extension body.
    ///
    /// ## Example
    ///
    /// ```swift
    /// let encryptedExtensions = [RFC_6066.ServerNameList.Acknowledgement().extensionData]
    /// ```
    public struct Acknowledgement: Sendable, Hashable {
        /// Creates the empty acknowledgement body.
        public init() {}

        /// The extension type for this payload (`server_name`).
        public static let extensionType: RFC_8446.Extension.ExtensionType = .serverName

        /// Wraps this payload in a generic ``RFC_8446/Extension/Data`` envelope
        /// with an empty `extension_data`.
        public var extensionData: RFC_8446.Extension.Data {
            RFC_8446.Extension.Data(type: Self.extensionType, data: [])
        }
    }
}

// MARK: - Binary.Serializable

extension RFC_6066.ServerNameList.Acknowledgement: Binary.Serializable {
    /// Appends nothing: the acknowledgement body is empty.
    public static func serialize<Buffer: RangeReplaceableCollection>(
        _ value: Self,
        into buffer: inout Buffer
    ) where Buffer.Element == Byte {
        // The "extension_data" field of this extension SHALL be empty.
    }

    /// Parses the server's `server_name` response body, which must be empty.
    public init<Bytes: Collection>(binary bytes: Bytes) throws(Error)
    where Bytes.Element == Byte {
        guard bytes.isEmpty else {
            throw Error.trailingData(bytes.count)
        }
        self.init()
    }
}
