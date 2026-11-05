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

// RFC_6066.ServerNameList.swift
// swift-rfc-6066
//
// RFC 6066 Section 3: Server Name Indication

public import Binary
public import RFC_8446

extension RFC_6066 {
    /// `server_name` extension payload (`extension_data` body) — Server Name
    /// Indication (SNI).
    ///
    /// ## Wire Format
    ///
    /// ```
    /// struct {
    ///     ServerName server_name_list<1..2^16-1>
    /// } ServerNameList;
    /// ```
    ///
    /// ## Direction
    ///
    /// The **client** sends this body in its ClientHello. The **server** does not
    /// echo it: per RFC 6066 Section 3, "the server SHALL include an extension of
    /// type 'server_name' in the (extended) server hello. The 'extension_data'
    /// field of this extension SHALL be empty." That empty body is
    /// ``Acknowledgement`` (in TLS 1.3 it travels in EncryptedExtensions —
    /// RFC 8446 Section 4.2).
    ///
    /// ## Serialization Convention
    ///
    /// This type serializes the **body** (`extension_data` contents) only, not
    /// the `extension_type` + length envelope — the RFC 8446 payload convention.
    /// Use ``extensionData`` to lift the body into an
    /// ``RFC_8446/Extension/Data``.
    ///
    /// ## Example
    ///
    /// ```swift
    /// let sni = RFC_6066.ServerNameList(hostName: try RFC_6066.HostName("example.com"))
    /// let ext = try sni.extensionData      // type == .serverName
    /// ```
    public struct ServerNameList: Sendable, Hashable {
        /// The offered server names.
        ///
        /// Non-empty, and — per RFC 6066 Section 3, "The ServerNameList MUST NOT
        /// contain more than one name of the same name_type" — carrying at most
        /// one entry per ``ServerName/NameType``.
        public let serverNameList: [ServerName]

        /// Creates a server name list WITHOUT validation.
        init(__unchecked: Void, serverNameList: [ServerName]) {
            self.serverNameList = serverNameList
        }

        /// Creates a server name list with validation.
        ///
        /// - Parameter serverNameList: The entries (at least one; at most one per
        ///   `name_type`).
        /// - Throws: ``Error/empty`` or ``Error/duplicateNameType(_:)``.
        public init(serverNameList: [ServerName]) throws(Error) {
            guard !serverNameList.isEmpty else {
                throw Error.empty
            }
            var seen: Set<ServerName.NameType> = []
            for serverName in serverNameList {
                guard seen.insert(serverName.nameType).inserted else {
                    throw Error.duplicateNameType(serverName.nameType)
                }
            }
            self.init(__unchecked: (), serverNameList: serverNameList)
        }

        /// Creates a single-entry server name list — the SNI case.
        ///
        /// Cannot fail: one entry is non-empty and cannot collide with itself.
        public init(hostName: HostName) {
            self.init(__unchecked: (), serverNameList: [ServerName(hostName: hostName)])
        }

        /// The offered `host_name`, if the list carries one.
        public var hostName: HostName? {
            serverNameList.first { $0.nameType == .hostName }?.hostName
        }

        /// The extension type for this payload (`server_name`).
        public static let extensionType: RFC_8446.Extension.ExtensionType = .serverName

        /// Wraps this payload in a generic ``RFC_8446/Extension/Data`` envelope.
        ///
        /// - Throws: ``RFC_8446/Extension/Data/Error`` if the body exceeds the
        ///   envelope's 65535-byte limit.
        public var extensionData: RFC_8446.Extension.Data {
            get throws(RFC_8446.Extension.Data.Error) {
                try RFC_8446.Extension.Data(type: Self.extensionType, data: self.bytes)
            }
        }
    }
}

// MARK: - Binary.Serializable

extension RFC_6066.ServerNameList: Binary.Serializable {
    public static func serialize<Buffer: RangeReplaceableCollection>(
        _ value: Self,
        into buffer: inout Buffer
    ) where Buffer.Element == Byte {
        var block: [Byte] = []
        for serverName in value.serverNameList {
            RFC_6066.ServerName.serialize(serverName, into: &block)
        }
        RFC_6066.Wire.appendVector16(block, into: &buffer)
    }

    /// Parses a `server_name` `extension_data` body (the client form).
    ///
    /// The server's response body is empty and parses as
    /// ``RFC_6066/ServerNameList/Acknowledgement`` instead.
    public init<Bytes: Swift::Collection>(binary bytes: Bytes) throws(Error)
    where Bytes.Element == Byte {
        var reader = RFC_6066.Wire.Reader(Array(bytes))
        let block: [Byte]
        do {
            block = try reader.vector16()
            try reader.expectEnd()
        } catch {
            switch error {
            case .trailingData(let remaining): throw .trailingData(remaining)
            case .truncated, .lengthOverflow: throw .truncated
            }
        }

        var sub = RFC_6066.Wire.Reader(block)
        var serverNames: [RFC_6066.ServerName] = []
        while !sub.isAtEnd {
            let fields: (nameType: UInt8, name: [Byte])
            do {
                fields = try sub.serverNameFields()
            } catch {
                switch error {
                case .trailingData(let remaining): throw .trailingData(remaining)
                case .truncated, .lengthOverflow: throw .truncated
                }
            }
            do {
                serverNames.append(try RFC_6066.ServerName(nameType: fields.nameType, name: fields.name))
            } catch {
                switch error {
                case .unknownNameType(let rawValue): throw .unknownNameType(rawValue)
                case .invalidHostName(let hostNameError): throw .invalidHostName(hostNameError)
                case .truncated: throw .truncated
                case .trailingData(let remaining): throw .trailingData(remaining)
                }
            }
        }
        try self.init(serverNameList: serverNames)
    }
}
