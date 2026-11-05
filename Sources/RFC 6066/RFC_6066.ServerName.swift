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

// RFC_6066.ServerName.swift
// swift-rfc-6066
//
// RFC 6066 Section 3: Server Name Indication

public import Binary

extension RFC_6066 {
    /// A single `ServerName` entry of the `server_name` extension.
    ///
    /// ## Wire Format
    ///
    /// ```
    /// struct {
    ///     NameType name_type;
    ///     select (name_type) {
    ///         case host_name: HostName;
    ///     } name;
    /// } ServerName;
    /// ```
    ///
    /// `host_name(0)` is the only registered ``NameType``, so the variant
    /// collapses to a single stored ``HostName``; ``nameType`` reports the wire
    /// discriminator. Parsing an entry whose `name_type` is not `host_name`
    /// fails with ``Error/unknownNameType(_:)`` — the RFC defines no generic
    /// length prefix for other variants, so the bytes after an unknown
    /// discriminator cannot be skipped.
    public struct ServerName: Sendable, Hashable {
        /// The server name (an ASCII DNS hostname).
        public let hostName: HostName

        /// Creates a `host_name` server name entry.
        public init(hostName: HostName) {
            self.hostName = hostName
        }

        /// The wire discriminator for this entry — always `host_name(0)`.
        public var nameType: NameType { .hostName }
    }
}

// MARK: - Binary.Serializable

extension RFC_6066.ServerName: Binary.Serializable {
    /// Serializes `name_type` (1 byte) followed by the `HostName` vector.
    public static func serialize<Buffer: RangeReplaceableCollection>(
        _ serverName: Self,
        into buffer: inout Buffer
    ) where Buffer.Element == Byte {
        buffer.append(Byte(serverName.nameType.rawValue))
        RFC_6066.HostName.serialize(serverName.hostName, into: &buffer)
    }

    /// Parses exactly one `ServerName` structure.
    public init<Bytes: Swift::Collection>(binary bytes: Bytes) throws(Error)
    where Bytes.Element == Byte {
        var reader = RFC_6066.Wire.Reader(Array(bytes))
        let fields: (nameType: UInt8, name: [Byte])
        do {
            fields = try reader.serverNameFields()
            try reader.expectEnd()
        } catch {
            switch error {
            case .trailingData(let remaining): throw .trailingData(remaining)
            case .truncated, .lengthOverflow: throw .truncated
            }
        }
        try self.init(nameType: fields.nameType, name: fields.name)
    }

    /// Builds an entry from its parsed wire fields, validating the discriminator.
    init(nameType: UInt8, name: [Byte]) throws(Error) {
        guard nameType == RFC_6066.ServerName.NameType.hostName.rawValue else {
            throw .unknownNameType(nameType)
        }
        let hostName: RFC_6066.HostName
        do {
            hostName = try RFC_6066.HostName(rawValue: name)
        } catch {
            throw .invalidHostName(error)
        }
        self.init(hostName: hostName)
    }
}

// MARK: - Wire Decoding

extension RFC_6066.Wire.Reader {
    /// Reads the raw fields of one `ServerName` from the cursor: the `name_type`
    /// discriminator and the `uint16`-length-prefixed `name` body.
    ///
    /// Discriminator validation is the caller's job — the reader deals only in
    /// presentation-language forms.
    mutating func serverNameFields() throws(RFC_6066.Wire.Error) -> (nameType: UInt8, name: [Byte]) {
        let nameType = try byte()
        let name = try vector16()
        return (nameType, name)
    }
}
