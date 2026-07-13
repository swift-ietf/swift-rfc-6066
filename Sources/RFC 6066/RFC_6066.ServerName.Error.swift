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

// RFC_6066.ServerName.Error.swift
// swift-rfc-6066
//
// RFC 6066 Section 3: Server Name Indication

extension RFC_6066.ServerName {
    /// Errors raised when parsing a `ServerName` entry.
    public enum Error: Swift.Error, Sendable, Equatable {
        /// The `name_type` discriminator is not `host_name(0)`, so the `name`
        /// variant has no known length and cannot be read.
        case unknownNameType(_ rawValue: UInt8)

        /// The `host_name` body failed ``RFC_6066/HostName`` validation.
        case invalidHostName(_ error: RFC_6066.HostName.Error)

        /// The input ended before the entry was complete.
        case truncated

        /// Bytes remained after the entry.
        case trailingData(_ remaining: Int)
    }
}

extension RFC_6066.ServerName.Error: CustomStringConvertible {
    public var description: String {
        switch self {
        case .unknownNameType(let rawValue):
            return "TLS server_name has unknown name_type \(rawValue) (only host_name(0) is defined)"
        case .invalidHostName(let error):
            return "TLS server_name has invalid host_name: \(error)"
        case .truncated:
            return "TLS server_name entry truncated"
        case .trailingData(let remaining):
            return "TLS server_name entry has \(remaining) trailing bytes"
        }
    }
}
