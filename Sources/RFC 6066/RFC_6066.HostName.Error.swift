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

// RFC_6066.HostName.Error.swift
// swift-rfc-6066
//
// RFC 6066 Section 3: Server Name Indication

extension RFC_6066.HostName {
    /// Errors raised when creating or parsing a hostname.
    public enum Error: Swift.Error, Sendable, Equatable {
        /// `HostName` is bounded `<1..2^16-1>`; it cannot be empty.
        case empty

        /// `HostName` is bounded `<1..2^16-1>`; it cannot exceed 65535 bytes.
        case tooLong(_ length: Int)

        /// RFC 6066 Section 3: the hostname is "represented as a byte string
        /// using ASCII encoding".
        case nonASCII

        /// RFC 6066 Section 3: the hostname is represented "without a trailing dot".
        case trailingDot

        /// The input ended before the hostname vector was complete.
        case truncated

        /// Bytes remained after the hostname vector.
        case trailingData(_ remaining: Int)
    }
}

extension RFC_6066.HostName.Error: CustomStringConvertible {
    public var description: String {
        switch self {
        case .empty:
            return "TLS server_name host_name cannot be empty"
        case .tooLong(let length):
            return "TLS server_name host_name too long: \(length) bytes (max 65535)"
        case .nonASCII:
            return "TLS server_name host_name must be ASCII (A-label encode internationalized names)"
        case .trailingDot:
            return "TLS server_name host_name must not have a trailing dot"
        case .truncated:
            return "TLS server_name host_name truncated"
        case .trailingData(let remaining):
            return "TLS server_name host_name has \(remaining) trailing bytes"
        }
    }
}
