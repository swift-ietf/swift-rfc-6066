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

// RFC_6066.TrustedAuthorities.Error.swift
// swift-rfc-6066
//
// RFC 6066 Section 6: Trusted CA Indication

extension RFC_6066.TrustedAuthorities {
    /// Errors raised when parsing a `trusted_ca_keys` payload.
    public enum Error: Swift.Error, Sendable, Equatable {
        /// An entry carried an `identifier_type` outside `pre_agreed(0)`,
        /// `key_sha1_hash(1)`, `x509_name(2)`, `cert_sha1_hash(3)`. Each variant
        /// has its own length, so an unknown one cannot be skipped.
        case unknownIdentifierType(_ rawValue: UInt8)

        /// The input ended before the list was complete.
        case truncated

        /// Bytes remained after the list.
        case trailingData(_ remaining: Int)
    }
}

extension RFC_6066.TrustedAuthorities.Error: CustomStringConvertible {
    public var description: String {
        switch self {
        case .unknownIdentifierType(let rawValue):
            return "TLS trusted_ca_keys has unknown identifier_type \(rawValue)"
        case .truncated:
            return "TLS trusted_ca_keys truncated"
        case .trailingData(let remaining):
            return "TLS trusted_ca_keys has \(remaining) trailing bytes"
        }
    }
}
