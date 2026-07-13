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

// RFC_6066.MaxFragmentLength.Error.swift
// swift-rfc-6066
//
// RFC 6066 Section 4: Maximum Fragment Length Negotiation

extension RFC_6066.MaxFragmentLength {
    /// Errors raised when parsing a `max_fragment_length` payload.
    public enum Error: Swift.Error, Sendable, Equatable {
        /// The code point is not one of `2^9(1)`, `2^10(2)`, `2^11(3)`, `2^12(4)`.
        ///
        /// RFC 6066 Section 4 requires the receiver to abort the handshake with
        /// an `illegal_parameter` alert.
        case unknownLength(_ rawValue: UInt8)

        /// The input ended before the single length byte was read.
        case truncated

        /// Bytes remained after the length byte.
        case trailingData(_ remaining: Int)
    }
}

extension RFC_6066.MaxFragmentLength.Error: CustomStringConvertible {
    public var description: String {
        switch self {
        case .unknownLength(let rawValue):
            return "TLS max_fragment_length has illegal value \(rawValue) (allowed: 1...4)"
        case .truncated:
            return "TLS max_fragment_length truncated"
        case .trailingData(let remaining):
            return "TLS max_fragment_length has \(remaining) trailing bytes"
        }
    }
}
