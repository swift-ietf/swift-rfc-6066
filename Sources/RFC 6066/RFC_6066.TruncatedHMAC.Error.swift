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

// RFC_6066.TruncatedHMAC.Error.swift
// swift-rfc-6066
//
// RFC 6066 Section 7: Truncated HMAC

extension RFC_6066.TruncatedHMAC {
    /// Errors raised when parsing a `truncated_hmac` payload.
    public enum Error: Swift.Error, Sendable, Equatable {
        /// The body was not empty, as RFC 6066 Section 7 requires it to be.
        case trailingData(_ remaining: Int)
    }
}

extension RFC_6066.TruncatedHMAC.Error: CustomStringConvertible {
    public var description: String {
        switch self {
        case .trailingData(let remaining):
            return "TLS truncated_hmac body must be empty, found \(remaining) bytes"
        }
    }
}
