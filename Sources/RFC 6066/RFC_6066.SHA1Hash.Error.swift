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

// RFC_6066.SHA1Hash.Error.swift
// swift-rfc-6066
//
// RFC 6066 Sections 5 and 6: SHA1Hash

extension RFC_6066.SHA1Hash {
    /// Errors raised when creating a `SHA1Hash`.
    public enum Error: Swift.Error, Sendable, Equatable {
        /// `SHA1Hash[20]` is a fixed-width 20-byte vector.
        case invalidLength(_ length: Int)
    }
}

extension RFC_6066.SHA1Hash.Error: CustomStringConvertible {
    public var description: String {
        switch self {
        case .invalidLength(let length):
            return "TLS SHA1Hash must be exactly 20 bytes, found \(length)"
        }
    }
}
