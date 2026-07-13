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

// RFC_6066.CertificateURL.URLAndHash.Error.swift
// swift-rfc-6066
//
// RFC 6066 Section 5: Client Certificate URLs

extension RFC_6066.CertificateURL.URLAndHash {
    /// Errors raised when creating a `URLAndHash`.
    public enum Error: Swift.Error, Sendable, Equatable {
        /// `url` is bounded `<1..2^16-1>`; it cannot be empty.
        case emptyURL

        /// `url` is bounded `<1..2^16-1>`; it cannot exceed 65535 bytes.
        case urlTooLong(_ length: Int)
    }
}

extension RFC_6066.CertificateURL.URLAndHash.Error: CustomStringConvertible {
    public var description: String {
        switch self {
        case .emptyURL:
            return "TLS CertificateURL url cannot be empty"
        case .urlTooLong(let length):
            return "TLS CertificateURL url too long: \(length) bytes (max 65535)"
        }
    }
}
