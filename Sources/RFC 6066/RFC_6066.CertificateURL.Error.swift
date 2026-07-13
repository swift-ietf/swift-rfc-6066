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

// RFC_6066.CertificateURL.Error.swift
// swift-rfc-6066
//
// RFC 6066 Section 5: Client Certificate URLs

extension RFC_6066.CertificateURL {
    /// Errors raised when creating or parsing a `CertificateURL`.
    public enum Error: Swift.Error, Sendable, Equatable {
        /// `url_and_hash_list` is bounded `<1..2^16-1>`; it cannot be empty.
        case emptyList

        /// RFC 6066 Section 5: "The 'padding' byte MUST be 0x01."
        case invalidPadding(_ rawValue: UInt8)

        /// An entry failed ``RFC_6066/CertificateURL/URLAndHash`` validation.
        case invalidURLAndHash(_ error: RFC_6066.CertificateURL.URLAndHash.Error)

        /// The input ended before the message was complete.
        case truncated

        /// Bytes remained after the message.
        case trailingData(_ remaining: Int)
    }
}

extension RFC_6066.CertificateURL.Error: CustomStringConvertible {
    public var description: String {
        switch self {
        case .emptyList:
            return "TLS CertificateURL requires at least one url_and_hash entry"
        case .invalidPadding(let rawValue):
            return "TLS CertificateURL padding byte must be 0x01, found \(rawValue)"
        case .invalidURLAndHash(let error):
            return "TLS CertificateURL has an invalid entry: \(error)"
        case .truncated:
            return "TLS CertificateURL truncated"
        case .trailingData(let remaining):
            return "TLS CertificateURL has \(remaining) trailing bytes"
        }
    }
}
