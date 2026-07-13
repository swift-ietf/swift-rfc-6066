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

// RFC_6066.ClientCertificateURL.Error.swift
// swift-rfc-6066
//
// RFC 6066 Section 5: Client Certificate URLs

extension RFC_6066.ClientCertificateURL {
    /// Errors raised when parsing a `client_certificate_url` payload.
    public enum Error: Swift.Error, Sendable, Equatable {
        /// The body was not empty, as RFC 6066 Section 5 requires it to be.
        case trailingData(_ remaining: Int)
    }
}

extension RFC_6066.ClientCertificateURL.Error: CustomStringConvertible {
    public var description: String {
        switch self {
        case .trailingData(let remaining):
            return "TLS client_certificate_url body must be empty, found \(remaining) bytes"
        }
    }
}
