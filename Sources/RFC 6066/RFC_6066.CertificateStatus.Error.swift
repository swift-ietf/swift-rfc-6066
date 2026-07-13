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

// RFC_6066.CertificateStatus.Error.swift
// swift-rfc-6066
//
// RFC 6066 Section 8: Certificate Status Request (server response)

extension RFC_6066.CertificateStatus {
    /// Errors raised when creating or parsing a `CertificateStatus`.
    public enum Error: Swift.Error, Sendable, Equatable {
        /// `OCSPResponse` is bounded `<1..2^24-1>`; it cannot be empty.
        case emptyResponse

        /// `OCSPResponse` is bounded `<1..2^24-1>`; it cannot exceed 16777215 bytes.
        case responseTooLong(_ length: Int)

        /// The `status_type` discriminator is not `ocsp(1)`, so the `response`
        /// variant has no known length and cannot be read.
        case unsupportedStatusType(_ rawValue: UInt8)

        /// The input ended before the response was complete.
        case truncated

        /// Bytes remained after the response.
        case trailingData(_ remaining: Int)
    }
}

extension RFC_6066.CertificateStatus.Error: CustomStringConvertible {
    public var description: String {
        switch self {
        case .emptyResponse:
            return "TLS CertificateStatus OCSP response cannot be empty"
        case .responseTooLong(let length):
            return "TLS CertificateStatus OCSP response too long: \(length) bytes (max 16777215)"
        case .unsupportedStatusType(let rawValue):
            return "TLS CertificateStatus has unsupported status_type \(rawValue) (only ocsp(1) is defined)"
        case .truncated:
            return "TLS CertificateStatus truncated"
        case .trailingData(let remaining):
            return "TLS CertificateStatus has \(remaining) trailing bytes"
        }
    }
}
