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

// RFC_6066.CertificateStatusType.swift
// swift-rfc-6066
//
// RFC 6066 Section 8: Certificate Status Request

extension RFC_6066 {
    /// `CertificateStatusType`, the discriminator of the `status_request`
    /// request and response variants.
    ///
    /// ```
    /// enum { ocsp(1), (255) } CertificateStatusType;
    /// ```
    ///
    /// `ocsp(1)` is the only registered status type. The type stays open
    /// (`RawRepresentable`) so an unrecognized code point can be reported, but it
    /// cannot be *parsed*: the RFC defines no generic length prefix for the
    /// variant that follows, so an unknown status type makes the remainder
    /// unreadable.
    public struct CertificateStatusType: RawRepresentable, Sendable, Hashable, Codable {
        public let rawValue: UInt8

        public init(rawValue: UInt8) {
            self.rawValue = rawValue
        }

        /// Creates a CertificateStatusType WITHOUT validation.
        init(__unchecked: Void, rawValue: UInt8) {
            self.rawValue = rawValue
        }

        /// ocsp (1) — the status is an OCSP response (RFC 6960).
        public static let ocsp = Self(__unchecked: (), rawValue: 1)
    }
}

// MARK: - CustomStringConvertible

extension RFC_6066.CertificateStatusType: CustomStringConvertible {
    public var description: String {
        switch rawValue {
        case 1: return "ocsp"
        default: return "certificate_status_type(\(rawValue))"
        }
    }
}
