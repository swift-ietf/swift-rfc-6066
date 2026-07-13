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

// RFC_6066.Alert.Description.swift
// swift-rfc-6066
//
// RFC 6066 Section 9: Error Alerts
//
// RFC 6066 defines three alerts: unrecognized_name(112),
// bad_certificate_status_response(113) and bad_certificate_hash_value(114).
// TLS 1.3 carries the first two, so `RFC_8446.Alert.Description` already
// declares them — the alert registry, like the extension registry, has a single
// home. This file adds only the third, which TLS 1.3 does not carry.

public import RFC_8446

extension RFC_8446.Alert.Description {
    /// bad_certificate_hash_value (114) — RFC 6066 Section 9.
    ///
    /// Sent when the SHA-1 hash in a ``RFC_6066/CertificateURL`` entry does not
    /// match the certificate retrieved from the URL. Not carried forward by TLS
    /// 1.3 (RFC 8446 Section 6.2), which has no `client_certificate_url`.
    public static let badCertificateHashValue = Self(rawValue: 114)
}
