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

// RFC_6066.ExtensionType.swift
// swift-rfc-6066
//
// RFC 6066 Section 1.1: Extension type registry entries
//
// ```
// enum {
//     server_name(0), max_fragment_length(1),
//     client_certificate_url(2), trusted_ca_keys(3),
//     truncated_hmac(4), status_request(5), (65535)
// } ExtensionType;
// ```
//
// The registry itself lives in `RFC_8446.Extension.ExtensionType` — the single
// home for TLS extension code points. `server_name(0)`, `max_fragment_length(1)`
// and `status_request(5)` are already declared there (TLS 1.3 carries them
// forward). This file adds only the three RFC 6066 code points that TLS 1.3
// does not carry, so every RFC 6066 extension has a named constant.

public import RFC_8446

extension RFC_8446.Extension.ExtensionType {
    /// client_certificate_url (2) — RFC 6066 Section 5.
    ///
    /// Not carried forward by TLS 1.3 (RFC 8446 Section 4.2).
    public static let clientCertificateURL = Self(rawValue: 2)

    /// trusted_ca_keys (3) — RFC 6066 Section 6.
    ///
    /// Not carried forward by TLS 1.3 (RFC 8446 Section 4.2).
    public static let trustedCAKeys = Self(rawValue: 3)

    /// truncated_hmac (4) — RFC 6066 Section 7.
    ///
    /// Not carried forward by TLS 1.3 (RFC 8446 Section 4.2).
    public static let truncatedHMAC = Self(rawValue: 4)
}
