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

// RFC_6066.CertificateStatus+UInt8.swift
//
// Stdlib-interop UInt8 forwarder for OCSP response construction. Primary
// byte-domain API lives in `RFC 6066`; this forwarder bridges stdlib callers
// carrying `[UInt8]` (e.g. DER read from disk or an OCSP responder) via
// bit pattern. Per [API-BYTE-007] (byte-discipline skill).

internal import Byte
public import RFC_6066

extension RFC_6066.CertificateStatus {
    /// Stdlib-interop forwarder: construction from a `[UInt8]` OCSP response.
    @_disfavoredOverload
    public init(response: [UInt8]) throws(Error) {
        try self.init(response: response.map(Byte.init(bitPattern:)))
    }
}
