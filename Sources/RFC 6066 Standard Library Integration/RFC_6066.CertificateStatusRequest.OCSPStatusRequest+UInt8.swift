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

// RFC_6066.CertificateStatusRequest.OCSPStatusRequest+UInt8.swift
//
// Stdlib-interop UInt8 forwarder for OCSP status request construction. Primary
// byte-domain API lives in `RFC 6066`; this forwarder bridges stdlib callers
// carrying `[UInt8]` DER (responder IDs, request extensions) via
// `[Byte](uint8s)`. Per [API-BYTE-007] (byte-discipline skill).

internal import Byte_Primitives
public import RFC_6066

extension RFC_6066.CertificateStatusRequest.OCSPStatusRequest {
    /// Stdlib-interop forwarder: construction from `[UInt8]` DER.
    @_disfavoredOverload
    public init(responderIDList: [[UInt8]], requestExtensions: [UInt8]) {
        self.init(
            responderIDList: responderIDList.map { [Byte]($0) },
            requestExtensions: [Byte](requestExtensions)
        )
    }
}
