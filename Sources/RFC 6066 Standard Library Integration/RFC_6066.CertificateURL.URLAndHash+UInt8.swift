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

// RFC_6066.CertificateURL.URLAndHash+UInt8.swift
//
// Stdlib-interop UInt8 forwarder for CertificateURL entry construction. Primary
// byte-domain API lives in `RFC 6066`; this forwarder bridges stdlib callers
// carrying a `[UInt8]` URL via `[Byte](uint8s)`.
// Per [API-BYTE-007] (byte-discipline skill).

internal import Byte_Primitives
public import RFC_6066

extension RFC_6066.CertificateURL.URLAndHash {
    /// Stdlib-interop forwarder: construction from a `[UInt8]` URL.
    @_disfavoredOverload
    public init(url: [UInt8], sha1Hash: RFC_6066.SHA1Hash) throws(Error) {
        try self.init(url: [Byte](url), sha1Hash: sha1Hash)
    }
}
