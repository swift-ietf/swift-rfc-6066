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

// RFC_6066.SHA1Hash.swift
// swift-rfc-6066
//
// RFC 6066 Sections 5 and 6: SHA1Hash

public import Binary_Serializable_Primitives

extension RFC_6066 {
    /// `SHA1Hash` — a fixed-width 20-byte SHA-1 digest.
    ///
    /// ## Wire Format
    ///
    /// ```
    /// opaque SHA1Hash[20];
    /// ```
    ///
    /// A *fixed*-length vector: it carries no length prefix on the wire. Used by
    /// ``RFC_6066/CertificateURL/URLAndHash`` (Section 5) and by the
    /// `key_sha1_hash` / `cert_sha1_hash` variants of
    /// ``RFC_6066/TrustedAuthority`` (Section 6).
    ///
    /// The digest is carried opaquely — this package computes no hashes and
    /// takes no cryptographic dependency.
    public struct SHA1Hash: Sendable, Hashable {
        /// The 20 digest bytes.
        public let rawValue: [Byte]

        /// Creates a digest WITHOUT validation.
        init(__unchecked: Void, rawValue: [Byte]) {
            self.rawValue = rawValue
        }

        /// Creates a digest, requiring exactly 20 bytes.
        ///
        /// - Parameter rawValue: The 20 SHA-1 digest bytes.
        /// - Throws: ``Error/invalidLength(_:)`` if the count is not 20.
        public init(rawValue: [Byte]) throws(Error) {
            guard rawValue.count == 20 else {
                throw Error.invalidLength(rawValue.count)
            }
            self.init(__unchecked: (), rawValue: rawValue)
        }

        // Stdlib-interop forwarder `init(rawValue: [UInt8])` moved to
        // `RFC 6066 Standard Library Integration` target per [API-BYTE-007].
    }
}

// MARK: - Binary.Serializable

extension RFC_6066.SHA1Hash: Binary.Serializable {
    /// Serializes the 20 digest bytes — no length prefix (`SHA1Hash[20]` is a
    /// fixed-width vector).
    public static func serialize<Buffer: RangeReplaceableCollection>(
        _ hash: Self,
        into buffer: inout Buffer
    ) where Buffer.Element == Byte {
        buffer.append(contentsOf: hash.rawValue)
    }

    /// Parses exactly 20 digest bytes.
    public init<Bytes: Collection>(binary bytes: Bytes) throws(Error)
    where Bytes.Element == Byte {
        try self.init(rawValue: Array(bytes))
    }
}
