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

// RFC_6066.CertificateURL.URLAndHash.swift
// swift-rfc-6066
//
// RFC 6066 Section 5: Client Certificate URLs

public import Binary_Serializable_Primitives

extension RFC_6066.CertificateURL {
    /// One URL of a `CertificateURL` message, with the SHA-1 hash of the object
    /// it points at.
    ///
    /// ## Wire Format
    ///
    /// ```
    /// struct {
    ///     opaque url<1..2^16-1>;
    ///     uint8 padding;
    ///     opaque SHA1Hash[20];
    /// } URLAndHash;
    /// ```
    ///
    /// RFC 6066 Section 5: "The 'padding' byte MUST be 0x01." It is a fixed
    /// constant, not data, so it is not stored — ``Padding`` is written on
    /// serialization and checked on parse
    /// (``RFC_6066/CertificateURL/Error/invalidPadding(_:)``).
    public struct URLAndHash: Sendable, Hashable {
        /// The URL of the certificate (or PkiPath chain), 1...65535 bytes.
        public let url: [Byte]

        /// The SHA-1 hash of the DER object at ``url``.
        public let sha1Hash: RFC_6066.SHA1Hash

        /// The mandatory `padding` byte value (0x01).
        public static let padding: Byte = Byte(0x01)

        /// Creates a URL/hash pair WITHOUT validation.
        init(__unchecked: Void, url: [Byte], sha1Hash: RFC_6066.SHA1Hash) {
            self.url = url
            self.sha1Hash = sha1Hash
        }

        /// Creates a URL/hash pair.
        ///
        /// - Parameters:
        ///   - url: The URL bytes (`opaque url<1..2^16-1>`).
        ///   - sha1Hash: The SHA-1 hash of the object at `url`.
        /// - Throws: ``Error`` if the URL is empty or exceeds 65535 bytes.
        public init(url: [Byte], sha1Hash: RFC_6066.SHA1Hash) throws(Error) {
            guard !url.isEmpty else {
                throw Error.emptyURL
            }
            guard url.count <= 65535 else {
                throw Error.urlTooLong(url.count)
            }
            self.init(__unchecked: (), url: url, sha1Hash: sha1Hash)
        }

        // Stdlib-interop forwarder `init(url: [UInt8], sha1Hash:)` moved to
        // `RFC 6066 Standard Library Integration` target per [API-BYTE-007].
    }
}

// MARK: - Binary.Serializable

extension RFC_6066.CertificateURL.URLAndHash: Binary.Serializable {
    public static func serialize<Buffer: RangeReplaceableCollection>(
        _ value: Self,
        into buffer: inout Buffer
    ) where Buffer.Element == Byte {
        RFC_6066.Wire.appendVector16(value.url, into: &buffer)
        buffer.append(Self.padding)
        RFC_6066.SHA1Hash.serialize(value.sha1Hash, into: &buffer)
    }
}

// MARK: - Wire Decoding

extension RFC_6066.Wire.Reader {
    /// Reads the raw fields of one `URLAndHash` from the cursor.
    ///
    /// Padding validation is the caller's job — the reader deals only in
    /// presentation-language forms.
    mutating func urlAndHashFields() throws(RFC_6066.Wire.Error)
    -> (url: [Byte], padding: UInt8, sha1Hash: [Byte]) {
        let url = try vector16()
        let padding = try byte()
        let sha1Hash = try take(20)
        return (url, padding, sha1Hash)
    }
}
