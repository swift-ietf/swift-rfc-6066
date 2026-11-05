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

// RFC_6066.MaxFragmentLength.swift
// swift-rfc-6066
//
// RFC 6066 Section 4: Maximum Fragment Length Negotiation

public import Binary
public import RFC_8446

extension RFC_6066 {
    /// `max_fragment_length` extension payload (`extension_data` body).
    ///
    /// ## Wire Format
    ///
    /// ```
    /// enum{
    ///     2^9(1), 2^10(2), 2^11(3), 2^12(4), (255)
    /// } MaxFragmentLength;
    /// ```
    ///
    /// The body is a single byte. Unlike most TLS enums this one is **closed**:
    /// RFC 6066 Section 4 fixes the allowed values at `2^9`, `2^10`, `2^11` and
    /// `2^12`, and a peer that receives any other value must abort with an
    /// `illegal_parameter` alert — so unknown code points are a parse failure
    /// (``Error/unknownLength(_:)``), not an unrecognized-but-representable case.
    ///
    /// ## Direction
    ///
    /// The client offers a length; the server that accepts it echoes the *same*
    /// `MaxFragmentLength` back (RFC 6066 Section 4) — the body is identical in
    /// both directions.
    ///
    /// ## TLS 1.3
    ///
    /// TLS 1.3 does not carry `max_fragment_length` (RFC 8446 Section 4.2);
    /// RFC 8449 `record_size_limit` supersedes it. The type is defined here for
    /// TLS 1.2 peers and specification completeness.
    public enum MaxFragmentLength: UInt8, Sendable, Hashable, CaseIterable {
        /// `2^9(1)` — a 512-byte maximum fragment length.
        case bytes512 = 1

        /// `2^10(2)` — a 1024-byte maximum fragment length.
        case bytes1024 = 2

        /// `2^11(3)` — a 2048-byte maximum fragment length.
        case bytes2048 = 3

        /// `2^12(4)` — a 4096-byte maximum fragment length.
        case bytes4096 = 4
    }
}

// MARK: - Fragment Length

extension RFC_6066.MaxFragmentLength {
    /// The negotiated maximum fragment length in bytes (512, 1024, 2048, or 4096).
    public var fragmentLength: Int {
        switch self {
        case .bytes512: return 512
        case .bytes1024: return 1024
        case .bytes2048: return 2048
        case .bytes4096: return 4096
        }
    }

    /// The extension type for this payload (`max_fragment_length`).
    public static let extensionType: RFC_8446.Extension.ExtensionType = .maxFragmentLength

    /// Wraps this payload in a generic ``RFC_8446/Extension/Data`` envelope.
    public var extensionData: RFC_8446.Extension.Data {
        // Cannot throw: this payload's fixed-size body is under the envelope's 65535-byte limit.
        // swiftlint:disable:next force_try
        try! RFC_8446.Extension.Data(type: Self.extensionType, data: self.bytes)
    }
}

// MARK: - Binary.Serializable

extension RFC_6066.MaxFragmentLength: Binary.Serializable {
    /// Serializes the single-byte `MaxFragmentLength` code point.
    public static func serialize<Buffer: RangeReplaceableCollection>(
        _ value: Self,
        into buffer: inout Buffer
    ) where Buffer.Element == Byte {
        buffer.append(Byte(value.rawValue))
    }

    /// Parses a `max_fragment_length` `extension_data` body.
    public init<Bytes: Swift::Collection>(binary bytes: Bytes) throws(Error)
    where Bytes.Element == Byte {
        var reader = RFC_6066.Wire.Reader(Array(bytes))
        let rawValue: UInt8
        do {
            rawValue = try reader.byte()
            try reader.expectEnd()
        } catch {
            switch error {
            case .trailingData(let remaining): throw .trailingData(remaining)
            case .truncated, .lengthOverflow: throw .truncated
            }
        }
        guard let value = Self(rawValue: rawValue) else {
            throw Error.unknownLength(rawValue)
        }
        self = value
    }
}

// MARK: - CustomStringConvertible

extension RFC_6066.MaxFragmentLength: CustomStringConvertible {
    public var description: String {
        switch self {
        case .bytes512: return "2^9"
        case .bytes1024: return "2^10"
        case .bytes2048: return "2^11"
        case .bytes4096: return "2^12"
        }
    }
}
