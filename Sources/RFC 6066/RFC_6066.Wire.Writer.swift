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

// RFC_6066.Wire.Writer.swift
// swift-rfc-6066
//
// TLS presentation language: append helpers

internal import Binary_Serializable_Primitives

extension RFC_6066.Wire {
    /// Appends a big-endian `uint24` (0...2^24-1). `BinaryInteger` has no
    /// 3-byte form, so the split is manual; arithmetic-domain `Int` internal,
    /// `Byte()` bridge at the append boundary.
    static func appendUInt24<Buffer: RangeReplaceableCollection>(
        _ value: Int,
        into buffer: inout Buffer
    ) where Buffer.Element == Byte {
        buffer.append(Byte(UInt8((value >> 16) & 0xFF)))
        buffer.append(Byte(UInt8((value >> 8) & 0xFF)))
        buffer.append(Byte(UInt8(value & 0xFF)))
    }

    /// Appends a `uint16`-length-prefixed opaque vector.
    static func appendVector16<Buffer: RangeReplaceableCollection>(
        _ bytes: [Byte],
        into buffer: inout Buffer
    ) where Buffer.Element == Byte {
        buffer.append(contentsOf: UInt16(bytes.count).bytes(endianness: .big))
        buffer.append(contentsOf: bytes)
    }

    /// Appends a `uint24`-length-prefixed opaque vector.
    static func appendVector24<Buffer: RangeReplaceableCollection>(
        _ bytes: [Byte],
        into buffer: inout Buffer
    ) where Buffer.Element == Byte {
        appendUInt24(bytes.count, into: &buffer)
        buffer.append(contentsOf: bytes)
    }
}
