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

// RFC_6066.Wire.Error.swift
// swift-rfc-6066
//
// TLS presentation language: reader errors

extension RFC_6066.Wire {
    /// Errors raised by the presentation-language reader.
    ///
    /// Payload parsers catch these and map them onto their own typed `Error`
    /// so the internal ``RFC_6066/Wire`` namespace stays out of the public
    /// surface.
    enum Error: Swift.Error, Sendable, Equatable {
        /// The reader ran out of bytes before a field was complete.
        case truncated

        /// A declared vector/field length exceeded the bytes actually present.
        case lengthOverflow

        /// Bytes remained after a structure that should have consumed the input.
        case trailingData(_ remaining: Int)
    }
}
