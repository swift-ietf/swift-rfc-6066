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

// RFC_6066.ServerName.NameType.swift
// swift-rfc-6066
//
// RFC 6066 Section 3: Server Name Indication

extension RFC_6066.ServerName {
    /// `NameType`, the discriminator of the `ServerName` variant.
    ///
    /// ```
    /// enum {
    ///     host_name(0), (255)
    /// } NameType;
    /// ```
    ///
    /// `host_name(0)` is the only name type ever registered. The type stays
    /// open (`RawRepresentable`) so an unrecognized code point can be reported,
    /// but it cannot be *parsed*: the RFC defines no generic length prefix for
    /// the `name` variant, so an unknown `NameType` makes the remainder of the
    /// list unreadable.
    public struct NameType: RawRepresentable, Sendable, Hashable, Codable {
        public let rawValue: UInt8

        public init(rawValue: UInt8) {
            self.rawValue = rawValue
        }

        /// Creates a NameType WITHOUT validation.
        init(__unchecked: Void, rawValue: UInt8) {
            self.rawValue = rawValue
        }

        /// host_name (0) — the name is a `HostName`.
        public static let hostName = Self(__unchecked: (), rawValue: 0)
    }
}

// MARK: - CustomStringConvertible

extension RFC_6066.ServerName.NameType: CustomStringConvertible {
    public var description: String {
        switch rawValue {
        case 0: return "host_name"
        default: return "name_type(\(rawValue))"
        }
    }
}
