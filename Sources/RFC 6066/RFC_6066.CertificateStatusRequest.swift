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

// RFC_6066.CertificateStatusRequest.swift
// swift-rfc-6066
//
// RFC 6066 Section 8: Certificate Status Request

public import Binary_Serializable_Primitives
public import RFC_8446

extension RFC_6066 {
    /// `status_request` extension payload (`extension_data` body) — the client's
    /// OCSP request.
    ///
    /// ## Wire Format
    ///
    /// ```
    /// struct {
    ///     CertificateStatusType status_type;
    ///     select (status_type) {
    ///         case ocsp: OCSPStatusRequest;
    ///     } request;
    /// } CertificateStatusRequest;
    /// ```
    ///
    /// `ocsp(1)` is the only registered ``CertificateStatusType``, so the variant
    /// collapses to a single stored ``OCSPStatusRequest``; ``statusType`` reports
    /// the wire discriminator. Parsing any other status type fails with
    /// ``Error/unsupportedStatusType(_:)``.
    ///
    /// ## Direction
    ///
    /// The **client** sends this body. The **server**'s ServerHello/CertificateEntry
    /// response body is the OCSP response itself — ``RFC_6066/CertificateStatus``
    /// (TLS 1.3, RFC 8446 Section 4.4.2.1) — or, in TLS 1.2, an *empty*
    /// `status_request` extension followed by a `CertificateStatus` handshake
    /// message.
    public struct CertificateStatusRequest: Sendable, Hashable {
        /// The OCSP request parameters.
        public let request: OCSPStatusRequest

        /// Creates an OCSP `status_request` payload.
        public init(request: OCSPStatusRequest) {
            self.request = request
        }

        /// Creates an OCSP `status_request` payload with no responder IDs and no
        /// request extensions — the common "any responder, no extensions" form.
        public init() {
            self.init(request: OCSPStatusRequest())
        }

        /// The wire discriminator for this payload — always `ocsp(1)`.
        public var statusType: CertificateStatusType { .ocsp }

        /// The extension type for this payload (`status_request`).
        public static let extensionType: RFC_8446.Extension.ExtensionType = .statusRequest

        /// Wraps this payload in a generic ``RFC_8446/Extension/Data`` envelope.
        public var extensionData: RFC_8446.Extension.Data {
            RFC_8446.Extension.Data(type: Self.extensionType, data: self.bytes)
        }
    }
}

// MARK: - Binary.Serializable

extension RFC_6066.CertificateStatusRequest: Binary.Serializable {
    public static func serialize<Buffer: RangeReplaceableCollection>(
        _ value: Self,
        into buffer: inout Buffer
    ) where Buffer.Element == Byte {
        buffer.append(Byte(value.statusType.rawValue))
        OCSPStatusRequest.serialize(value.request, into: &buffer)
    }

    /// Parses a `status_request` `extension_data` body.
    public init<Bytes: Collection>(binary bytes: Bytes) throws(Error)
    where Bytes.Element == Byte {
        var reader = RFC_6066.Wire.Reader(Array(bytes))

        let statusType: UInt8
        do {
            statusType = try reader.byte()
        } catch {
            throw .truncated
        }
        guard statusType == RFC_6066.CertificateStatusType.ocsp.rawValue else {
            throw .unsupportedStatusType(statusType)
        }

        let request: OCSPStatusRequest
        do {
            request = try reader.ocspStatusRequest()
            try reader.expectEnd()
        } catch {
            switch error {
            case .trailingData(let remaining): throw .trailingData(remaining)
            case .truncated, .lengthOverflow: throw .truncated
            }
        }
        self.init(request: request)
    }
}
