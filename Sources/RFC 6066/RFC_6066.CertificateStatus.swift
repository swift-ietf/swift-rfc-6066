public import Binary
public import RFC_8446

extension RFC_6066 {
    /// The server's OCSP status response.
    ///
    /// ## Wire Format
    ///
    /// ```
    /// struct {
    ///     CertificateStatusType status_type;
    ///     select (status_type) {
    ///         case ocsp: OCSPResponse;
    ///     } response;
    /// } CertificateStatus;
    ///
    /// opaque OCSPResponse<1..2^24-1>;
    /// ```
    ///
    /// `ocsp(1)` is the only registered ``CertificateStatusType``, so the variant
    /// collapses to a single stored DER `OCSPResponse` (RFC 6960); ``statusType``
    /// reports the wire discriminator.
    ///
    /// ## Two Homes
    ///
    /// - **TLS 1.2** (RFC 6066 Section 8): this structure is the body of the
    ///   `CertificateStatus` *handshake message* (type 22), sent after the
    ///   server's Certificate message. The `status_request` extension in the
    ///   ServerHello is empty.
    /// - **TLS 1.3** (RFC 8446 Section 4.4.2.1): this same structure is the
    ///   `extension_data` of a `status_request` extension carried in the
    ///   server's `CertificateEntry`. ``extensionData`` produces that form.
    public struct CertificateStatus: Sendable, Hashable {
        /// The DER-encoded OCSP response (RFC 6960), 1...2^24-1 bytes.
        public let response: [Byte]

        /// Creates an OCSP status response WITHOUT validation.
        init(__unchecked: Void, response: [Byte]) {
            self.response = response
        }

        /// Creates an OCSP status response.
        ///
        /// - Parameter response: The DER-encoded OCSP response
        ///   (`opaque OCSPResponse<1..2^24-1>`).
        /// - Throws: ``Error`` if the response is empty or exceeds 2^24-1 bytes.
        public init(response: [Byte]) throws(Error) {
            guard !response.isEmpty else {
                throw Error.emptyResponse
            }
            guard response.count <= 0xFF_FFFF else {
                throw Error.responseTooLong(response.count)
            }
            self.init(__unchecked: (), response: response)
        }
    }
}

extension RFC_6066.CertificateStatus {
    /// The wire discriminator for this response — always `ocsp(1)`.
    public var statusType: CertificateStatusType { .ocsp }

    /// The extension type carrying this response in TLS 1.3 (`status_request`).
    public static let extensionType: RFC_8446.Extension.ExtensionType = .statusRequest

    /// Wraps this response in a generic ``RFC_8446/Extension/Data`` envelope —
    /// the TLS 1.3 `CertificateEntry` form (RFC 8446 Section 4.4.2.1).
    public var extensionData: RFC_8446.Extension.Data {
        get throws(RFC_8446.Extension.Data.Error) {
            try RFC_8446.Extension.Data(type: Self.extensionType, data: self.bytes)
        }
    }
}

extension RFC_6066.CertificateStatus: Binary.Serializable {
    public static func serialize<Buffer: RangeReplaceableCollection>(
        _ value: Self,
        into buffer: inout Buffer
    ) where Buffer.Element == Byte {
        buffer.append(Byte(value.statusType.rawValue))
        RFC_6066.Wire.appendVector24(value.response, into: &buffer)
    }

    /// Parses a `CertificateStatus` structure (handshake-message body in TLS 1.2,
    /// `status_request` `extension_data` in TLS 1.3).
    public init<Bytes: Swift::Collection>(binary bytes: Bytes) throws(Error)
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

        let response: [Byte]
        do {
            response = try reader.vector24()
            try reader.expectEnd()
        } catch {
            switch error {
            case .trailingData(let remaining): throw .trailingData(remaining)
            case .truncated, .lengthOverflow: throw .truncated
            }
        }
        try self.init(response: response)
    }
}
