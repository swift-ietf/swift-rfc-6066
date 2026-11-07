public import Binary

extension RFC_6066.CertificateStatusRequest {
    /// The `ocsp` variant of a `status_request`.
    ///
    /// ## Wire Format
    ///
    /// ```
    /// struct {
    ///     ResponderID responder_id_list<0..2^16-1>;
    ///     Extensions  request_extensions;
    /// } OCSPStatusRequest;
    ///
    /// opaque ResponderID<1..2^16-1>;
    /// opaque Extensions<0..2^16-1>;
    /// ```
    ///
    /// Both members are opaque DER (RFC 6960): a `ResponderID` is a DER-encoded
    /// OCSP `ResponderID`, and `request_extensions` is a DER-encoded OCSP
    /// `Extensions` sequence. Neither is interpreted here.
    ///
    /// RFC 6066 Section 8: "A zero-length 'responder_id_list' sequence has the
    /// special meaning that the responders are implicitly known to the server" —
    /// hence the empty defaults.
    public struct OCSPStatusRequest: Sendable, Hashable {
        /// DER-encoded OCSP responder identities the client trusts (may be empty).
        public let responderIDList: [[Byte]]

        /// DER-encoded OCSP request extensions (may be empty).
        public let requestExtensions: [Byte]

        /// Creates an OCSP status request.
        ///
        /// - Parameters:
        ///   - responderIDList: DER-encoded `ResponderID`s; empty means "any
        ///     responder known to the server".
        ///   - requestExtensions: DER-encoded OCSP `Extensions`; empty means none.
        public init(responderIDList: [[Byte]] = [], requestExtensions: [Byte] = []) {
            self.responderIDList = responderIDList
            self.requestExtensions = requestExtensions
        }

    }
}

extension RFC_6066.CertificateStatusRequest.OCSPStatusRequest: Binary.Serializable {
    public static func serialize<Buffer: RangeReplaceableCollection>(
        _ value: Self,
        into buffer: inout Buffer
    ) where Buffer.Element == Byte {
        var block: [Byte] = []
        for responderID in value.responderIDList {
            RFC_6066.Wire.appendVector16(responderID, into: &block)
        }
        RFC_6066.Wire.appendVector16(block, into: &buffer)
        RFC_6066.Wire.appendVector16(value.requestExtensions, into: &buffer)
    }
}

extension RFC_6066.Wire.Reader {
    /// Reads one ``RFC_6066/CertificateStatusRequest/OCSPStatusRequest`` from the
    /// cursor (the body after the `status_type` discriminator).
    mutating func ocspStatusRequest() throws(RFC_6066.Wire.Error)
        -> RFC_6066.CertificateStatusRequest.OCSPStatusRequest
    {
        let block = try vector16()
        var sub = RFC_6066.Wire.Reader(block)
        var responderIDList: [[Byte]] = []
        while !sub.isAtEnd {
            responderIDList.append(try sub.vector16())
        }
        let requestExtensions = try vector16()
        return RFC_6066.CertificateStatusRequest.OCSPStatusRequest(
            responderIDList: responderIDList,
            requestExtensions: requestExtensions
        )
    }
}
