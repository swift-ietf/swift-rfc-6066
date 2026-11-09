extension RFC_6066.CertificateStatusRequest.OCSPStatusRequest {
    /// Errors raised when creating an `OCSPStatusRequest`.
    public enum Error: Swift.Error, Sendable, Equatable {
        /// `ResponderID` is bounded `<1..2^16-1>`; it cannot be empty.
        case emptyResponderID

        /// `ResponderID` is bounded `<1..2^16-1>`; it cannot exceed 65535 bytes.
        case responderIDTooLong(_ length: Int)

        /// `responder_id_list` is bounded `<0..2^16-1>`; its encoding cannot
        /// exceed 65535 bytes.
        case responderIDListTooLong(_ length: Int)

        /// `Extensions` is bounded `<0..2^16-1>`; it cannot exceed 65535 bytes.
        case requestExtensionsTooLong(_ length: Int)
    }
}

extension RFC_6066.CertificateStatusRequest.OCSPStatusRequest.Error: CustomStringConvertible {
    public var description: String {
        switch self {
        case .emptyResponderID:
            return "TLS OCSPStatusRequest ResponderID cannot be empty"
        case .responderIDTooLong(let length):
            return "TLS OCSPStatusRequest ResponderID too long: \(length) bytes (max 65535)"
        case .responderIDListTooLong(let length):
            return "TLS OCSPStatusRequest responder_id_list too long: \(length) bytes (max 65535)"
        case .requestExtensionsTooLong(let length):
            return "TLS OCSPStatusRequest request_extensions too long: \(length) bytes (max 65535)"
        }
    }
}
