extension RFC_6066.CertificateStatusRequest {
    /// Errors raised when parsing a `status_request` payload.
    public enum Error: Swift.Error, Sendable, Equatable {
        /// The `status_type` discriminator is not `ocsp(1)`, so the `request`
        /// variant has no known length and cannot be read.
        case unsupportedStatusType(_ rawValue: UInt8)

        /// The request failed
        /// ``RFC_6066/CertificateStatusRequest/OCSPStatusRequest`` validation.
        case invalidRequest(_ error: RFC_6066.CertificateStatusRequest.OCSPStatusRequest.Error)

        /// The input ended before the request was complete.
        case truncated

        /// Bytes remained after the request.
        case trailingData(_ remaining: Int)
    }
}

extension RFC_6066.CertificateStatusRequest.Error: CustomStringConvertible {
    public var description: String {
        switch self {
        case .unsupportedStatusType(let rawValue):
            return "TLS status_request has unsupported status_type \(rawValue) (only ocsp(1) is defined)"
        case .invalidRequest(let error):
            return "TLS status_request has an invalid OCSP request: \(error)"
        case .truncated:
            return "TLS status_request truncated"
        case .trailingData(let remaining):
            return "TLS status_request has \(remaining) trailing bytes"
        }
    }
}
