extension RFC_6066.ClientCertificateURL {
    /// Errors raised when parsing a `client_certificate_url` payload.
    public enum Error: Swift.Error, Sendable, Equatable {
        /// The body was not empty, as RFC 6066 Section 5 requires it to be.
        case trailingData(_ remaining: Int)
    }
}

extension RFC_6066.ClientCertificateURL.Error: CustomStringConvertible {
    public var description: String {
        switch self {
        case .trailingData(let remaining):
            return "TLS client_certificate_url body must be empty, found \(remaining) bytes"
        }
    }
}
