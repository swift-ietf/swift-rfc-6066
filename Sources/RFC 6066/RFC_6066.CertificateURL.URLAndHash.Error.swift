extension RFC_6066.CertificateURL.URLAndHash {
    /// Errors raised when creating a `URLAndHash`.
    public enum Error: Swift.Error, Sendable, Equatable {
        /// `url` is bounded `<1..2^16-1>`; it cannot be empty.
        case emptyURL

        /// `url` is bounded `<1..2^16-1>`; it cannot exceed 65535 bytes.
        case urlTooLong(_ length: Int)
    }
}

extension RFC_6066.CertificateURL.URLAndHash.Error: CustomStringConvertible {
    public var description: String {
        switch self {
        case .emptyURL:
            return "TLS CertificateURL url cannot be empty"
        case .urlTooLong(let length):
            return "TLS CertificateURL url too long: \(length) bytes (max 65535)"
        }
    }
}
