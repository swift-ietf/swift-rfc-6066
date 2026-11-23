extension IETF.RFC.`6066`.HMAC.Truncated {
    /// Errors raised when parsing a `truncated_hmac` payload.
    public enum Error: Swift.Error, Sendable, Equatable {
        /// The body was not empty, as RFC 6066 Section 7 requires it to be.
        case trailingData(_ remaining: Int)
    }
}

extension IETF.RFC.`6066`.HMAC.Truncated.Error: CustomStringConvertible {
    public var description: String {
        switch self {
        case .trailingData(let remaining):
            return "TLS truncated_hmac body must be empty, found \(remaining) bytes"
        }
    }
}
