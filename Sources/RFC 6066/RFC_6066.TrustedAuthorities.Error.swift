extension RFC_6066.TrustedAuthorities {
    /// Errors raised when parsing a `trusted_ca_keys` payload.
    public enum Error: Swift.Error, Sendable, Equatable {
        /// An entry carried an `identifier_type` outside `pre_agreed(0)`,
        /// `key_sha1_hash(1)`, `x509_name(2)`, `cert_sha1_hash(3)`. Each variant
        /// has its own length, so an unknown one cannot be skipped.
        case unknownIdentifierType(_ rawValue: UInt8)

        /// The input ended before the list was complete.
        case truncated

        /// Bytes remained after the list.
        case trailingData(_ remaining: Int)
    }
}

extension RFC_6066.TrustedAuthorities.Error: CustomStringConvertible {
    public var description: String {
        switch self {
        case .unknownIdentifierType(let rawValue):
            return "TLS trusted_ca_keys has unknown identifier_type \(rawValue)"
        case .truncated:
            return "TLS trusted_ca_keys truncated"
        case .trailingData(let remaining):
            return "TLS trusted_ca_keys has \(remaining) trailing bytes"
        }
    }
}
