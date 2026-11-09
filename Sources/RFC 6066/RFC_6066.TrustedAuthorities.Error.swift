extension RFC_6066.TrustedAuthorities {
    /// Errors raised when parsing a `trusted_ca_keys` payload.
    public enum Error: Swift.Error, Sendable, Equatable {
        /// An entry carried an `identifier_type` outside `pre_agreed(0)`,
        /// `key_sha1_hash(1)`, `x509_name(2)`, `cert_sha1_hash(3)`. Each variant
        /// has its own length, so an unknown one cannot be skipped.
        case unknownIdentifierType(_ rawValue: UInt8)

        /// An `x509_name` entry failed
        /// ``RFC_6066/TrustedAuthority/DistinguishedName`` validation.
        case invalidDistinguishedName(_ error: RFC_6066.TrustedAuthority.DistinguishedName.Error)

        /// `trusted_authorities_list` is bounded `<0..2^16-1>`; its encoding
        /// cannot exceed 65535 bytes.
        case listTooLong(_ length: Int)

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
        case .invalidDistinguishedName(let error):
            return "TLS trusted_ca_keys has an invalid x509_name: \(error)"
        case .listTooLong(let length):
            return "TLS trusted_ca_keys list too long: \(length) bytes (max 65535)"
        case .truncated:
            return "TLS trusted_ca_keys truncated"
        case .trailingData(let remaining):
            return "TLS trusted_ca_keys has \(remaining) trailing bytes"
        }
    }
}
