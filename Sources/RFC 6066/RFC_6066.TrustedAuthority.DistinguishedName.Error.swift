extension RFC_6066.TrustedAuthority.DistinguishedName {
    /// Errors raised when creating a `DistinguishedName`.
    public enum Error: Swift.Error, Sendable, Equatable {
        /// `DistinguishedName` is bounded `<1..2^16-1>`; it cannot be empty.
        case empty

        /// `DistinguishedName` is bounded `<1..2^16-1>`; it cannot exceed 65535 bytes.
        case tooLong(_ length: Int)
    }
}

extension RFC_6066.TrustedAuthority.DistinguishedName.Error: CustomStringConvertible {
    public var description: String {
        switch self {
        case .empty:
            return "TLS trusted_ca_keys DistinguishedName cannot be empty"
        case .tooLong(let length):
            return "TLS trusted_ca_keys DistinguishedName too long: \(length) bytes (max 65535)"
        }
    }
}
