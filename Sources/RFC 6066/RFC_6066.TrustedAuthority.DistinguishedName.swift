public import Binary

extension RFC_6066.TrustedAuthority {
    /// The DER-encoded X.509 `DistinguishedName` of an ``x509Name(_:)``
    /// authority.
    ///
    /// ## Wire Format
    ///
    /// ```
    /// opaque DistinguishedName<1..2^16-1>;
    /// ```
    ///
    /// The DER is carried opaquely; only the vector bounds are enforced.
    public struct DistinguishedName: Sendable, Hashable {
        /// The DER-encoded name, 1...65535 bytes.
        public let rawValue: [Byte]

        /// Creates a distinguished name WITHOUT validation.
        init(__unchecked: Void, rawValue: [Byte]) {
            self.rawValue = rawValue
        }

        /// Creates a distinguished name.
        ///
        /// - Parameter rawValue: The DER bytes (`opaque DistinguishedName<1..2^16-1>`).
        /// - Throws: ``Error`` if the name is empty or exceeds 65535 bytes.
        public init(rawValue: [Byte]) throws(Error) {
            guard !rawValue.isEmpty else {
                throw Error.empty
            }
            guard rawValue.count <= 65535 else {
                throw Error.tooLong(rawValue.count)
            }
            self.init(__unchecked: (), rawValue: rawValue)
        }
    }
}
