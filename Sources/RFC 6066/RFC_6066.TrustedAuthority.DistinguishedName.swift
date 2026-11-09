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
    }
}

extension RFC_6066.TrustedAuthority.DistinguishedName {
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

extension RFC_6066.TrustedAuthority.DistinguishedName {
    /// The number of bytes this name occupies on the wire: the `uint16`
    /// length prefix and the DER.
    var encodedLength: Int {
        2 + rawValue.count
    }

    /// Serializes the name as the `opaque DistinguishedName<1..2^16-1>` vector
    /// (`uint16` length prefix + the DER bytes).
    static func serialize<Buffer: RangeReplaceableCollection>(
        _ distinguishedName: Self,
        into buffer: inout Buffer
    ) where Buffer.Element == Byte {
        RFC_6066.Wire.appendVector16(distinguishedName.rawValue, into: &buffer)
    }
}
