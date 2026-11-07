public import Binary

extension RFC_6066 {
    /// One trusted certificate authority of a `trusted_ca_keys` payload.
    ///
    /// ## Wire Format
    ///
    /// ```
    /// struct {
    ///     IdentifierType identifier_type;
    ///     select (identifier_type) {
    ///         case pre_agreed: struct {};
    ///         case key_sha1_hash: SHA1Hash;
    ///         case x509_name: DistinguishedName;
    ///         case cert_sha1_hash: SHA1Hash;
    ///     } identifier;
    /// } TrustedAuthority;
    ///
    /// opaque DistinguishedName<1..2^16-1>;
    /// ```
    ///
    /// A genuine four-way variant, so it is modelled as an enum: the payload
    /// shape (nothing / a fixed 20-byte digest / a length-prefixed DER name) is
    /// determined by the `identifier_type` discriminator, which ``identifierType``
    /// reports.
    ///
    /// The `<1..2^16-1>` lower bound on `DistinguishedName` is *not* enforced:
    /// an empty ``x509Name(_:)`` serializes as a zero-length vector, which is
    /// wire-parseable but out of spec. Callers supply DER that is non-empty by
    /// construction.
    public enum TrustedAuthority: Sendable, Hashable {
        /// pre_agreed(0) — no identifier travels on the wire.
        case preAgreed

        /// key_sha1_hash(1) — SHA-1 of the CA's `SubjectPublicKeyInfo`.
        case keySHA1Hash(SHA1Hash)

        /// x509_name(2) — the CA's DER-encoded X.509 `DistinguishedName`.
        case x509Name([Byte])

        /// cert_sha1_hash(3) — SHA-1 of the CA's DER certificate.
        case certSHA1Hash(SHA1Hash)
    }
}

extension RFC_6066.TrustedAuthority {
    /// The wire discriminator for this authority.
    public var identifierType: IdentifierType {
        switch self {
        case .preAgreed: return .preAgreed
        case .keySHA1Hash: return .keySHA1Hash
        case .x509Name: return .x509Name
        case .certSHA1Hash: return .certSHA1Hash
        }
    }
}

extension RFC_6066.TrustedAuthority: Binary.Serializable {
    public static func serialize<Buffer: RangeReplaceableCollection>(
        _ value: Self,
        into buffer: inout Buffer
    ) where Buffer.Element == Byte {
        buffer.append(Byte(value.identifierType.rawValue))
        switch value {
        case .preAgreed:
            break
        case .keySHA1Hash(let hash), .certSHA1Hash(let hash):
            RFC_6066.SHA1Hash.serialize(hash, into: &buffer)
        case .x509Name(let distinguishedName):
            RFC_6066.Wire.appendVector16(distinguishedName, into: &buffer)
        }
    }
}
