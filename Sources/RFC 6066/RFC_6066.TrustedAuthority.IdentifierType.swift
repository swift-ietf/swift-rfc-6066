extension RFC_6066.TrustedAuthority {
    /// `IdentifierType`, the discriminator of the `TrustedAuthority` variant.
    ///
    /// ```
    /// enum {
    ///     pre_agreed(0), key_sha1_hash(1), x509_name(2),
    ///     cert_sha1_hash(3), (255)
    /// } IdentifierType;
    /// ```
    ///
    /// Each variant has a different (and, for `pre_agreed`, zero) length, so an
    /// unrecognized code point cannot be skipped: parsing one fails with
    /// ``RFC_6066/TrustedAuthorities/Error/unknownIdentifierType(_:)``.
    public struct IdentifierType: RawRepresentable, Sendable, Hashable, Codable {
        public let rawValue: UInt8

        public init(rawValue: UInt8) {
            self.rawValue = rawValue
        }

        /// Creates an IdentifierType WITHOUT validation.
        init(__unchecked: Void, rawValue: UInt8) {
            self.rawValue = rawValue
        }
    }
}

extension RFC_6066.TrustedAuthority.IdentifierType: CustomStringConvertible {
    public var description: String {
        switch rawValue {
        case 0: return "pre_agreed"
        case 1: return "key_sha1_hash"
        case 2: return "x509_name"
        case 3: return "cert_sha1_hash"
        default: return "identifier_type(\(rawValue))"
        }
    }
}

extension RFC_6066.TrustedAuthority.IdentifierType {

    /// pre_agreed (0) — no identifier is supplied; the CA is known out of band.
    public static let preAgreed = Self(__unchecked: (), rawValue: 0)

    /// key_sha1_hash (1) — SHA-1 hash of the CA's `SubjectPublicKeyInfo`.
    public static let keySHA1Hash = Self(__unchecked: (), rawValue: 1)

    /// x509_name (2) — the CA's DER-encoded X.509 `DistinguishedName`.
    public static let x509Name = Self(__unchecked: (), rawValue: 2)

    /// cert_sha1_hash (3) — SHA-1 hash of the CA's DER certificate.
    public static let certSHA1Hash = Self(__unchecked: (), rawValue: 3)
}
