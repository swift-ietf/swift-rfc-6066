extension RFC_6066.CertificateURL {
    /// `CertChainType`, how the certificates at the URLs are packaged.
    ///
    /// ```
    /// enum {
    ///     individual_certs(0), pkipath(1), (255)
    /// } CertChainType;
    /// ```
    ///
    /// Unlike `NameType` or `CertificateStatusType`, this discriminator does not
    /// select a variant structure — the `url_and_hash_list` follows it either way
    /// — so an unrecognized code point stays representable and round-trips.
    public struct CertChainType: RawRepresentable, Sendable, Hashable, Codable {
        public let rawValue: UInt8

        public init(rawValue: UInt8) {
            self.rawValue = rawValue
        }

        /// Creates a CertChainType WITHOUT validation.
        init(__unchecked: Void, rawValue: UInt8) {
            self.rawValue = rawValue
        }

        /// individual_certs (0) — each URL refers to a single DER certificate.
        public static let individualCerts = Self(__unchecked: (), rawValue: 0)

        /// pkipath (1) — a single URL refers to a DER PkiPath certificate chain.
        public static let pkipath = Self(__unchecked: (), rawValue: 1)
    }
}

extension RFC_6066.CertificateURL.CertChainType: CustomStringConvertible {
    public var description: String {
        switch rawValue {
        case 0: return "individual_certs"
        case 1: return "pkipath"
        default: return "cert_chain_type(\(rawValue))"
        }
    }
}
