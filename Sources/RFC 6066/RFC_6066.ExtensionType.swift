public import RFC_8446

extension RFC_8446.Extension.ExtensionType {
    /// client_certificate_url (2) — RFC 6066 Section 5.
    ///
    /// Not carried forward by TLS 1.3 (RFC 8446 Section 4.2).
    public static let clientCertificateURL = Self(rawValue: 2)

    /// trusted_ca_keys (3) — RFC 6066 Section 6.
    ///
    /// Not carried forward by TLS 1.3 (RFC 8446 Section 4.2).
    public static let trustedCAKeys = Self(rawValue: 3)

    /// truncated_hmac (4) — RFC 6066 Section 7.
    ///
    /// Not carried forward by TLS 1.3 (RFC 8446 Section 4.2).
    public static let truncatedHMAC = Self(rawValue: 4)
}
