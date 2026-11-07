public import RFC_8446

extension RFC_8446.Alert.Description {
    /// bad_certificate_hash_value (114) — RFC 6066 Section 9.
    ///
    /// Sent when the SHA-1 hash in a ``RFC_6066/CertificateURL`` entry does not
    /// match the certificate retrieved from the URL. Not carried forward by TLS
    /// 1.3 (RFC 8446 Section 6.2), which has no `client_certificate_url`.
    public static let badCertificateHashValue = Self(rawValue: 114)
}
