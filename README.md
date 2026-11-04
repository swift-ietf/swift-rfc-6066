# swift-rfc-6066

Use this package when you build or read the TLS extensions of RFC 6066, most often Server Name Indication, and need their exact bytes inside a TLS handshake. Start from `RFC_6066.ServerNameList` for the client's server name, or from `RFC_6066.MaxFragmentLength`, `RFC_6066.CertificateStatusRequest`, `RFC_6066.TrustedAuthorities` or `RFC_6066.CertificateURL` for the other extensions. Each one wraps into the extension envelope of swift-rfc-8446 through its `extensionData`.

## Laws

- Decoding accepts exactly one encoded value. Missing bytes and bytes left over are both refused.
- A host name is ASCII without a trailing dot. Encode an internationalized name to its A-label form first.
- A name type other than host name is refused when decoding a server name list, not skipped.
- The server's acknowledgement of a server name, `RFC_6066.TruncatedHMAC` and `RFC_6066.ClientCertificateURL` have empty bodies, and decoding refuses any byte.
- `RFC_6066.MaxFragmentLength` decodes only the codes 1 to 4, for 512, 1024, 2048 and 4096 bytes.
- `RFC_6066.CertificateStatusRequest` and `RFC_6066.CertificateStatus` support only OCSP. Any other status type is refused when decoding.
- A trusted authorities list may be empty. An unknown identifier type in it is refused when decoding.
- Every URL in a certificate URL message carries a SHA-1 hash of exactly 20 bytes. The padding byte before each hash must be 1.
