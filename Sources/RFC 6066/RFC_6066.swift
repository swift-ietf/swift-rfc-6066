/// RFC 6066: TLS Extension Definitions
///
/// This namespace contains the typed `extension_data` payloads defined by
/// RFC 6066 from January 2011. The generic extension envelope (the
/// `extension_type` + `uint16`-length `extension_data` framing) belongs to
/// ``RFC_8446/Extension/Data``; the types here model the *bodies* that ride
/// inside it.
///
/// ## Key Types
///
/// - ``ServerNameList``: the `server_name` (SNI) payload — the client's list of
///   names, plus ``ServerNameList/Acknowledgement`` for the server's empty
///   response body.
/// - ``MaxFragmentLength``: the `max_fragment_length` payload.
/// - ``CertificateStatusRequest``: the `status_request` (OCSP) request payload.
/// - ``CertificateStatus``: the OCSP response structure — the TLS 1.2
///   `CertificateStatus` handshake message, and the TLS 1.3 `status_request`
///   response body (RFC 8446 Section 4.4.2.1).
/// - ``TruncatedHMAC``: the (empty) `truncated_hmac` payload.
/// - ``ClientCertificateURL`` / ``CertificateURL``: the (empty)
///   `client_certificate_url` payload and its `CertificateURL` handshake message.
/// - ``TrustedAuthorities``: the `trusted_ca_keys` payload.
///
/// ## TLS 1.3 Status
///
/// RFC 8446 (TLS 1.3) Section 4.2 carries `server_name` and `status_request`
/// forward. It does **not** carry `max_fragment_length` (superseded by
/// RFC 8449 `record_size_limit`), `client_certificate_url`, `trusted_ca_keys`,
/// or `truncated_hmac` — those remain defined here for TLS 1.2 peers and for
/// completeness of the specification.
///
/// ## Serialization Convention
///
/// Every payload type serializes its **body only** (the `extension_data`
/// contents), never the `extension_type` + length envelope. Use the
/// `extensionData` accessor to lift a body into an
/// ``RFC_8446/Extension/Data`` envelope with the correct
/// ``RFC_8446/Extension/ExtensionType``.
///
/// ## Example
///
/// ```swift
/// // Client: offer SNI for "example.com".
/// let sni = try RFC_6066.ServerNameList(hostName: RFC_6066.HostName("example.com"))
/// let extensionData = try sni.extensionData   // RFC_8446.Extension.Data(type: .serverName, …)
///
/// // Server: acknowledge in EncryptedExtensions with an empty body.
/// let ack = RFC_6066.ServerNameList.Acknowledgement().extensionData
/// ```
///
/// ## See Also
///
/// - [RFC 6066](https://www.rfc-editor.org/rfc/rfc6066)
/// - ``RFC_8446`` for TLS 1.3
public enum RFC_6066 {}
