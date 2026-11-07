public import Binary
public import RFC_8446

extension RFC_6066 {
    /// `client_certificate_url` extension payload (`extension_data` body) —
    /// **empty**.
    ///
    /// RFC 6066 Section 5 defines no structure for the extension itself: "The
    /// 'extension_data' field of this extension SHALL be empty." Presence alone
    /// signals that the client may send a ``RFC_6066/CertificateURL`` handshake
    /// message in place of its Certificate message.
    ///
    /// ## TLS 1.3
    ///
    /// TLS 1.3 does not carry `client_certificate_url` (RFC 8446 Section 4.2).
    /// The type is defined here for TLS 1.2 peers and specification completeness.
    public struct ClientCertificateURL: Sendable, Hashable {
        /// Creates the empty `client_certificate_url` body.
        public init() {}

        /// The extension type for this payload (`client_certificate_url`).
        public static let extensionType: RFC_8446.Extension.ExtensionType = .clientCertificateURL

        /// Wraps this payload in a generic ``RFC_8446/Extension/Data`` envelope
        /// with an empty `extension_data`.
        public var extensionData: RFC_8446.Extension.Data {
            // swift-format-ignore: NeverUseForceTry
            // swiftlint:disable:next force_try
            try! RFC_8446.Extension.Data(type: Self.extensionType, data: [])
        }
    }
}

extension RFC_6066.ClientCertificateURL: Binary.Serializable {
    /// Appends nothing: the `client_certificate_url` body is empty.
    public static func serialize<Buffer: RangeReplaceableCollection>(
        _ value: Self,
        into buffer: inout Buffer
    ) where Buffer.Element == Byte {
    }

    /// Parses a `client_certificate_url` `extension_data` body, which must be empty.
    public init<Bytes: Swift::Collection>(binary bytes: Bytes) throws(Error)
    where Bytes.Element == Byte {
        guard bytes.isEmpty else {
            throw Error.trailingData(bytes.count)
        }
        self.init()
    }
}
