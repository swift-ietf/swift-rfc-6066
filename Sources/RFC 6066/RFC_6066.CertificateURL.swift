public import Binary

extension RFC_6066 {
    /// The `CertificateURL` handshake message body (handshake type 21).
    ///
    /// ## Wire Format
    ///
    /// ```
    /// struct {
    ///     CertChainType type;
    ///     URLAndHash url_and_hash_list<1..2^16-1>;
    /// } CertificateURL;
    /// ```
    ///
    /// Sent by a client that negotiated ``RFC_6066/ClientCertificateURL`` in
    /// place of its Certificate message: the certificates live at the URLs, and
    /// each is pinned by a SHA-1 hash.
    ///
    /// ## Not an Extension
    ///
    /// Unlike the other types in this package this is a **handshake message
    /// body**, not an `extension_data` payload — it has no `extensionData`
    /// accessor. The handshake framing (msg_type + `uint24` length) belongs to
    /// the TLS version in play (RFC 5246 Section 7.4 for TLS 1.2); this type
    /// models only the body.
    ///
    /// ## TLS 1.3
    ///
    /// TLS 1.3 does not carry `client_certificate_url` (RFC 8446 Section 4.2),
    /// so this message never appears in a TLS 1.3 handshake. It is defined here
    /// for TLS 1.2 peers and specification completeness.
    public struct CertificateURL: Sendable, Hashable {
        /// How the objects at the URLs are packaged.
        public let type: CertChainType

        /// The URLs and their SHA-1 hashes (at least one).
        public let urlAndHashList: [URLAndHash]

        /// Creates a `CertificateURL` body WITHOUT validation.
        init(__unchecked: Void, type: CertChainType, urlAndHashList: [URLAndHash]) {
            self.type = type
            self.urlAndHashList = urlAndHashList
        }

        /// Creates a `CertificateURL` body.
        ///
        /// - Parameters:
        ///   - type: How the objects at the URLs are packaged.
        ///   - urlAndHashList: The URLs and hashes (`<1..2^16-1>` — at least one).
        /// - Throws: ``Error/emptyList`` if `urlAndHashList` is empty.
        public init(type: CertChainType, urlAndHashList: [URLAndHash]) throws(Error) {
            guard !urlAndHashList.isEmpty else {
                throw Error.emptyList
            }
            self.init(__unchecked: (), type: type, urlAndHashList: urlAndHashList)
        }
    }
}

extension RFC_6066.CertificateURL: Binary.Serializable {
    public static func serialize<Buffer: RangeReplaceableCollection>(
        _ value: Self,
        into buffer: inout Buffer
    ) where Buffer.Element == Byte {
        buffer.append(Byte(value.type.rawValue))
        var block: [Byte] = []
        for urlAndHash in value.urlAndHashList {
            URLAndHash.serialize(urlAndHash, into: &block)
        }
        RFC_6066.Wire.appendVector16(block, into: &buffer)
    }

    /// Parses a `CertificateURL` handshake message body.
    public init<Bytes: Swift::Collection>(binary bytes: Bytes) throws(Error)
    where Bytes.Element == Byte {
        var reader = RFC_6066.Wire.Reader(Array(bytes))

        let rawType: UInt8
        let block: [Byte]
        do {
            rawType = try reader.byte()
            block = try reader.vector16()
            try reader.expectEnd()
        } catch {
            switch error {
            case .trailingData(let remaining): throw .trailingData(remaining)
            case .truncated, .lengthOverflow: throw .truncated
            }
        }

        var sub = RFC_6066.Wire.Reader(block)
        var urlAndHashList: [URLAndHash] = []
        while !sub.isAtEnd {
            let fields: (url: [Byte], padding: UInt8, sha1Hash: [Byte])
            do {
                fields = try sub.urlAndHashFields()
            } catch {
                switch error {
                case .trailingData(let remaining): throw .trailingData(remaining)
                case .truncated, .lengthOverflow: throw .truncated
                }
            }
            guard fields.padding == URLAndHash.padding.bitPattern else {
                throw .invalidPadding(fields.padding)
            }
            let hash = RFC_6066.SHA1Hash(__unchecked: (), rawValue: fields.sha1Hash)
            do {
                urlAndHashList.append(try URLAndHash(url: fields.url, sha1Hash: hash))
            } catch {
                throw .invalidURLAndHash(error)
            }
        }

        try self.init(
            type: RFC_6066.CertificateURL.CertChainType(rawValue: rawType),
            urlAndHashList: urlAndHashList
        )
    }
}
