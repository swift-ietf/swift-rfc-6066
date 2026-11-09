public import Binary
public import RFC_8446

extension RFC_6066 {
    /// `trusted_ca_keys` extension payload (`extension_data` body).
    ///
    /// ## Wire Format
    ///
    /// ```
    /// struct {
    ///     TrustedAuthority trusted_authorities_list<0..2^16-1>;
    /// } TrustedAuthorities;
    /// ```
    ///
    /// The list is bounded `<0..2^16-1>` — it may legitimately be empty.
    ///
    /// ## Direction
    ///
    /// The **client** sends this body. The **server**'s response is an empty
    /// `trusted_ca_keys` extension body (RFC 6066 Section 6: "The 'extension_data'
    /// field of this extension SHALL be empty"), which is an
    /// ``RFC_8446/Extension/Data`` with `type: .trustedCAKeys` and no data — no
    /// payload type is needed to build it.
    ///
    /// ## TLS 1.3
    ///
    /// TLS 1.3 does not carry `trusted_ca_keys` (RFC 8446 Section 4.2); the
    /// `certificate_authorities` extension (RFC 8446 Section 4.2.4) covers the
    /// same ground. The type is defined here for TLS 1.2 peers and specification
    /// completeness.
    public struct TrustedAuthorities: Sendable, Hashable {
        /// The CAs the client trusts (may be empty).
        public let trustedAuthoritiesList: [TrustedAuthority]

        /// Creates a `trusted_ca_keys` payload WITHOUT validation.
        init(__unchecked: Void, trustedAuthoritiesList: [TrustedAuthority]) {
            self.trustedAuthoritiesList = trustedAuthoritiesList
        }
    }
}

extension RFC_6066.TrustedAuthorities {
    /// Creates an empty `trusted_ca_keys` payload.
    public init() {
        self.init(__unchecked: (), trustedAuthoritiesList: [])
    }

    /// Creates a `trusted_ca_keys` payload.
    ///
    /// - Parameter trustedAuthoritiesList: The CAs the client trusts.
    /// - Throws: ``Error/listTooLong(_:)`` if the encoded list exceeds
    ///   65535 bytes.
    public init(trustedAuthoritiesList: [RFC_6066.TrustedAuthority]) throws(Error) {
        let length = trustedAuthoritiesList.reduce(0) { $0 + $1.encodedLength }
        guard length <= 65535 else {
            throw Error.listTooLong(length)
        }
        self.init(__unchecked: (), trustedAuthoritiesList: trustedAuthoritiesList)
    }
}

extension RFC_6066.TrustedAuthorities {
    /// The extension type for this payload (`trusted_ca_keys`).
    public static let extensionType: RFC_8446.Extension.ExtensionType = .trustedCAKeys

    /// Wraps this payload in a generic ``RFC_8446/Extension/Data`` envelope.
    ///
    /// - Throws: ``RFC_8446/Extension/Data/Error`` if the body exceeds the
    ///   envelope's 65535-byte limit.
    public var extensionData: RFC_8446.Extension.Data {
        get throws(RFC_8446.Extension.Data.Error) {
            try RFC_8446.Extension.Data(type: Self.extensionType, data: self.bytes)
        }
    }
}

extension RFC_6066.TrustedAuthorities: Binary.Serializable {
    public static func serialize<Buffer: RangeReplaceableCollection>(
        _ value: Self,
        into buffer: inout Buffer
    ) where Buffer.Element == Byte {
        var block: [Byte] = []
        for authority in value.trustedAuthoritiesList {
            RFC_6066.TrustedAuthority.serialize(authority, into: &block)
        }
        RFC_6066.Wire.appendVector16(block, into: &buffer)
    }

    /// Parses a `trusted_ca_keys` `extension_data` body (the client form).
    public init<Bytes: Swift::Collection>(binary bytes: Bytes) throws(Error)
    where Bytes.Element == Byte {
        var reader = RFC_6066.Wire.Reader(Array(bytes))
        let block: [Byte]
        do {
            block = try reader.vector16()
            try reader.expectEnd()
        } catch {
            switch error {
            case .trailingData(let remaining): throw .trailingData(remaining)
            case .truncated, .lengthOverflow: throw .truncated
            }
        }

        var sub = RFC_6066.Wire.Reader(block)
        var authorities: [RFC_6066.TrustedAuthority] = []
        while !sub.isAtEnd {
            let rawType: UInt8
            do {
                rawType = try sub.byte()
            } catch {
                throw .truncated
            }

            switch rawType {
            case RFC_6066.TrustedAuthority.IdentifierType.preAgreed.rawValue:
                authorities.append(.preAgreed)

            case RFC_6066.TrustedAuthority.IdentifierType.keySHA1Hash.rawValue:
                let hash: [Byte]
                do {
                    hash = try sub.take(20)
                } catch {
                    throw .truncated
                }
                authorities.append(.keySHA1Hash(RFC_6066.SHA1Hash(__unchecked: (), rawValue: hash)))

            case RFC_6066.TrustedAuthority.IdentifierType.x509Name.rawValue:
                let distinguishedName: [Byte]
                do {
                    distinguishedName = try sub.vector16()
                } catch {
                    throw .truncated
                }
                do {
                    authorities.append(.x509Name(try RFC_6066.TrustedAuthority.DistinguishedName(rawValue: distinguishedName)))
                } catch {
                    throw .invalidDistinguishedName(error)
                }

            case RFC_6066.TrustedAuthority.IdentifierType.certSHA1Hash.rawValue:
                let hash: [Byte]
                do {
                    hash = try sub.take(20)
                } catch {
                    throw .truncated
                }
                authorities.append(.certSHA1Hash(RFC_6066.SHA1Hash(__unchecked: (), rawValue: hash)))

            default:
                throw .unknownIdentifierType(rawType)
            }
        }
        try self.init(trustedAuthoritiesList: authorities)
    }
}
