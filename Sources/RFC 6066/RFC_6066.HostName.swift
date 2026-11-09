public import Binary

extension RFC_6066 {
    /// `HostName` — the fully qualified DNS hostname of the server.
    ///
    /// ## Wire Format
    ///
    /// ```
    /// opaque HostName<1..2^16-1>;
    /// ```
    ///
    /// ## Constraints (RFC 6066 Section 3)
    ///
    /// > "HostName" contains the fully qualified DNS hostname of the server, as
    /// > understood by the client. The hostname is represented as a byte string
    /// > using ASCII encoding without a trailing dot.
    ///
    /// > Literal IPv4 and IPv6 addresses are not permitted in "HostName".
    ///
    /// Enforced here: non-empty, at most `2^16-1` bytes, ASCII-only, and no
    /// trailing dot. The literal-IP prohibition is **not** enforced — deciding
    /// whether a byte string is an IP literal is an address-parsing question
    /// that belongs to the caller (RFC 791 / RFC 4291), not to this type.
    ///
    /// The bytes are carried opaquely: internationalized names must already be
    /// A-label (Punycode, RFC 5890) encoded by the caller.
    public struct HostName: Sendable, Hashable {
        /// The hostname bytes (opaque byte-domain — ASCII per RFC 6066).
        public let rawValue: [Byte]

        /// Creates a hostname WITHOUT validation.
        init(__unchecked: Void, rawValue: [Byte]) {
            self.rawValue = rawValue
        }

        /// Creates a hostname with validation.
        ///
        /// - Parameter rawValue: The hostname bytes (1...65535 ASCII bytes,
        ///   without a trailing dot).
        /// - Throws: ``Error`` if validation fails.
        public init(rawValue: [Byte]) throws(Error) {
            guard !rawValue.isEmpty else {
                throw Error.empty
            }
            guard rawValue.count <= 65535 else {
                throw Error.tooLong(rawValue.count)
            }
            guard !rawValue.contains(where: { $0.bitPattern > 0x7F }) else {
                throw Error.nonASCII
            }
            guard rawValue.last != Byte(0x2E) else {
                throw Error.trailingDot
            }
            self.init(__unchecked: (), rawValue: rawValue)
        }

        /// Creates a hostname from a string.
        ///
        /// - Parameter string: The hostname (e.g. `"example.com"`).
        /// - Throws: ``Error`` if validation fails.
        public init(_ string: some StringProtocol) throws(Error) {
            try self.init(rawValue: string.utf8.map(Byte.init(bitPattern:)))
        }
    }
}

extension RFC_6066.HostName {
    /// The number of bytes this hostname occupies on the wire: the `uint16`
    /// length prefix and the bytes.
    var encodedLength: Int {
        2 + rawValue.count
    }
}

extension RFC_6066.HostName: Binary.Serializable {
    /// Serializes the hostname as the `opaque HostName<1..2^16-1>` vector
    /// (`uint16` length prefix + the ASCII bytes).
    public static func serialize<Buffer: RangeReplaceableCollection>(
        _ hostName: Self,
        into buffer: inout Buffer
    ) where Buffer.Element == Byte {
        RFC_6066.Wire.appendVector16(hostName.rawValue, into: &buffer)
    }

    /// Parses an `opaque HostName<1..2^16-1>` vector.
    public init<Bytes: Swift::Collection>(binary bytes: Bytes) throws(Error)
    where Bytes.Element == Byte {
        var reader = RFC_6066.Wire.Reader(Array(bytes))
        let raw: [Byte]
        do {
            raw = try reader.vector16()
            try reader.expectEnd()
        } catch {
            switch error {
            case .trailingData(let remaining): throw .trailingData(remaining)
            case .truncated, .lengthOverflow: throw .truncated
            }
        }
        try self.init(rawValue: raw)
    }
}

extension RFC_6066.HostName: CustomStringConvertible {
    public var description: String {
        String(decoding: rawValue, as: UTF8.self)
    }
}
