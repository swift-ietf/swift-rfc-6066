public import Binary

extension IETF.RFC.`6066` {
    /// A single `ServerName` entry of the `server_name` extension.
    ///
    /// ## Wire Format
    ///
    /// ```
    /// struct {
    ///     NameType name_type;
    ///     select (name_type) {
    ///         case host_name: HostName;
    ///     } name;
    /// } ServerName;
    /// ```
    ///
    /// `host_name(0)` is the only registered ``NameType``, so the variant
    /// collapses to a single stored ``Host/Name``; ``nameType`` reports the wire
    /// discriminator. Parsing an entry whose `name_type` is not `host_name`
    /// fails with ``Error/unknownNameType(_:)`` — the RFC defines no generic
    /// length prefix for other variants, so the bytes after an unknown
    /// discriminator cannot be skipped.
    public struct ServerName: Sendable, Hashable {
        /// The server name (an ASCII DNS hostname).
        public let hostName: Host.Name

        /// Creates a `host_name` server name entry.
        public init(hostName: Host.Name) {
            self.hostName = hostName
        }
    }
}

extension IETF.RFC.`6066`.ServerName {
    /// The wire discriminator for this entry — always `host_name(0)`.
    public var nameType: NameType { .hostName }
}

extension IETF.RFC.`6066`.ServerName: Binary.Serializable {
    /// Serializes `name_type` (1 byte) followed by the `HostName` vector.
    public static func serialize<Buffer: RangeReplaceableCollection>(
        _ serverName: Self,
        into buffer: inout Buffer
    ) where Buffer.Element == Byte {
        buffer.append(Byte(serverName.nameType.rawValue))
        IETF.RFC.`6066`.Host.Name.serialize(serverName.hostName, into: &buffer)
    }

    /// Parses exactly one `ServerName` structure.
    public init<Bytes: Swift::Collection>(binary bytes: Bytes) throws(Error)
    where Bytes.Element == Byte {
        var reader = IETF.RFC.`6066`.Wire.Reader(Array(bytes))
        let fields: (nameType: UInt8, name: [Byte])
        do {
            fields = try reader.serverNameFields()
            try reader.expectEnd()
        } catch {
            switch error {
            case .trailingData(let remaining): throw .trailingData(remaining)
            case .truncated, .lengthOverflow: throw .truncated
            }
        }
        try self.init(nameType: fields.nameType, name: fields.name)
    }

    /// Builds an entry from its parsed wire fields, validating the discriminator.
    init(nameType: UInt8, name: [Byte]) throws(Error) {
        guard nameType == IETF.RFC.`6066`.ServerName.NameType.hostName.rawValue else {
            throw .unknownNameType(nameType)
        }
        let hostName: IETF.RFC.`6066`.Host.Name
        do {
            hostName = try IETF.RFC.`6066`.Host.Name(rawValue: name)
        } catch {
            throw .invalidHostName(error)
        }
        self.init(hostName: hostName)
    }
}

extension IETF.RFC.`6066`.Wire.Reader {
    /// Reads the raw fields of one `ServerName` from the cursor: the `name_type`
    /// discriminator and the `uint16`-length-prefixed `name` body.
    ///
    /// Discriminator validation is the caller's job — the reader deals only in
    /// presentation-language forms.
    mutating func serverNameFields() throws(IETF.RFC.`6066`.Wire.Error) -> (nameType: UInt8, name: [Byte]) {
        let nameType = try byte()
        let name = try vector16()
        return (nameType, name)
    }
}
