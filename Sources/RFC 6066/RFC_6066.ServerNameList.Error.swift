extension RFC_6066.ServerNameList {
    /// Errors raised when creating or parsing a `server_name` payload.
    public enum Error: Swift.Error, Sendable, Equatable {
        /// `server_name_list` is bounded `<1..2^16-1>`; it cannot be empty.
        ///
        /// The server's empty *response* body is a different structure —
        /// ``RFC_6066/ServerNameList/Acknowledgement``.
        case empty

        /// RFC 6066 Section 3: "The ServerNameList MUST NOT contain more than one
        /// name of the same name_type."
        case duplicateNameType(_ nameType: RFC_6066.ServerName.NameType)

        /// `server_name_list` is bounded `<1..2^16-1>`; its encoding cannot
        /// exceed 65535 bytes.
        case listTooLong(_ length: Int)

        /// An entry carried a `name_type` other than `host_name(0)`, which has no
        /// parseable length.
        case unknownNameType(_ rawValue: UInt8)

        /// An entry's `host_name` failed ``RFC_6066/HostName`` validation.
        case invalidHostName(_ error: RFC_6066.HostName.Error)

        /// The input ended before the list was complete.
        case truncated

        /// Bytes remained after the list.
        case trailingData(_ remaining: Int)
    }
}

extension RFC_6066.ServerNameList.Error: CustomStringConvertible {
    public var description: String {
        switch self {
        case .empty:
            return "TLS server_name list requires at least one name"
        case .duplicateNameType(let nameType):
            return "TLS server_name list has more than one name of type \(nameType)"
        case .listTooLong(let length):
            return "TLS server_name list too long: \(length) bytes (max 65535)"
        case .unknownNameType(let rawValue):
            return "TLS server_name list has unknown name_type \(rawValue) (only host_name(0) is defined)"
        case .invalidHostName(let error):
            return "TLS server_name list has invalid host_name: \(error)"
        case .truncated:
            return "TLS server_name list truncated"
        case .trailingData(let remaining):
            return "TLS server_name list has \(remaining) trailing bytes"
        }
    }
}
