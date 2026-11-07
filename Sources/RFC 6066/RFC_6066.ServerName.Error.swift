extension RFC_6066.ServerName {
    /// Errors raised when parsing a `ServerName` entry.
    public enum Error: Swift.Error, Sendable, Equatable {
        /// The `name_type` discriminator is not `host_name(0)`, so the `name`
        /// variant has no known length and cannot be read.
        case unknownNameType(_ rawValue: UInt8)

        /// The `host_name` body failed ``RFC_6066/HostName`` validation.
        case invalidHostName(_ error: RFC_6066.HostName.Error)

        /// The input ended before the entry was complete.
        case truncated

        /// Bytes remained after the entry.
        case trailingData(_ remaining: Int)
    }
}

extension RFC_6066.ServerName.Error: CustomStringConvertible {
    public var description: String {
        switch self {
        case .unknownNameType(let rawValue):
            return "TLS server_name has unknown name_type \(rawValue) (only host_name(0) is defined)"
        case .invalidHostName(let error):
            return "TLS server_name has invalid host_name: \(error)"
        case .truncated:
            return "TLS server_name entry truncated"
        case .trailingData(let remaining):
            return "TLS server_name entry has \(remaining) trailing bytes"
        }
    }
}
