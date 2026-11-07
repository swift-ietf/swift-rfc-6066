extension RFC_6066.ServerNameList.Acknowledgement {
    /// Errors raised when parsing the server's `server_name` response body.
    public enum Error: Swift.Error, Sendable, Equatable {
        /// The body was not empty, as RFC 6066 Section 3 requires it to be.
        case trailingData(_ remaining: Int)
    }
}

extension RFC_6066.ServerNameList.Acknowledgement.Error: CustomStringConvertible {
    public var description: String {
        switch self {
        case .trailingData(let remaining):
            return "TLS server_name server response must be empty, found \(remaining) bytes"
        }
    }
}
