extension RFC_6066.SHA1Hash {
    /// Errors raised when creating a `SHA1Hash`.
    public enum Error: Swift.Error, Sendable, Equatable {
        /// `SHA1Hash[20]` is a fixed-width 20-byte vector.
        case invalidLength(_ length: Int)
    }
}

extension RFC_6066.SHA1Hash.Error: CustomStringConvertible {
    public var description: String {
        switch self {
        case .invalidLength(let length):
            return "TLS SHA1Hash must be exactly 20 bytes, found \(length)"
        }
    }
}
