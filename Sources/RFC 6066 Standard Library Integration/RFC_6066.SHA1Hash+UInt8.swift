internal import Byte
public import RFC_6066

extension RFC_6066.SHA1Hash {
    /// Stdlib-interop forwarder: construction from `[UInt8]` rawValue.
    @_disfavoredOverload
    public init(rawValue: [UInt8]) throws(Error) {
        try self.init(rawValue: rawValue.map(Byte.init(bitPattern:)))
    }
}
