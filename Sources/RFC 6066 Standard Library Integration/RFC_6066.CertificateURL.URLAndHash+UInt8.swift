internal import Byte
public import RFC_6066

extension RFC_6066.CertificateURL.URLAndHash {
    /// Stdlib-interop forwarder: construction from a `[UInt8]` URL.
    @_disfavoredOverload
    public init(url: [UInt8], sha1Hash: RFC_6066.SHA1Hash) throws(Error) {
        try self.init(url: url.map(Byte.init(bitPattern:)), sha1Hash: sha1Hash)
    }
}
