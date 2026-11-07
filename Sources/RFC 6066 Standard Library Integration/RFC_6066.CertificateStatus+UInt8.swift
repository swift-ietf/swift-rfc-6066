internal import Byte
public import RFC_6066

extension RFC_6066.CertificateStatus {
    /// Stdlib-interop forwarder: construction from a `[UInt8]` OCSP response.
    @_disfavoredOverload
    public init(response: [UInt8]) throws(Error) {
        try self.init(response: response.map(Byte.init(bitPattern:)))
    }
}
