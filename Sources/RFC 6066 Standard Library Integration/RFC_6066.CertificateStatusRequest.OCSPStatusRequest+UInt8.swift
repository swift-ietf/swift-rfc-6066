internal import Byte
public import RFC_6066

extension RFC_6066.CertificateStatusRequest.OCSPStatusRequest {
    /// Stdlib-interop forwarder: construction from `[UInt8]` DER.
    @_disfavoredOverload
    public init(responderIDList: [[UInt8]], requestExtensions: [UInt8]) throws(Error) {
        try self.init(
            responderIDList: responderIDList.map { $0.map(Byte.init(bitPattern:)) },
            requestExtensions: requestExtensions.map(Byte.init(bitPattern:))
        )
    }
}
