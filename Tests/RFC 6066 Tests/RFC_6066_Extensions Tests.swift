// ===----------------------------------------------------------------------===//
//
// Copyright (c) 2025 Coen ten Thije Boonkkamp
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of project contributors
//
// SPDX-License-Identifier: Apache-2.0
//
// ===----------------------------------------------------------------------===//

import Binary
import RFC_8446
import Testing

@testable import RFC_6066

enum `RFC_6066_Extensions Tests` {}

extension `RFC_6066_Extensions Tests` {
    @Suite
    struct `RFC 6066 extension payloads` {

        @Suite
        struct `ExtensionType registry` {
            @Test
            func `RFC 6066 code points`() {
                // The three RFC 6066 code points TLS 1.3 does not carry are declared
                // by this package; server_name(0), max_fragment_length(1) and
                // status_request(5) already live in RFC 8446's registry.
                #expect(IETF.RFC.`8446`.Extension.ExtensionType.serverName.rawValue == 0)
                #expect(IETF.RFC.`8446`.Extension.ExtensionType.maxFragmentLength.rawValue == 1)
                #expect(IETF.RFC.`8446`.Extension.ExtensionType.clientCertificateURL.rawValue == 2)
                #expect(IETF.RFC.`8446`.Extension.ExtensionType.trustedCAKeys.rawValue == 3)
                #expect(IETF.RFC.`8446`.Extension.ExtensionType.truncatedHMAC.rawValue == 4)
                #expect(IETF.RFC.`8446`.Extension.ExtensionType.statusRequest.rawValue == 5)
            }

            @Test
            func `RFC 6066 §9 alerts`() {
                // 112 and 113 are TLS 1.3 alerts and live in RFC 8446's registry;
                // 114 is RFC 6066-only and is added by this package.
                #expect(IETF.RFC.`8446`.Alert.Description.unrecognizedName.rawValue == 112)
                #expect(IETF.RFC.`8446`.Alert.Description.badCertificateStatusResponse.rawValue == 113)
                #expect(IETF.RFC.`8446`.Alert.Description.badCertificateHashValue.rawValue == 114)
            }
        }

        @Suite
        struct `max_fragment_length` {
            @Test
            func `Code points map to fragment lengths`() {
                #expect(IETF.RFC.`6066`.MaxFragmentLength.bytes512.rawValue == 1)
                #expect(IETF.RFC.`6066`.MaxFragmentLength.bytes1024.rawValue == 2)
                #expect(IETF.RFC.`6066`.MaxFragmentLength.bytes2048.rawValue == 3)
                #expect(IETF.RFC.`6066`.MaxFragmentLength.bytes4096.rawValue == 4)

                #expect(IETF.RFC.`6066`.MaxFragmentLength.bytes512.fragmentLength == 512)
                #expect(IETF.RFC.`6066`.MaxFragmentLength.bytes1024.fragmentLength == 1024)
                #expect(IETF.RFC.`6066`.MaxFragmentLength.bytes2048.fragmentLength == 2048)
                #expect(IETF.RFC.`6066`.MaxFragmentLength.bytes4096.fragmentLength == 4096)
            }

            @Test
            func `Serializes to a single byte`() {
                let expected: [Byte] = [Byte(0x02)]
                #expect(IETF.RFC.`6066`.MaxFragmentLength.bytes1024.bytes == expected)
            }

            @Test(arguments: IETF.RFC.`6066`.MaxFragmentLength.allCases)
            func `Round-trips`(value: IETF.RFC.`6066`.MaxFragmentLength) throws {
                #expect(try IETF.RFC.`6066`.MaxFragmentLength(binary: value.bytes) == value)
                #expect(value.extensionData.type == .maxFragmentLength)
            }

            @Test
            func `Rejects an illegal code point`() {
                // RFC 6066 §4 allows only 1...4; anything else is illegal_parameter.
                let bytes: [Byte] = [Byte(0x05)]
                #expect(throws: IETF.RFC.`6066`.MaxFragmentLength.Error.unknownLength(5)) {
                    try IETF.RFC.`6066`.MaxFragmentLength(binary: bytes)
                }
            }

            @Test
            func `Rejects trailing bytes`() {
                let bytes: [Byte] = [Byte(0x02), Byte(0x02)]
                #expect(throws: IETF.RFC.`6066`.MaxFragmentLength.Error.trailingData(1)) {
                    try IETF.RFC.`6066`.MaxFragmentLength(binary: bytes)
                }
            }
        }

        @Suite
        struct `status_request` {
            @Test
            func `Empty OCSP request serializes byte-for-byte`() throws {
                // status_type (ocsp=1) | responder_id_list length (0) | request_extensions length (0)
                let request = IETF.RFC.`6066`.CertificateStatusRequest()
                let expected: [Byte] = [Byte(0x01), Byte(0x00), Byte(0x00), Byte(0x00), Byte(0x00)]

                #expect(request.bytes == expected)
                #expect(request.statusType == .ocsp)
                #expect(try request.extensionData.type == .statusRequest)
            }

            @Test
            func `Populated OCSP request serializes byte-for-byte`() throws {
                let responderID: [Byte] = [Byte(0xAA), Byte(0xBB)]
                let requestExtensions: [Byte] = [Byte(0xCC)]
                let request = IETF.RFC.`6066`.CertificateStatusRequest(
                    request: try IETF.RFC.`6066`.CertificateStatusRequest.OCSPStatusRequest(
                        responderIDList: [responderID],
                        requestExtensions: requestExtensions
                    )
                )

                // status_type | responder_id_list<4> { ResponderID<2> AA BB } | Extensions<1> CC
                let expected: [Byte] = [Byte(0x01), Byte(0x00), Byte(0x04), Byte(0x00), Byte(0x02), Byte(0xAA), Byte(0xBB), Byte(0x00), Byte(0x01), Byte(0xCC)]
                #expect(request.bytes == expected)
            }

            @Test
            func `Round-trips`() throws {
                let request = IETF.RFC.`6066`.CertificateStatusRequest(
                    request: try IETF.RFC.`6066`.CertificateStatusRequest.OCSPStatusRequest(
                        responderIDList: [[Byte(0xAA), Byte(0xBB)], [Byte(0x01)]],
                        requestExtensions: [Byte(0xCC), Byte(0xDD)]
                    )
                )
                #expect(try IETF.RFC.`6066`.CertificateStatusRequest(binary: request.bytes) == request)
            }

            @Test
            func `Rejects an unsupported status_type`() {
                let bytes: [Byte] = [Byte(0x02), Byte(0x00), Byte(0x00), Byte(0x00), Byte(0x00)]
                #expect(throws: IETF.RFC.`6066`.CertificateStatusRequest.Error.unsupportedStatusType(2)) {
                    try IETF.RFC.`6066`.CertificateStatusRequest(binary: bytes)
                }
            }

            @Test
            func `Rejects a truncated request`() {
                let bytes: [Byte] = [Byte(0x01), Byte(0x00)]
                #expect(throws: IETF.RFC.`6066`.CertificateStatusRequest.Error.truncated) {
                    try IETF.RFC.`6066`.CertificateStatusRequest(binary: bytes)
                }
            }

            @Test
            func `Rejects an empty ResponderID on construction`() {
                #expect(throws: IETF.RFC.`6066`.CertificateStatusRequest.OCSPStatusRequest.Error.emptyResponderID) {
                    try IETF.RFC.`6066`.CertificateStatusRequest.OCSPStatusRequest(responderIDList: [[]])
                }
            }

            @Test
            func `Rejects an empty ResponderID when decoding`() {
                // status_type | responder_id_list<2> { ResponderID<0> } | Extensions<0>
                let bytes: [Byte] = [Byte(0x01), Byte(0x00), Byte(0x02), Byte(0x00), Byte(0x00), Byte(0x00), Byte(0x00)]
                #expect(
                    throws: IETF.RFC.`6066`.CertificateStatusRequest.Error.invalidRequest(.emptyResponderID)
                ) {
                    try IETF.RFC.`6066`.CertificateStatusRequest(binary: bytes)
                }
            }

            @Test
            func `ResponderID is bounded at 65535 bytes`() throws {
                #expect(throws: IETF.RFC.`6066`.CertificateStatusRequest.OCSPStatusRequest.Error.responderIDTooLong(65536)) {
                    try IETF.RFC.`6066`.CertificateStatusRequest.OCSPStatusRequest(
                        responderIDList: [Array(repeating: Byte(0xAA), count: 65536)]
                    )
                }
                #expect(throws: IETF.RFC.`6066`.CertificateStatusRequest.OCSPStatusRequest.Error.responderIDListTooLong(65537)) {
                    try IETF.RFC.`6066`.CertificateStatusRequest.OCSPStatusRequest(
                        responderIDList: [Array(repeating: Byte(0xAA), count: 65535)]
                    )
                }
                let largest = try IETF.RFC.`6066`.CertificateStatusRequest.OCSPStatusRequest(
                    responderIDList: [Array(repeating: Byte(0xAA), count: 65533)]
                )
                let request = IETF.RFC.`6066`.CertificateStatusRequest(request: largest)
                #expect(try IETF.RFC.`6066`.CertificateStatusRequest(binary: request.bytes) == request)
            }

            @Test
            func `Request extensions are bounded at 65535 bytes`() throws {
                #expect(throws: IETF.RFC.`6066`.CertificateStatusRequest.OCSPStatusRequest.Error.requestExtensionsTooLong(65536)) {
                    try IETF.RFC.`6066`.CertificateStatusRequest.OCSPStatusRequest(
                        responderIDList: [],
                        requestExtensions: Array(repeating: Byte(0xCC), count: 65536)
                    )
                }
                let largest = try IETF.RFC.`6066`.CertificateStatusRequest.OCSPStatusRequest(
                    responderIDList: [],
                    requestExtensions: Array(repeating: Byte(0xCC), count: 65535)
                )
                let request = IETF.RFC.`6066`.CertificateStatusRequest(request: largest)
                #expect(try IETF.RFC.`6066`.CertificateStatusRequest(binary: request.bytes) == request)
            }
        }

        @Suite
        struct `CertificateStatus` {
            @Test
            func `Serializes status_type and a uint24-prefixed OCSP response`() throws {
                let response: [Byte] = [Byte(0xDE), Byte(0xAD), Byte(0xBE), Byte(0xEF)]
                let status = try IETF.RFC.`6066`.CertificateStatus(response: response)

                let expected: [Byte] = [Byte(0x01), Byte(0x00), Byte(0x00), Byte(0x04), Byte(0xDE), Byte(0xAD), Byte(0xBE), Byte(0xEF)]
                #expect(status.bytes == expected)
                #expect(status.statusType == .ocsp)
            }

            @Test
            func `Round-trips`() throws {
                let response: [Byte] = [Byte(0xDE), Byte(0xAD), Byte(0xBE), Byte(0xEF)]
                let status = try IETF.RFC.`6066`.CertificateStatus(response: response)
                #expect(try IETF.RFC.`6066`.CertificateStatus(binary: status.bytes) == status)
            }

            @Test
            func `Wraps into the TLS 1.3 status_request extension`() throws {
                // RFC 8446 §4.4.2.1 carries this structure as the CertificateEntry's
                // status_request extension_data.
                let status = try IETF.RFC.`6066`.CertificateStatus(response: [Byte(0xDE), Byte(0xAD)])
                let ext = try status.extensionData

                #expect(ext.type == .statusRequest)
                #expect(ext.data == status.bytes)
            }

            @Test
            func `Rejects an empty response`() {
                let empty: [Byte] = []
                #expect(throws: IETF.RFC.`6066`.CertificateStatus.Error.emptyResponse) {
                    try IETF.RFC.`6066`.CertificateStatus(response: empty)
                }
            }

            @Test
            func `Rejects an unsupported status_type`() {
                let bytes: [Byte] = [Byte(0x02), Byte(0x00), Byte(0x00), Byte(0x01), Byte(0xFF)]
                #expect(throws: IETF.RFC.`6066`.CertificateStatus.Error.unsupportedStatusType(2)) {
                    try IETF.RFC.`6066`.CertificateStatus(binary: bytes)
                }
            }
        }

        @Suite
        struct `truncated_hmac` {
            @Test
            func `Serializes to an empty body`() {
                let value = IETF.RFC.`6066`.TruncatedHMAC()
                #expect(value.bytes.isEmpty)
                #expect(value.extensionData.type == .truncatedHMAC)
                #expect(value.extensionData.data.isEmpty)
            }

            @Test
            func `Round-trips`() throws {
                let value = IETF.RFC.`6066`.TruncatedHMAC()
                #expect(try IETF.RFC.`6066`.TruncatedHMAC(binary: value.bytes) == value)
            }

            @Test
            func `Rejects a non-empty body`() {
                let bytes: [Byte] = [Byte(0x00)]
                #expect(throws: IETF.RFC.`6066`.TruncatedHMAC.Error.trailingData(1)) {
                    try IETF.RFC.`6066`.TruncatedHMAC(binary: bytes)
                }
            }
        }

        @Suite
        struct `client_certificate_url` {
            @Test
            func `Serializes to an empty body`() {
                let value = IETF.RFC.`6066`.ClientCertificateURL()
                #expect(value.bytes.isEmpty)
                #expect(value.extensionData.type == .clientCertificateURL)
                #expect(value.extensionData.data.isEmpty)
            }

            @Test
            func `Round-trips`() throws {
                let value = IETF.RFC.`6066`.ClientCertificateURL()
                #expect(try IETF.RFC.`6066`.ClientCertificateURL(binary: value.bytes) == value)
            }

            @Test
            func `Rejects a non-empty body`() {
                let bytes: [Byte] = [Byte(0x00)]
                #expect(throws: IETF.RFC.`6066`.ClientCertificateURL.Error.trailingData(1)) {
                    try IETF.RFC.`6066`.ClientCertificateURL(binary: bytes)
                }
            }
        }

        @Suite
        struct `CertificateURL` {
            /// "http://x" — the URL used by the byte-exact vector.
            static let url: [Byte] = [Byte(0x68), Byte(0x74), Byte(0x74), Byte(0x70), Byte(0x3A), Byte(0x2F), Byte(0x2F), Byte(0x78)]

            /// A 20-byte SHA-1 digest stand-in.
            static let hash: [Byte] = Array(repeating: Byte(0xCD), count: 20)

            @Test
            func `Serializes cert chain type and the url_and_hash_list`() throws {
                let entry = try IETF.RFC.`6066`.CertificateURL.URLAndHash(
                    url: Self.url,
                    sha1Hash: try IETF.RFC.`6066`.SHA1Hash(rawValue: Self.hash)
                )
                let message = try IETF.RFC.`6066`.CertificateURL(
                    type: .individualCerts,
                    urlAndHashList: [entry]
                )

                // type (0) | list length (31) | url<8> | padding (0x01) | SHA1Hash[20]
                let expected: [Byte] =
                    [Byte(0x00), Byte(0x00), Byte(0x1F), Byte(0x00), Byte(0x08)] + Self.url + [Byte(0x01)] + Self.hash
                #expect(message.bytes == expected)
            }

            @Test
            func `Round-trips`() throws {
                let entry = try IETF.RFC.`6066`.CertificateURL.URLAndHash(
                    url: Self.url,
                    sha1Hash: try IETF.RFC.`6066`.SHA1Hash(rawValue: Self.hash)
                )
                let message = try IETF.RFC.`6066`.CertificateURL(type: .pkipath, urlAndHashList: [entry, entry])
                #expect(try IETF.RFC.`6066`.CertificateURL(binary: message.bytes) == message)
            }

            @Test
            func `Rejects an empty url_and_hash_list`() {
                #expect(throws: IETF.RFC.`6066`.CertificateURL.Error.emptyList) {
                    try IETF.RFC.`6066`.CertificateURL(type: .individualCerts, urlAndHashList: [])
                }
            }

            @Test
            func `Rejects a padding byte other than 0x01`() {
                // RFC 6066 §5: "The 'padding' byte MUST be 0x01."
                let bytes: [Byte] =
                    [Byte(0x00), Byte(0x00), Byte(0x1F), Byte(0x00), Byte(0x08)] + Self.url + [Byte(0x00)] + Self.hash
                #expect(throws: IETF.RFC.`6066`.CertificateURL.Error.invalidPadding(0)) {
                    try IETF.RFC.`6066`.CertificateURL(binary: bytes)
                }
            }

            @Test
            func `url_and_hash_list encoding is bounded at 65535 bytes`() throws {
                let hash = try IETF.RFC.`6066`.SHA1Hash(rawValue: Self.hash)
                let largest = try IETF.RFC.`6066`.CertificateURL.URLAndHash(
                    url: Array(repeating: Byte(0x61), count: 65512),
                    sha1Hash: hash
                )
                let message = try IETF.RFC.`6066`.CertificateURL(type: .individualCerts, urlAndHashList: [largest])
                #expect(message.bytes.count == 1 + 2 + 65535)
                #expect(try IETF.RFC.`6066`.CertificateURL(binary: message.bytes) == message)

                let tooLarge = try IETF.RFC.`6066`.CertificateURL.URLAndHash(
                    url: Array(repeating: Byte(0x61), count: 65513),
                    sha1Hash: hash
                )
                #expect(throws: IETF.RFC.`6066`.CertificateURL.Error.listTooLong(65536)) {
                    try IETF.RFC.`6066`.CertificateURL(type: .individualCerts, urlAndHashList: [tooLarge])
                }
            }

            @Test
            func `SHA1Hash requires exactly 20 bytes`() {
                let short: [Byte] = [Byte(0x01), Byte(0x02), Byte(0x03)]
                #expect(throws: IETF.RFC.`6066`.SHA1Hash.Error.invalidLength(3)) {
                    try IETF.RFC.`6066`.SHA1Hash(rawValue: short)
                }
            }
        }

        @Suite
        struct `trusted_ca_keys` {
            @Test
            func `Empty list serializes to a zero-length vector`() throws {
                let value = IETF.RFC.`6066`.TrustedAuthorities()
                let expected: [Byte] = [Byte(0x00), Byte(0x00)]

                #expect(value.bytes == expected)
                #expect(try value.extensionData.type == .trustedCAKeys)
            }

            @Test
            func `Serializes each identifier variant byte-for-byte`() throws {
                let distinguishedName = try IETF.RFC.`6066`.TrustedAuthority.DistinguishedName(
                    rawValue: [Byte(0x30), Byte(0x00)]
                )
                let value = try IETF.RFC.`6066`.TrustedAuthorities(
                    trustedAuthoritiesList: [.preAgreed, .x509Name(distinguishedName)]
                )

                // list length (6) | pre_agreed(0) | x509_name(2) | DN length (2) | 30 00
                let expected: [Byte] = [Byte(0x00), Byte(0x06), Byte(0x00), Byte(0x02), Byte(0x00), Byte(0x02), Byte(0x30), Byte(0x00)]
                #expect(value.bytes == expected)
            }

            @Test
            func `Round-trips every identifier type`() throws {
                let hash = try IETF.RFC.`6066`.SHA1Hash(rawValue: Array(repeating: Byte(0xAB), count: 20))
                let value = try IETF.RFC.`6066`.TrustedAuthorities(
                    trustedAuthoritiesList: [
                        .preAgreed,
                        .keySHA1Hash(hash),
                        .x509Name(
                            IETF.RFC.`6066`.TrustedAuthority.DistinguishedName(
                                rawValue: [Byte(0x30), Byte(0x03), Byte(0x02), Byte(0x01), Byte(0x00)]
                            )
                        ),
                        .certSHA1Hash(hash),
                    ]
                )
                #expect(try IETF.RFC.`6066`.TrustedAuthorities(binary: value.bytes) == value)

                #expect(value.trustedAuthoritiesList[0].identifierType == .preAgreed)
                #expect(value.trustedAuthoritiesList[1].identifierType == .keySHA1Hash)
                #expect(value.trustedAuthoritiesList[2].identifierType == .x509Name)
                #expect(value.trustedAuthoritiesList[3].identifierType == .certSHA1Hash)
            }

            @Test
            func `DistinguishedName is bounded 1...65535 bytes`() throws {
                #expect(throws: IETF.RFC.`6066`.TrustedAuthority.DistinguishedName.Error.empty) {
                    try IETF.RFC.`6066`.TrustedAuthority.DistinguishedName(rawValue: [])
                }
                #expect(throws: IETF.RFC.`6066`.TrustedAuthority.DistinguishedName.Error.tooLong(65536)) {
                    try IETF.RFC.`6066`.TrustedAuthority.DistinguishedName(rawValue: Array(repeating: Byte(0x30), count: 65536))
                }
                let largest = try IETF.RFC.`6066`.TrustedAuthority.DistinguishedName(
                    rawValue: Array(repeating: Byte(0x30), count: 65535)
                )
                let authority = IETF.RFC.`6066`.TrustedAuthority.x509Name(largest)
                #expect(authority.bytes.count == 1 + 2 + 65535)
            }

            @Test
            func `Rejects an empty x509_name when decoding`() {
                // list length (3) | x509_name(2) | DN length (0)
                let bytes: [Byte] = [Byte(0x00), Byte(0x03), Byte(0x02), Byte(0x00), Byte(0x00)]
                #expect(throws: IETF.RFC.`6066`.TrustedAuthorities.Error.invalidDistinguishedName(.empty)) {
                    try IETF.RFC.`6066`.TrustedAuthorities(binary: bytes)
                }
            }

            @Test
            func `List encoding is bounded at 65535 bytes`() throws {
                let largest = try IETF.RFC.`6066`.TrustedAuthority.DistinguishedName(
                    rawValue: Array(repeating: Byte(0x30), count: 65532)
                )
                let value = try IETF.RFC.`6066`.TrustedAuthorities(trustedAuthoritiesList: [.x509Name(largest)])
                #expect(value.bytes.count == 2 + 65535)
                #expect(try IETF.RFC.`6066`.TrustedAuthorities(binary: value.bytes) == value)

                let tooLarge = try IETF.RFC.`6066`.TrustedAuthority.DistinguishedName(
                    rawValue: Array(repeating: Byte(0x30), count: 65533)
                )
                #expect(throws: IETF.RFC.`6066`.TrustedAuthorities.Error.listTooLong(65536)) {
                    try IETF.RFC.`6066`.TrustedAuthorities(trustedAuthoritiesList: [.x509Name(tooLarge)])
                }
            }

            @Test
            func `Rejects an unknown identifier type`() {
                // list length (1) | identifier_type (4 — undefined)
                let bytes: [Byte] = [Byte(0x00), Byte(0x01), Byte(0x04)]
                #expect(throws: IETF.RFC.`6066`.TrustedAuthorities.Error.unknownIdentifierType(4)) {
                    try IETF.RFC.`6066`.TrustedAuthorities(binary: bytes)
                }
            }

            @Test
            func `Rejects a truncated hash`() {
                // list length (3) | key_sha1_hash(1) | only 2 of the 20 hash bytes
                let bytes: [Byte] = [Byte(0x00), Byte(0x03), Byte(0x01), Byte(0xAB), Byte(0xCD)]
                #expect(throws: IETF.RFC.`6066`.TrustedAuthorities.Error.truncated) {
                    try IETF.RFC.`6066`.TrustedAuthorities(binary: bytes)
                }
            }
        }
    }
}
