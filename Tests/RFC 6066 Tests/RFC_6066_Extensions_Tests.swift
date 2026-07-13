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

import Binary_Serializable_Primitives
import RFC_8446
import Testing

@testable import RFC_6066

@Suite("RFC 6066 extension payloads")
struct RFC_6066_Extensions_Tests {

    @Suite("ExtensionType registry")
    struct ExtensionTypeTests {
        @Test
        func `RFC 6066 code points`() {
            // The three RFC 6066 code points TLS 1.3 does not carry are declared
            // by this package; server_name(0), max_fragment_length(1) and
            // status_request(5) already live in RFC 8446's registry.
            #expect(RFC_8446.Extension.ExtensionType.serverName.rawValue == 0)
            #expect(RFC_8446.Extension.ExtensionType.maxFragmentLength.rawValue == 1)
            #expect(RFC_8446.Extension.ExtensionType.clientCertificateURL.rawValue == 2)
            #expect(RFC_8446.Extension.ExtensionType.trustedCAKeys.rawValue == 3)
            #expect(RFC_8446.Extension.ExtensionType.truncatedHMAC.rawValue == 4)
            #expect(RFC_8446.Extension.ExtensionType.statusRequest.rawValue == 5)
        }

        @Test
        func `RFC 6066 §9 alerts`() {
            // 112 and 113 are TLS 1.3 alerts and live in RFC 8446's registry;
            // 114 is RFC 6066-only and is added by this package.
            #expect(RFC_8446.Alert.Description.unrecognizedName.rawValue == 112)
            #expect(RFC_8446.Alert.Description.badCertificateStatusResponse.rawValue == 113)
            #expect(RFC_8446.Alert.Description.badCertificateHashValue.rawValue == 114)
        }
    }

    @Suite("max_fragment_length")
    struct MaxFragmentLengthTests {
        @Test
        func `Code points map to fragment lengths`() {
            #expect(RFC_6066.MaxFragmentLength.bytes512.rawValue == 1)
            #expect(RFC_6066.MaxFragmentLength.bytes1024.rawValue == 2)
            #expect(RFC_6066.MaxFragmentLength.bytes2048.rawValue == 3)
            #expect(RFC_6066.MaxFragmentLength.bytes4096.rawValue == 4)

            #expect(RFC_6066.MaxFragmentLength.bytes512.fragmentLength == 512)
            #expect(RFC_6066.MaxFragmentLength.bytes1024.fragmentLength == 1024)
            #expect(RFC_6066.MaxFragmentLength.bytes2048.fragmentLength == 2048)
            #expect(RFC_6066.MaxFragmentLength.bytes4096.fragmentLength == 4096)
        }

        @Test
        func `Serializes to a single byte`() {
            let expected: [Byte] = [0x02]
            #expect(RFC_6066.MaxFragmentLength.bytes1024.bytes == expected)
        }

        @Test(arguments: RFC_6066.MaxFragmentLength.allCases)
        func `Round-trips`(value: RFC_6066.MaxFragmentLength) throws {
            #expect(try RFC_6066.MaxFragmentLength(binary: value.bytes) == value)
            #expect(value.extensionData.type == .maxFragmentLength)
        }

        @Test
        func `Rejects an illegal code point`() {
            // RFC 6066 §4 allows only 1...4; anything else is illegal_parameter.
            let bytes: [Byte] = [0x05]
            #expect(throws: RFC_6066.MaxFragmentLength.Error.unknownLength(5)) {
                try RFC_6066.MaxFragmentLength(binary: bytes)
            }
        }

        @Test
        func `Rejects trailing bytes`() {
            let bytes: [Byte] = [0x02, 0x02]
            #expect(throws: RFC_6066.MaxFragmentLength.Error.trailingData(1)) {
                try RFC_6066.MaxFragmentLength(binary: bytes)
            }
        }
    }

    @Suite("status_request")
    struct StatusRequestTests {
        @Test
        func `Empty OCSP request serializes byte-for-byte`() {
            // status_type (ocsp=1) | responder_id_list length (0) | request_extensions length (0)
            let request = RFC_6066.CertificateStatusRequest()
            let expected: [Byte] = [0x01, 0x00, 0x00, 0x00, 0x00]

            #expect(request.bytes == expected)
            #expect(request.statusType == .ocsp)
            #expect(request.extensionData.type == .statusRequest)
        }

        @Test
        func `Populated OCSP request serializes byte-for-byte`() {
            let responderID: [Byte] = [0xAA, 0xBB]
            let requestExtensions: [Byte] = [0xCC]
            let request = RFC_6066.CertificateStatusRequest(
                request: RFC_6066.CertificateStatusRequest.OCSPStatusRequest(
                    responderIDList: [responderID],
                    requestExtensions: requestExtensions
                )
            )

            // status_type | responder_id_list<4> { ResponderID<2> AA BB } | Extensions<1> CC
            let expected: [Byte] = [0x01, 0x00, 0x04, 0x00, 0x02, 0xAA, 0xBB, 0x00, 0x01, 0xCC]
            #expect(request.bytes == expected)
        }

        @Test
        func `Round-trips`() throws {
            let request = RFC_6066.CertificateStatusRequest(
                request: RFC_6066.CertificateStatusRequest.OCSPStatusRequest(
                    responderIDList: [[0xAA, 0xBB], [0x01]],
                    requestExtensions: [0xCC, 0xDD]
                )
            )
            #expect(try RFC_6066.CertificateStatusRequest(binary: request.bytes) == request)
        }

        @Test
        func `Rejects an unsupported status_type`() {
            let bytes: [Byte] = [0x02, 0x00, 0x00, 0x00, 0x00]
            #expect(throws: RFC_6066.CertificateStatusRequest.Error.unsupportedStatusType(2)) {
                try RFC_6066.CertificateStatusRequest(binary: bytes)
            }
        }

        @Test
        func `Rejects a truncated request`() {
            let bytes: [Byte] = [0x01, 0x00]
            #expect(throws: RFC_6066.CertificateStatusRequest.Error.truncated) {
                try RFC_6066.CertificateStatusRequest(binary: bytes)
            }
        }
    }

    @Suite("CertificateStatus")
    struct CertificateStatusTests {
        @Test
        func `Serializes status_type and a uint24-prefixed OCSP response`() throws {
            let response: [Byte] = [0xDE, 0xAD, 0xBE, 0xEF]
            let status = try RFC_6066.CertificateStatus(response: response)

            let expected: [Byte] = [0x01, 0x00, 0x00, 0x04, 0xDE, 0xAD, 0xBE, 0xEF]
            #expect(status.bytes == expected)
            #expect(status.statusType == .ocsp)
        }

        @Test
        func `Round-trips`() throws {
            let response: [Byte] = [0xDE, 0xAD, 0xBE, 0xEF]
            let status = try RFC_6066.CertificateStatus(response: response)
            #expect(try RFC_6066.CertificateStatus(binary: status.bytes) == status)
        }

        @Test
        func `Wraps into the TLS 1.3 status_request extension`() throws {
            // RFC 8446 §4.4.2.1 carries this structure as the CertificateEntry's
            // status_request extension_data.
            let status = try RFC_6066.CertificateStatus(response: [0xDE, 0xAD])
            let ext = status.extensionData

            #expect(ext.type == .statusRequest)
            #expect(ext.data == status.bytes)
        }

        @Test
        func `Rejects an empty response`() {
            let empty: [Byte] = []
            #expect(throws: RFC_6066.CertificateStatus.Error.emptyResponse) {
                try RFC_6066.CertificateStatus(response: empty)
            }
        }

        @Test
        func `Rejects an unsupported status_type`() {
            let bytes: [Byte] = [0x02, 0x00, 0x00, 0x01, 0xFF]
            #expect(throws: RFC_6066.CertificateStatus.Error.unsupportedStatusType(2)) {
                try RFC_6066.CertificateStatus(binary: bytes)
            }
        }
    }

    @Suite("truncated_hmac")
    struct TruncatedHMACTests {
        @Test
        func `Serializes to an empty body`() {
            let value = RFC_6066.TruncatedHMAC()
            #expect(value.bytes.isEmpty)
            #expect(value.extensionData.type == .truncatedHMAC)
            #expect(value.extensionData.data.isEmpty)
        }

        @Test
        func `Round-trips`() throws {
            let value = RFC_6066.TruncatedHMAC()
            #expect(try RFC_6066.TruncatedHMAC(binary: value.bytes) == value)
        }

        @Test
        func `Rejects a non-empty body`() {
            let bytes: [Byte] = [0x00]
            #expect(throws: RFC_6066.TruncatedHMAC.Error.trailingData(1)) {
                try RFC_6066.TruncatedHMAC(binary: bytes)
            }
        }
    }

    @Suite("client_certificate_url")
    struct ClientCertificateURLTests {
        @Test
        func `Serializes to an empty body`() {
            let value = RFC_6066.ClientCertificateURL()
            #expect(value.bytes.isEmpty)
            #expect(value.extensionData.type == .clientCertificateURL)
            #expect(value.extensionData.data.isEmpty)
        }

        @Test
        func `Round-trips`() throws {
            let value = RFC_6066.ClientCertificateURL()
            #expect(try RFC_6066.ClientCertificateURL(binary: value.bytes) == value)
        }

        @Test
        func `Rejects a non-empty body`() {
            let bytes: [Byte] = [0x00]
            #expect(throws: RFC_6066.ClientCertificateURL.Error.trailingData(1)) {
                try RFC_6066.ClientCertificateURL(binary: bytes)
            }
        }
    }

    @Suite("CertificateURL")
    struct CertificateURLTests {
        /// "http://x" — the URL used by the byte-exact vector.
        static let url: [Byte] = [0x68, 0x74, 0x74, 0x70, 0x3A, 0x2F, 0x2F, 0x78]

        /// A 20-byte SHA-1 digest stand-in.
        static let hash: [Byte] = Array(repeating: Byte(0xCD), count: 20)

        @Test
        func `Serializes cert chain type and the url_and_hash_list`() throws {
            let entry = try RFC_6066.CertificateURL.URLAndHash(
                url: Self.url,
                sha1Hash: try RFC_6066.SHA1Hash(rawValue: Self.hash)
            )
            let message = try RFC_6066.CertificateURL(
                type: .individualCerts,
                urlAndHashList: [entry]
            )

            // type (0) | list length (31) | url<8> | padding (0x01) | SHA1Hash[20]
            let expected: [Byte] =
                [0x00, 0x00, 0x1F, 0x00, 0x08] + Self.url + [0x01] + Self.hash
            #expect(message.bytes == expected)
        }

        @Test
        func `Round-trips`() throws {
            let entry = try RFC_6066.CertificateURL.URLAndHash(
                url: Self.url,
                sha1Hash: try RFC_6066.SHA1Hash(rawValue: Self.hash)
            )
            let message = try RFC_6066.CertificateURL(type: .pkipath, urlAndHashList: [entry, entry])
            #expect(try RFC_6066.CertificateURL(binary: message.bytes) == message)
        }

        @Test
        func `Rejects an empty url_and_hash_list`() {
            #expect(throws: RFC_6066.CertificateURL.Error.emptyList) {
                try RFC_6066.CertificateURL(type: .individualCerts, urlAndHashList: [])
            }
        }

        @Test
        func `Rejects a padding byte other than 0x01`() {
            // RFC 6066 §5: "The 'padding' byte MUST be 0x01."
            let bytes: [Byte] =
                [0x00, 0x00, 0x1F, 0x00, 0x08] + Self.url + [0x00] + Self.hash
            #expect(throws: RFC_6066.CertificateURL.Error.invalidPadding(0)) {
                try RFC_6066.CertificateURL(binary: bytes)
            }
        }

        @Test
        func `SHA1Hash requires exactly 20 bytes`() {
            let short: [Byte] = [0x01, 0x02, 0x03]
            #expect(throws: RFC_6066.SHA1Hash.Error.invalidLength(3)) {
                try RFC_6066.SHA1Hash(rawValue: short)
            }
        }
    }

    @Suite("trusted_ca_keys")
    struct TrustedAuthoritiesTests {
        @Test
        func `Empty list serializes to a zero-length vector`() {
            let value = RFC_6066.TrustedAuthorities()
            let expected: [Byte] = [0x00, 0x00]

            #expect(value.bytes == expected)
            #expect(value.extensionData.type == .trustedCAKeys)
        }

        @Test
        func `Serializes each identifier variant byte-for-byte`() throws {
            let distinguishedName: [Byte] = [0x30, 0x00]
            let value = RFC_6066.TrustedAuthorities(
                trustedAuthoritiesList: [.preAgreed, .x509Name(distinguishedName)]
            )

            // list length (6) | pre_agreed(0) | x509_name(2) | DN length (2) | 30 00
            let expected: [Byte] = [0x00, 0x06, 0x00, 0x02, 0x00, 0x02, 0x30, 0x00]
            #expect(value.bytes == expected)
        }

        @Test
        func `Round-trips every identifier type`() throws {
            let hash = try RFC_6066.SHA1Hash(rawValue: Array(repeating: Byte(0xAB), count: 20))
            let value = RFC_6066.TrustedAuthorities(
                trustedAuthoritiesList: [
                    .preAgreed,
                    .keySHA1Hash(hash),
                    .x509Name([0x30, 0x03, 0x02, 0x01, 0x00]),
                    .certSHA1Hash(hash),
                ]
            )
            #expect(try RFC_6066.TrustedAuthorities(binary: value.bytes) == value)

            #expect(value.trustedAuthoritiesList[0].identifierType == .preAgreed)
            #expect(value.trustedAuthoritiesList[1].identifierType == .keySHA1Hash)
            #expect(value.trustedAuthoritiesList[2].identifierType == .x509Name)
            #expect(value.trustedAuthoritiesList[3].identifierType == .certSHA1Hash)
        }

        @Test
        func `Rejects an unknown identifier type`() {
            // list length (1) | identifier_type (4 — undefined)
            let bytes: [Byte] = [0x00, 0x01, 0x04]
            #expect(throws: RFC_6066.TrustedAuthorities.Error.unknownIdentifierType(4)) {
                try RFC_6066.TrustedAuthorities(binary: bytes)
            }
        }

        @Test
        func `Rejects a truncated hash`() {
            // list length (3) | key_sha1_hash(1) | only 2 of the 20 hash bytes
            let bytes: [Byte] = [0x00, 0x03, 0x01, 0xAB, 0xCD]
            #expect(throws: RFC_6066.TrustedAuthorities.Error.truncated) {
                try RFC_6066.TrustedAuthorities(binary: bytes)
            }
        }
    }
}
