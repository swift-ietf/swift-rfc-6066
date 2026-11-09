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

import RFC_6066
import RFC_6066_Standard_Library_Integration
import Testing

enum `RFC_6066_UInt8 Tests` {}

extension `RFC_6066_UInt8 Tests` {
    @Suite
    struct `RFC 6066 UInt8 forwarders` {

        @Test
        func `HostName forwarder constructs from [UInt8]`() throws {
            let uint8Bytes: [UInt8] = Array("example.com".utf8)
            let hostName = try RFC_6066.HostName(rawValue: uint8Bytes)
            #expect(hostName.description == "example.com")
        }

        @Test
        func `HostName forwarder rejects empty [UInt8]`() {
            let uint8Bytes: [UInt8] = []
            #expect(throws: RFC_6066.HostName.Error.empty) {
                try RFC_6066.HostName(rawValue: uint8Bytes)
            }
        }

        @Test
        func `HostName forwarder rejects a trailing dot`() {
            let uint8Bytes: [UInt8] = Array("example.com.".utf8)
            #expect(throws: RFC_6066.HostName.Error.trailingDot) {
                try RFC_6066.HostName(rawValue: uint8Bytes)
            }
        }

        @Test
        func `SHA1Hash forwarder constructs from [UInt8]`() throws {
            let uint8Bytes: [UInt8] = Array(repeating: 0xAB, count: 20)
            let hash = try RFC_6066.SHA1Hash(rawValue: uint8Bytes)
            #expect(hash.rawValue.count == 20)
        }

        @Test
        func `SHA1Hash forwarder rejects a wrong-length [UInt8]`() {
            let uint8Bytes: [UInt8] = Array(repeating: 0xAB, count: 19)
            #expect(throws: RFC_6066.SHA1Hash.Error.invalidLength(19)) {
                try RFC_6066.SHA1Hash(rawValue: uint8Bytes)
            }
        }

        @Test
        func `CertificateStatus forwarder constructs from [UInt8]`() throws {
            let uint8Bytes: [UInt8] = [0xDE, 0xAD, 0xBE, 0xEF]
            let status = try RFC_6066.CertificateStatus(response: uint8Bytes)
            #expect(status.response.count == 4)
            #expect(status.statusType == .ocsp)
        }

        @Test
        func `CertificateStatus forwarder rejects an empty [UInt8]`() {
            let uint8Bytes: [UInt8] = []
            #expect(throws: RFC_6066.CertificateStatus.Error.emptyResponse) {
                try RFC_6066.CertificateStatus(response: uint8Bytes)
            }
        }

        @Test
        func `OCSPStatusRequest forwarder constructs from [UInt8]`() throws {
            let responderIDs: [[UInt8]] = [[0xAA, 0xBB]]
            let requestExtensions: [UInt8] = [0xCC]
            let request = try RFC_6066.CertificateStatusRequest.OCSPStatusRequest(
                responderIDList: responderIDs,
                requestExtensions: requestExtensions
            )
            #expect(request.responderIDList.count == 1)
            #expect(request.responderIDList[0].count == 2)
            #expect(request.requestExtensions.count == 1)
        }

        @Test
        func `URLAndHash forwarder constructs from [UInt8]`() throws {
            let url: [UInt8] = Array("http://example.com/cert.der".utf8)
            let hash = try RFC_6066.SHA1Hash(rawValue: Array(repeating: 0xCD, count: 20) as [UInt8])
            let entry = try RFC_6066.CertificateURL.URLAndHash(url: url, sha1Hash: hash)
            #expect(entry.url.count == url.count)
            #expect(entry.sha1Hash == hash)
        }

        @Test
        func `URLAndHash forwarder rejects an empty [UInt8] url`() throws {
            let url: [UInt8] = []
            let hash = try RFC_6066.SHA1Hash(rawValue: Array(repeating: 0xCD, count: 20) as [UInt8])
            #expect(throws: RFC_6066.CertificateURL.URLAndHash.Error.emptyURL) {
                try RFC_6066.CertificateURL.URLAndHash(url: url, sha1Hash: hash)
            }
        }
    }
}
