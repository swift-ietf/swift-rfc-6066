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
import Testing

@testable import RFC_6066

@Suite
struct `RFC 6066 server_name (SNI)` {

    /// "example.com" — the running example for the byte-exact vectors below.
    static let exampleCom: [Byte] = [Byte(0x65), Byte(0x78), Byte(0x61), Byte(0x6D), Byte(0x70), Byte(0x6C), Byte(0x65), Byte(0x2E), Byte(0x63), Byte(0x6F), Byte(0x6D)]

    /// The full `server_name` `extension_data` body for "example.com":
    /// server_name_list length (14) | name_type (0) | host_name length (11) | "example.com"
    static let body: [Byte] = [Byte(0x00), Byte(0x0E), Byte(0x00), Byte(0x00), Byte(0x0B)] + exampleCom

    @Suite
    struct `HostName` {
        @Test
        func `Creates from string`() throws {
            let hostName = try RFC_6066.HostName("example.com")
            #expect(hostName.description == "example.com")
            #expect(hostName.rawValue == `RFC 6066 server_name (SNI)`.exampleCom)
        }

        @Test
        func `Serializes as a uint16-length-prefixed vector`() throws {
            let hostName = try RFC_6066.HostName("example.com")

            var buffer: [Byte] = []
            RFC_6066.HostName.serialize(hostName, into: &buffer)

            let expected: [Byte] = [Byte(0x00), Byte(0x0B)] + `RFC 6066 server_name (SNI)`.exampleCom
            #expect(buffer == expected)
        }

        @Test
        func `Round-trips`() throws {
            let hostName = try RFC_6066.HostName("example.com")
            #expect(try RFC_6066.HostName(binary: hostName.bytes) == hostName)
        }

        @Test
        func `Rejects empty host name`() {
            let empty: [Byte] = []
            #expect(throws: RFC_6066.HostName.Error.empty) {
                try RFC_6066.HostName(rawValue: empty)
            }
        }

        @Test
        func `Rejects trailing dot`() {
            // RFC 6066 §3: "represented as a byte string using ASCII encoding
            // without a trailing dot".
            #expect(throws: RFC_6066.HostName.Error.trailingDot) {
                try RFC_6066.HostName("example.com.")
            }
        }

        @Test
        func `Rejects non-ASCII bytes`() {
            // U+00E4 encodes as 0xC3 0xA4 in UTF-8 — internationalized names must
            // be A-label (Punycode) encoded before they reach HostName.
            #expect(throws: RFC_6066.HostName.Error.nonASCII) {
                try RFC_6066.HostName("exämple.com")
            }
        }
    }

    @Suite
    struct `ServerName` {
        @Test
        func `Reports host_name as its name type`() throws {
            let serverName = RFC_6066.ServerName(hostName: try RFC_6066.HostName("example.com"))
            #expect(serverName.nameType == .hostName)
            #expect(serverName.nameType.rawValue == 0)
        }

        @Test
        func `Serializes name_type then host name`() throws {
            let serverName = RFC_6066.ServerName(hostName: try RFC_6066.HostName("example.com"))

            var buffer: [Byte] = []
            RFC_6066.ServerName.serialize(serverName, into: &buffer)

            let expected: [Byte] = [Byte(0x00), Byte(0x00), Byte(0x0B)] + `RFC 6066 server_name (SNI)`.exampleCom
            #expect(buffer == expected)
        }

        @Test
        func `Round-trips`() throws {
            let serverName = RFC_6066.ServerName(hostName: try RFC_6066.HostName("example.com"))
            #expect(try RFC_6066.ServerName(binary: serverName.bytes) == serverName)
        }

        @Test
        func `Rejects unknown name_type`() {
            // name_type = 1 (undefined), then a 1-byte name.
            let bytes: [Byte] = [Byte(0x01), Byte(0x00), Byte(0x01), Byte(0x61)]
            #expect(throws: RFC_6066.ServerName.Error.unknownNameType(1)) {
                try RFC_6066.ServerName(binary: bytes)
            }
        }
    }

    @Suite
    struct `ServerNameList` {
        @Test
        func `Serializes the RFC 6066 §3 body byte-for-byte`() throws {
            let list = RFC_6066.ServerNameList(hostName: try RFC_6066.HostName("example.com"))

            #expect(list.bytes == `RFC 6066 server_name (SNI)`.body)
            #expect(list.bytes.count == 16)
        }

        @Test
        func `Wraps into an RFC 8446 extension envelope`() throws {
            let list = RFC_6066.ServerNameList(hostName: try RFC_6066.HostName("example.com"))
            let ext = try list.extensionData

            #expect(ext.type == .serverName)
            #expect(ext.type.rawValue == 0)
            #expect(ext.data == `RFC 6066 server_name (SNI)`.body)

            // extension_type (0x0000) | extension_data length (16) | body
            let expected: [Byte] = [Byte(0x00), Byte(0x00), Byte(0x00), Byte(0x10)] + `RFC 6066 server_name (SNI)`.body
            #expect(ext.bytes == expected)
        }

        @Test
        func `Round-trips`() throws {
            let list = RFC_6066.ServerNameList(hostName: try RFC_6066.HostName("example.com"))
            #expect(try RFC_6066.ServerNameList(binary: list.bytes) == list)
        }

        @Test
        func `Parses the reference body`() throws {
            let list = try RFC_6066.ServerNameList(binary: `RFC 6066 server_name (SNI)`.body)
            #expect(list.serverNameList.count == 1)
            #expect(list.hostName?.description == "example.com")
        }

        @Test
        func `Rejects an empty list`() {
            #expect(throws: RFC_6066.ServerNameList.Error.empty) {
                try RFC_6066.ServerNameList(serverNameList: [])
            }
            // …and on the wire: a zero-length server_name_list.
            let zeroLength: [Byte] = [Byte(0x00), Byte(0x00)]
            #expect(throws: RFC_6066.ServerNameList.Error.empty) {
                try RFC_6066.ServerNameList(binary: zeroLength)
            }
        }

        @Test
        func `Rejects duplicate name types`() throws {
            // RFC 6066 §3: "The ServerNameList MUST NOT contain more than one name
            // of the same name_type."
            let entry = RFC_6066.ServerName(hostName: try RFC_6066.HostName("example.com"))
            #expect(throws: RFC_6066.ServerNameList.Error.duplicateNameType(.hostName)) {
                try RFC_6066.ServerNameList(serverNameList: [entry, entry])
            }
        }

        @Test
        func `Rejects an unknown name_type on the wire`() {
            // list length (4) | name_type (1 — undefined) | name length (1) | 'a'
            let bytes: [Byte] = [Byte(0x00), Byte(0x04), Byte(0x01), Byte(0x00), Byte(0x01), Byte(0x61)]
            #expect(throws: RFC_6066.ServerNameList.Error.unknownNameType(1)) {
                try RFC_6066.ServerNameList(binary: bytes)
            }
        }

        @Test
        func `Rejects a truncated body`() {
            let bytes: [Byte] = [Byte(0x00), Byte(0x0E), Byte(0x00)]
            #expect(throws: RFC_6066.ServerNameList.Error.truncated) {
                try RFC_6066.ServerNameList(binary: bytes)
            }
        }

        @Test
        func `Rejects trailing bytes`() {
            let bytes: [Byte] = `RFC 6066 server_name (SNI)`.body + [Byte(0xFF)]
            #expect(throws: RFC_6066.ServerNameList.Error.trailingData(1)) {
                try RFC_6066.ServerNameList(binary: bytes)
            }
        }
    }

    @Suite("ServerNameList.Acknowledgement")
    struct AcknowledgementTests {
        @Test
        func `Serializes to an empty body`() {
            // RFC 6066 §3: "The 'extension_data' field of this extension SHALL be
            // empty." — the server's response (EncryptedExtensions in TLS 1.3).
            let ack = RFC_6066.ServerNameList.Acknowledgement()
            #expect(ack.bytes.isEmpty)
        }

        @Test
        func `Wraps into an empty RFC 8446 extension envelope`() {
            let ext = RFC_6066.ServerNameList.Acknowledgement().extensionData
            #expect(ext.type == .serverName)
            #expect(ext.data.isEmpty)

            // extension_type (0x0000) | extension_data length (0)
            let expected: [Byte] = [Byte(0x00), Byte(0x00), Byte(0x00), Byte(0x00)]
            #expect(ext.bytes == expected)
        }

        @Test
        func `Round-trips`() throws {
            let ack = RFC_6066.ServerNameList.Acknowledgement()
            #expect(try RFC_6066.ServerNameList.Acknowledgement(binary: ack.bytes) == ack)
        }

        @Test
        func `Rejects a non-empty body`() {
            let bytes: [Byte] = [Byte(0x00)]
            #expect(throws: RFC_6066.ServerNameList.Acknowledgement.Error.trailingData(1)) {
                try RFC_6066.ServerNameList.Acknowledgement(binary: bytes)
            }
        }
    }
}
