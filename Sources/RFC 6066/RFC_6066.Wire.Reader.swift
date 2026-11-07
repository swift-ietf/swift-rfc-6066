internal import Binary

extension RFC_6066.Wire {
    /// A forward cursor over a byte buffer that decodes the TLS
    /// presentation-language forms.
    ///
    /// The cursor advances as fields are read; length-prefixed vectors are
    /// bounds-checked against the remaining input. All reads throw
    /// ``RFC_6066/Wire/Error`` on exhaustion or overflow.
    struct Reader {
        /// The backing byte buffer (arithmetic-domain reads bridge via
        /// `Byte.bitPattern`).
        private let bytes: [Byte]

        /// The current read offset.
        private(set) var index: Int

        /// Creates a reader positioned at the start of `bytes`.
        init(_ bytes: [Byte]) {
            self.bytes = bytes
            self.index = 0
        }
    }
}

extension RFC_6066.Wire.Reader {
    /// The number of unread bytes remaining.
    var remaining: Int { bytes.count - index }

    /// Whether every byte has been consumed.
    var isAtEnd: Bool { index >= bytes.count }

    /// Reads a single `uint8` (arithmetic-domain).
    mutating func byte() throws(RFC_6066.Wire.Error) -> UInt8 {
        guard index < bytes.count else { throw .truncated }
        defer { index += 1 }
        return bytes[index].bitPattern
    }

    /// Reads a big-endian `uint16`.
    mutating func uint16() throws(RFC_6066.Wire.Error) -> UInt16 {
        let hi = try byte()
        let lo = try byte()
        return (UInt16(hi) << 8) | UInt16(lo)
    }

    /// Reads a big-endian `uint24` as an `Int` (0...2^24-1).
    mutating func uint24() throws(RFC_6066.Wire.Error) -> Int {
        let a = try byte()
        let b = try byte()
        let c = try byte()
        return (Int(a) << 16) | (Int(b) << 8) | Int(c)
    }

    /// Reads `count` raw bytes (opaque byte-domain).
    mutating func take(_ count: Int) throws(RFC_6066.Wire.Error) -> [Byte] {
        guard count >= 0 else { throw .lengthOverflow }
        guard remaining >= count else { throw .truncated }
        let slice = bytes[index..<index + count]
        index += count
        return Array(slice)
    }

    /// Reads a `uint16`-length-prefixed opaque vector (`opaque x<0..2^16-1>`).
    mutating func vector16() throws(RFC_6066.Wire.Error) -> [Byte] {
        let count = Int(try uint16())
        return try take(count)
    }

    /// Reads a `uint24`-length-prefixed opaque vector (`opaque x<0..2^24-1>`).
    mutating func vector24() throws(RFC_6066.Wire.Error) -> [Byte] {
        let count = try uint24()
        return try take(count)
    }

    /// Asserts the reader has consumed all of its input.
    func expectEnd() throws(RFC_6066.Wire.Error) {
        guard isAtEnd else { throw .trailingData(remaining) }
    }
}
