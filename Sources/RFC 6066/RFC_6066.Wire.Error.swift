extension RFC_6066.Wire {
    /// Errors raised by the presentation-language reader.
    ///
    /// Payload parsers catch these and map them onto their own typed `Error`
    /// so the internal ``RFC_6066/Wire`` namespace stays out of the public
    /// surface.
    enum Error: Swift.Error, Sendable, Equatable {
        /// The reader ran out of bytes before a field was complete.
        case truncated

        /// A declared vector/field length exceeded the bytes actually present.
        case lengthOverflow

        /// Bytes remained after a structure that should have consumed the input.
        case trailingData(_ remaining: Int)
    }
}
