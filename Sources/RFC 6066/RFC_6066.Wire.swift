extension RFC_6066 {
    /// Internal TLS presentation-language codec namespace.
    ///
    /// The TLS presentation language's only composite forms are fixed-width
    /// big-endian integers and length-prefixed opaque vectors
    /// (`opaque x<lo..hi>`). ``Wire`` centralizes the reading (``Wire/Reader``)
    /// and writing (append helpers) of those forms.
    enum Wire {}
}
