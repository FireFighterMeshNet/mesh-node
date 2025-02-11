error_set::error_set! {
    PacketNewErr = {
        /// Too much data for one packet.
        #[display("data too large for one packet")]
        TooBig,
    };
    /// Errors related to messages received.
    InvalidMsg = {
        /// Protocol version of msg doesn't match.
        Version { version: crate::Version },
    };
}
