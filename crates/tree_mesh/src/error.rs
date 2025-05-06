//! Custom error types for this crate.

error_set::error_set! {
    /// Error creating a new [`crate::Packet`]
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
