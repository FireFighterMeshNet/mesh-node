error_set::error_set! {
    SendToParentErr = {
        #[display("no parent")]
        NoParent,
    } || PacketSendErr || PacketNewErr;
    SendToChildErr = {
        #[display("child missing")]
        NoChild
    } || PacketSendErr || PacketNewErr;
    PacketSendErr = {
        #[display("{source:?}")]
        Tcp {
            source: embassy_net::tcp::Error
        },
        /// The selected next hop isn't available.
        NextHopMissing
        // #[display("{source:?}")]
        // ScrollErr {
        //     source: scroll::Error,
        // },
    };
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
