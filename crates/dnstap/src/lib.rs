//! DNSTAP support for structured DNS event logging.
//!
//! [DNSTAP](https://dnstap.info/) is a flexible, structured binary log format for DNS software,
//! commonly used for security monitoring, analytics, and SIEM integration. It uses
//! [Protocol Buffers](https://protobuf.dev/) for message encoding and
//! [Frame Streams](https://farsightsec.github.io/fstrm/) for transport framing.
//!
//! # Architecture
//!
//! The implementation uses an async client (`DnstapClient`) with a background sender task
//! connected via an mpsc channel. DNS handler code sends log messages through the channel
//! without blocking request processing. The background task manages the Frame Streams
//! connection to the collector, with automatic reconnection and exponential backoff on failure.
//!
//! # Supported transports
//!
//! - **TCP** - connect to a remote DNSTAP collector via TCP
//! - **Unix socket** - connect via Unix domain socket (unix platforms only)
//!
//! # Per-message-type logging
//!
//! Each combination of message category and direction is toggled by its own flag.
//! The ten supported message types are:
//!
//! | Config option              | Description                                    |
//! |----------------------------|------------------------------------------------|
//! | `log_auth_query`           | Authoritative queries received                 |
//! | `log_auth_response`        | Authoritative responses sent                   |
//! | `log_client_query`         | Client queries received                        |
//! | `log_client_response`      | Client responses sent                          |
//! | `log_resolver_query`       | Recursor queries sent upstream                 |
//! | `log_resolver_response`    | Recursor responses received from upstream      |
//! | `log_forwarder_query`      | Forwarded queries sent to an upstream resolver |
//! | `log_forwarder_response`   | Forwarded responses received from an upstream  |
//! | `log_update_query`         | Dynamic update requests received               |
//! | `log_update_response`      | Dynamic update responses sent                  |
//!
//! All default to `false`.
//!
//! # Configuration example
//!
//! ```toml
//! [dnstap]
//! enabled = true
//! tcp_address = "127.0.0.1:6000"
//! send_identity = true
//! # identity = "custom-name"  # defaults to hostname
//! send_version = true
//! # version = "custom-version"  # defaults to package version
//! buffer_size = 4096
//! log_client_query = true
//! log_client_response = true
//! ```

#![warn(clippy::dbg_macro, clippy::print_stdout, missing_docs)]
#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]

mod client;
mod dnstap_message;
mod event;
mod framestream;

pub use client::{
    DnstapClient, DnstapConfig, DnstapConnection, DnstapEndpoint, QUEUED_BYTES_PER_EVENT,
};
pub use event::DnstapMessageType;

/// DNS transport protocol for the DNSTAP `socket_protocol` field.
///
/// This is a simplified protocol enum that decouples the DNSTAP crate from
/// the server's internal `Protocol` type and its feature-gated variants.
#[derive(Clone, Copy, Debug)]
pub enum DnsTransport {
    /// DNS over UDP (RFC 1035).
    Udp,
    /// DNS over TCP (RFC 1035).
    Tcp,
    /// DNS over TLS (RFC 7858).
    Tls,
    /// DNS over HTTPS (RFC 8484), including HTTP/3.
    Https,
    /// DNS over QUIC (RFC 9250).
    Quic,
}
