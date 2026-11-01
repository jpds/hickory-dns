// Copyright 2015-2026 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your option. This
// file may not be copied, modified, or distributed except according to those
// terms.

//! DNS events queued for DNSTAP encoding.

use std::net::SocketAddr;

use bytes::Bytes;

use crate::DnsTransport;

/// DNSTAP message type variants.
///
/// Determines which protobuf message type is used for query/response events.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum DnstapMessageType {
    /// AUTH_QUERY / AUTH_RESPONSE.
    Auth,
    /// CLIENT_QUERY / CLIENT_RESPONSE.
    Client,
    /// RESOLVER_QUERY / RESOLVER_RESPONSE.
    Resolver,
    /// FORWARDER_QUERY / FORWARDER_RESPONSE, for upstream servers asked to
    /// recurse.
    Forwarder,
    /// UPDATE_QUERY / UPDATE_RESPONSE, used when the message opcode is UPDATE.
    Update,
}

/// A raw DNS event, encoded at the emit site and handed to the sender.
///
/// Emitters build these structs on the request path; the queue turns each one
/// into a protobuf message before it reaches the channel.
///
/// The message type is classified by the emitter; each event yields exactly
/// one frame.
#[derive(Debug)]
pub(crate) struct DnstapEvent {
    pub(crate) message_type: DnstapMessageType,
    pub(crate) src_addr: Option<SocketAddr>,
    pub(crate) server_addr: Option<SocketAddr>,
    pub(crate) transport: Option<DnsTransport>,
    pub(crate) query_time: (u64, u32),
    pub(crate) query_zone: Option<Vec<u8>>,
    pub(crate) payload: EventPayload,
}

/// The DNS message bytes an event carries. Responses also carry the time
/// they were emitted, recorded before queueing so the timestamp does not
/// drift with sender backlog.
#[derive(Debug)]
pub(crate) enum EventPayload {
    Query {
        bytes: Vec<u8>,
    },
    Response {
        bytes: Vec<u8>,
        response_time: (u64, u32),
    },
}

impl EventPayload {
    /// The DNS message bytes, query or response.
    pub(crate) fn bytes(&self) -> &[u8] {
        match self {
            Self::Query { bytes } | Self::Response { bytes, .. } => bytes,
        }
    }

    /// The response emit time; `None` for queries.
    pub(crate) fn response_time(&self) -> Option<(u64, u32)> {
        match self {
            Self::Query { .. } => None,
            Self::Response { response_time, .. } => Some(*response_time),
        }
    }
}

impl DnstapEvent {
    /// Whether the event carries a query rather than a response.
    pub(crate) fn is_query(&self) -> bool {
        matches!(self.payload, EventPayload::Query { .. })
    }

    pub(crate) fn payload_len(&self) -> usize {
        // Accounted bytes for the queue budget: the DNS payload plus the
        // query zone, the per-event heap this event holds while queued.
        self.payload.bytes().len() + self.query_zone.as_ref().map_or(0, Vec::len)
    }
}

/// An event encoded at the emit site, waiting for the sender.
///
/// The protobuf message is built on the emitting thread so the background
/// sender only writes bytes. The metadata next to it is what the counters and
/// the byte budget need once the event itself is gone.
#[derive(Debug)]
pub(crate) struct QueuedEvent {
    /// One DNSTAP protobuf message, the payload of a data frame.
    pub(crate) message: Bytes,
    /// Category for the counters; read only when the metrics feature is on.
    #[cfg_attr(not(feature = "metrics"), allow(dead_code))]
    pub(crate) message_type: DnstapMessageType,
    /// Whether the message is a query, for the direction label.
    #[cfg_attr(not(feature = "metrics"), allow(dead_code))]
    pub(crate) query: bool,
    /// The accounted size, as [`DnstapEvent::payload_len`] reports it.
    pub(crate) payload_len: usize,
}
