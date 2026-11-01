//! Tracing subscriber Layer for DNSTAP event capture.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use tracing::field::{Field, Visit};
use tracing::span::{Attributes, Id};
use tracing::{Event, Metadata, Subscriber};
use tracing_core::Interest;
use tracing_subscriber::Layer;
use tracing_subscriber::layer::Context;
use tracing_subscriber::registry::LookupSpan;

#[cfg(test)]
use crate::client::MessageTypeFilter;
use crate::client::{DnstapConnection, EventQueue};
use crate::dnstap_message::now_time;
use crate::event::{DnstapEvent, DnstapMessageType, EventPayload};
use crate::{DnsTransport, DnstapConfig};

const DNSTAP_TARGET: &str = "hickory_server::dnstap";

/// A [`tracing_subscriber::Layer`] that captures DNS request/response events
/// and sends them as DNSTAP protobuf messages over Frame Streams.
///
/// The layer is intentionally thin: it captures the raw wire bytes and
/// metadata from each tracing event into a lightweight `DnstapEvent`. The
/// queue encodes it into a protobuf message on the calling thread, so the
/// background sender task only writes frames.
///
/// Message classification is done at the emit site and recorded on the
/// `dns.request` span; resolver and forwarder events carry their fields on the
/// event instead, since they run outside any span.
pub struct DnstapLayer {
    queue: EventQueue,
}

impl DnstapLayer {
    /// Create a new DNSTAP layer and its associated connection handle.
    ///
    /// The layer is immediately usable as a [`tracing_subscriber::Layer`] -
    /// events will be queued in an internal channel.  The returned
    /// [`DnstapConnection`] must be [`start`](DnstapConnection::start)ed
    /// inside a Tokio runtime to actually connect to the collector and drain
    /// the queue.  This two-phase design lets the caller control *when* the
    /// background task (and its "handshake completed" log line) fires relative
    /// to other startup messages.
    pub fn new(config: DnstapConfig) -> (Self, DnstapConnection) {
        let (queue, connection) = EventQueue::new(config);
        (Self { queue }, connection)
    }

    fn send(&self, event: DnstapEvent) {
        self.queue.send(event);
    }
}

/// Per-span data stored in span extensions.
struct DnstapSpanData {
    src_addr: Option<SocketAddr>,
    server_addr: Option<SocketAddr>,
    transport: Option<DnsTransport>,
    message_type: Option<DnstapMessageType>,
    /// Answering zone in wire format, recorded on the span by the catalog so
    /// the response frame can carry the bailiwick.
    query_zone: Option<Vec<u8>>,
    query_time: Option<(u64, u32)>,
}

/// Visitor for extracting fields from span attributes.
///
/// Socket addresses arrive as byte fields plus separate u64 ports so span
/// recording never formats or re-parses `SocketAddr` strings. String fields
/// are parsed to their enums on record; a field whose value never parses
/// leaves the slot empty.
#[derive(Default)]
struct SpanVisitor {
    src_ip: Option<IpAddr>,
    src_port: Option<u16>,
    server_ip: Option<IpAddr>,
    server_port: Option<u16>,
    transport: Option<DnsTransport>,
    message_type: Option<DnstapMessageType>,
    /// Bailiwick carried by upstream query spans.
    query_zone: Option<Vec<u8>>,
    /// Send time carried by upstream query spans, pairing the query with its
    /// response.
    query_time_sec: Option<u64>,
    query_time_nsec: Option<u64>,
}

impl Visit for SpanVisitor {
    fn record_bytes(&mut self, field: &Field, value: &[u8]) {
        match field.name() {
            // An empty zone field keeps the bailiwick absent.
            "query_zone" if !value.is_empty() => self.query_zone = Some(value.to_vec()),
            // An empty slice means absent; otherwise the length selects the IP family.
            "src_addr_bytes" => self.src_ip = parse_ip(value),
            "server_addr_bytes" => self.server_ip = parse_ip(value),
            _ => {}
        }
    }

    fn record_u64(&mut self, field: &Field, value: u64) {
        match field.name() {
            "src_port" => self.src_port = Some(value as u16),
            "server_port" => self.server_port = Some(value as u16),
            "query_time_sec" => self.query_time_sec = Some(value),
            "query_time_nsec" => self.query_time_nsec = Some(value),
            _ => {}
        }
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        match field.name() {
            "protocol" => self.transport = parse_transport(value),
            "class" => self.message_type = parse_class(value),
            _ => {}
        }
    }

    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        // Display fields land here; the Debug payload still has to be
        // materialized to be parsed. 16 bytes cover every value the emit
        // sites record ("update", "https", ...); anything longer cannot be
        // a valid protocol or class.
        let mut buf = [0u8; 16];
        let Some(s) = write_debug(value, &mut buf) else {
            return;
        };
        self.record_str(field, s);
    }
}

/// Render a `record_debug` payload into `buf` for parsing.
///
/// `None` if the payload did not fit; values that long were never valid
/// field content.
fn write_debug<'a>(value: &dyn fmt::Debug, buf: &'a mut [u8]) -> Option<&'a str> {
    use fmt::Write as _;

    struct SliceWriter<'a> {
        buf: &'a mut [u8],
        len: usize,
        overflow: bool,
    }

    impl fmt::Write for SliceWriter<'_> {
        fn write_str(&mut self, s: &str) -> fmt::Result {
            let Some(rest) = self.buf.get_mut(self.len..) else {
                self.overflow = true;
                return Err(fmt::Error);
            };
            if s.len() > rest.len() {
                self.overflow = true;
                return Err(fmt::Error);
            }
            rest[..s.len()].copy_from_slice(s.as_bytes());
            self.len += s.len();
            Ok(())
        }
    }

    let mut writer = SliceWriter {
        buf,
        len: 0,
        overflow: false,
    };
    writer.write_fmt(format_args!("{value:?}")).ok()?;
    if writer.overflow {
        return None;
    }
    // record_debug payloads carry no interior NULs, and the written range is
    // fmt output.
    let SliceWriter { buf, len, .. } = writer;
    std::str::from_utf8(&buf[..len]).ok()
}

/// The emit site classifies; spans without a valid class produce no events.
fn parse_class(s: &str) -> Option<DnstapMessageType> {
    match s {
        "auth" => Some(DnstapMessageType::Auth),
        "client" => Some(DnstapMessageType::Client),
        "resolver" => Some(DnstapMessageType::Resolver),
        "forwarder" => Some(DnstapMessageType::Forwarder),
        "update" => Some(DnstapMessageType::Update),
        _ => None,
    }
}

/// Parse a 4- or 16-octet address field; an empty slice means absent.
fn parse_ip(value: &[u8]) -> Option<IpAddr> {
    if let Ok(octets) = <[u8; 4]>::try_from(value) {
        Some(IpAddr::V4(Ipv4Addr::from(octets)))
    } else if let Ok(octets) = <[u8; 16]>::try_from(value) {
        Some(IpAddr::V6(Ipv6Addr::from(octets)))
    } else {
        None
    }
}

/// Visitor for extracting fields from events.
#[derive(Default)]
struct EventVisitor {
    kind: Option<EventKind>,
    message_bytes: Option<Vec<u8>>,
    query_zone: Option<Vec<u8>>,
    /// Endpoints and transport carried by resolver and forwarder events.
    src_ip: Option<IpAddr>,
    src_port: Option<u16>,
    server_ip: Option<IpAddr>,
    server_port: Option<u16>,
    transport: Option<DnsTransport>,
    /// Query send time carried by resolver and forwarder responses.
    query_time_sec: Option<u64>,
    query_time_nsec: Option<u64>,
}

/// The `kind` field of a DNSTAP emit event.
///
/// Parsing at record time keeps the hot path free of String traffic; an
/// unknown kind produces no event, matching the previous match-and-skip.
#[derive(Clone, Copy, Debug, PartialEq)]
enum EventKind {
    Query,
    Response,
    Zone,
    ResolverQuery,
    ResolverResponse,
    ForwarderQuery,
    ForwarderResponse,
}

impl EventKind {
    fn parse(s: &str) -> Option<Self> {
        match s {
            "query" => Some(Self::Query),
            "response" => Some(Self::Response),
            "zone" => Some(Self::Zone),
            "resolver_query" => Some(Self::ResolverQuery),
            "resolver_response" => Some(Self::ResolverResponse),
            "forwarder_query" => Some(Self::ForwarderQuery),
            "forwarder_response" => Some(Self::ForwarderResponse),
            _ => None,
        }
    }

    fn is_upstream(self) -> bool {
        matches!(
            self,
            Self::ResolverQuery
                | Self::ResolverResponse
                | Self::ForwarderQuery
                | Self::ForwarderResponse
        )
    }
}

impl Visit for EventVisitor {
    fn record_str(&mut self, field: &Field, value: &str) {
        match field.name() {
            "kind" => self.kind = EventKind::parse(value),
            "protocol" => self.transport = parse_transport(value),
            _ => {}
        }
    }

    fn record_bytes(&mut self, field: &Field, value: &[u8]) {
        match field.name() {
            "message_bytes" => self.message_bytes = Some(value.to_vec()),
            // An empty zone field keeps the bailiwick absent.
            "query_zone" if !value.is_empty() => self.query_zone = Some(value.to_vec()),
            "src_addr_bytes" => self.src_ip = parse_ip(value),
            "server_addr_bytes" => self.server_ip = parse_ip(value),
            _ => {}
        }
    }

    fn record_u64(&mut self, field: &Field, value: u64) {
        match field.name() {
            "query_time_sec" => self.query_time_sec = Some(value),
            "query_time_nsec" => self.query_time_nsec = Some(value),
            "src_port" => self.src_port = Some(value as u16),
            "server_port" => self.server_port = Some(value as u16),
            _ => {}
        }
    }

    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        // `%`-formatted fields arrive here, so parse them like string fields.
        let mut buf = [0u8; 16];
        let Some(s) = write_debug(value, &mut buf) else {
            return;
        };
        self.record_str(field, s);
    }
}

/// Map a protocol string from the span to a transport.
///
/// The emit sites record `Protocol` through its `Display` impl, so the
/// accepted strings are that type's `as_str()` values, including `"http3"`
/// for DoH3. Returns `None` for unrecognized protocols so that events with
/// unknown transports are skipped rather than mislabeled.
fn parse_transport(s: &str) -> Option<DnsTransport> {
    match s {
        "udp" => Some(DnsTransport::Udp),
        "tcp" => Some(DnsTransport::Tcp),
        "tls" => Some(DnsTransport::Tls),
        "https" | "http3" => Some(DnsTransport::Https),
        "quic" => Some(DnsTransport::Quic),
        _ => None,
    }
}

/// Build an upstream event from one that has no span; responses carry no initiator.
fn upstream_event(
    kind: EventKind,
    bytes: Vec<u8>,
    zone: Option<Vec<u8>>,
    query_time: Option<(u64, u32)>,
    server_addr: Option<SocketAddr>,
    transport: Option<DnsTransport>,
) -> Option<DnstapEvent> {
    let (message_type, query) = match kind {
        EventKind::ResolverQuery => (DnstapMessageType::Resolver, true),
        EventKind::ResolverResponse => (DnstapMessageType::Resolver, false),
        EventKind::ForwarderQuery => (DnstapMessageType::Forwarder, true),
        EventKind::ForwarderResponse => (DnstapMessageType::Forwarder, false),
        _ => return None,
    };

    let (query_time, payload) = if query {
        (now_time(), EventPayload::Query { bytes })
    } else {
        (
            query_time.unwrap_or_else(now_time),
            EventPayload::Response {
                bytes,
                response_time: now_time(),
            },
        )
    };

    Some(DnstapEvent {
        message_type,
        src_addr: None,
        server_addr,
        transport,
        query_zone: zone,
        query_time,
        payload,
    })
}

impl<S> Layer<S> for DnstapLayer
where
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    // Interest::never() for other targets would block other layers from
    // seeing those events.
    fn register_callsite(&self, _metadata: &'static Metadata<'static>) -> Interest {
        Interest::sometimes()
    }

    /// Always enabled: a layer's `enabled` is a veto over the whole subscriber,
    /// so returning `false` for other targets would silence the server's own
    /// logging. The callbacks filter on `DNSTAP_TARGET` instead.
    fn enabled(&self, _metadata: &Metadata<'_>, _ctx: Context<'_, S>) -> bool {
        true
    }

    fn on_new_span(&self, attrs: &Attributes<'_>, id: &Id, ctx: Context<'_, S>) {
        if attrs.metadata().target() != DNSTAP_TARGET {
            return;
        }

        let mut visitor = SpanVisitor::default();
        attrs.record(&mut visitor);

        let src_addr = visitor
            .src_ip
            .zip(visitor.src_port)
            .map(|(ip, port)| SocketAddr::new(ip, port));
        // An empty server address byte field keeps the slot absent.
        let server_addr = visitor
            .server_ip
            .zip(visitor.server_port)
            .map(|(ip, port)| SocketAddr::new(ip, port));
        let transport = visitor.transport;
        let message_type = visitor.message_type;

        let data = DnstapSpanData {
            src_addr,
            server_addr,
            transport,
            message_type,
            query_zone: visitor.query_zone,
            query_time: visitor
                .query_time_sec
                .zip(visitor.query_time_nsec)
                .map(|(sec, nsec)| (sec, nsec as u32)),
        };

        if let Some(span) = ctx.span(id) {
            span.extensions_mut().insert(data);
        }
    }

    fn on_event(&self, event: &Event<'_>, ctx: Context<'_, S>) {
        if event.metadata().target() != DNSTAP_TARGET {
            return;
        }

        let mut visitor = EventVisitor::default();
        event.record(&mut visitor);

        let Some(kind) = visitor.kind else {
            return;
        };

        if kind.is_upstream() {
            let Some(bytes) = visitor.message_bytes else {
                return;
            };
            let query_time = visitor
                .query_time_sec
                .zip(visitor.query_time_nsec)
                .map(|(sec, nsec)| (sec, nsec as u32));
            let server_addr = visitor
                .server_ip
                .zip(visitor.server_port)
                .map(|(ip, port)| SocketAddr::new(ip, port));
            if let Some(event) = upstream_event(
                kind,
                bytes,
                visitor.query_zone,
                query_time,
                server_addr,
                visitor.transport,
            ) {
                self.send(event);
            }
            return;
        }

        let Some(span) = ctx.event_span(event) else {
            return;
        };

        match kind {
            // The catalog records the answering zone; keep it on the span.
            EventKind::Zone => {
                let Some(zone) = visitor.query_zone else {
                    return;
                };
                let mut ext = span.extensions_mut();
                if let Some(data) = ext.get_mut::<DnstapSpanData>() {
                    data.query_zone = Some(zone);
                }
            }
            EventKind::Query => {
                let Some(bytes) = visitor.message_bytes else {
                    return;
                };
                // The upstream span is created before the client socket exists, so the
                // initiator arrives on the query event and wins over the span's value.
                let event_src_addr = visitor
                    .src_ip
                    .zip(visitor.src_port)
                    .map(|(ip, port)| SocketAddr::new(ip, port));
                // Hold the extensions lock only long enough to mutate span data
                // and copy out the metadata needed to build the event.
                let (src_addr, server_addr, transport, message_type, query_time, zone) = {
                    let mut ext = span.extensions_mut();
                    let Some(data) = ext.get_mut::<DnstapSpanData>() else {
                        return;
                    };
                    let Some(transport) = data.transport else {
                        return;
                    };
                    let Some(message_type) = data.message_type else {
                        return;
                    };
                    // Upstream spans carry the send time; server spans take the
                    // time the request arrived.
                    let query_time = data.query_time.unwrap_or_else(now_time);
                    data.query_time = Some(query_time);
                    (
                        event_src_addr.or(data.src_addr),
                        data.server_addr,
                        transport,
                        message_type,
                        query_time,
                        data.query_zone.clone(),
                    )
                };
                self.send(DnstapEvent {
                    message_type,
                    src_addr,
                    server_addr,
                    transport: Some(transport),
                    query_zone: zone,
                    query_time,
                    payload: EventPayload::Query { bytes },
                });
            }
            EventKind::Response => {
                let Some(response_bytes) = visitor.message_bytes else {
                    return;
                };
                let (src_addr, server_addr, transport, message_type, query_time, query_zone) = {
                    let mut ext = span.extensions_mut();
                    let Some(data) = ext.get_mut::<DnstapSpanData>() else {
                        return;
                    };
                    let Some(src_addr) = data.src_addr else {
                        return;
                    };
                    let Some(transport) = data.transport else {
                        return;
                    };
                    let Some(message_type) = data.message_type else {
                        return;
                    };
                    let query_time = data.query_time.unwrap_or_else(now_time);
                    let query_zone = data.query_zone.take();
                    (
                        src_addr,
                        data.server_addr,
                        transport,
                        message_type,
                        query_time,
                        query_zone,
                    )
                };
                self.send(DnstapEvent {
                    message_type,
                    src_addr: Some(src_addr),
                    server_addr,
                    transport: Some(transport),
                    query_zone,
                    query_time,
                    payload: EventPayload::Response {
                        bytes: response_bytes,
                        response_time: now_time(),
                    },
                });
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use prost::Message as ProstMessage;

    use crate::dnstap_message::dnstap_proto::{
        Message as DnstapMessage, SocketFamily, SocketProtocol, message::Type as MessageType,
    };
    use crate::event::QueuedEvent;

    use super::*;
    use crate::client::{QueueSender, channel};
    use tracing_subscriber::layer::SubscriberExt;

    #[test]
    fn test_response_without_zone_has_no_bailiwick() {
        let (sender, receiver) = channel(16);
        let layer = layer_with_sender(sender);

        let _guard = tracing::subscriber::set_default(tracing_subscriber::registry().with(layer));
        let span = request_span();
        let _enter = span.enter();

        tracing::event!(
            target: DNSTAP_TARGET,
            tracing::Level::TRACE,
            kind = "query",
            message_bytes = b"\x12\x34\x01\x00".as_slice(),
        );
        tracing::event!(
            target: DNSTAP_TARGET,
            tracing::Level::TRACE,
            kind = "response",
            message_bytes = b"\x12\x34\x81\x80".as_slice(),
        );
        drop(_enter);

        let query = decode(&receiver.try_recv().expect("query event"));
        assert_eq!(
            query.query_message.as_deref(),
            Some(b"\x12\x34\x01\x00".as_slice())
        );
        assert!(query.query_zone.is_none());

        let response = decode(&receiver.try_recv().expect("response event"));
        assert_eq!(
            response.response_message.as_deref(),
            Some(b"\x12\x34\x81\x80".as_slice())
        );
        assert!(response.query_zone.is_none());
        drop(_guard);
    }

    /// Each protocol string the server records maps to its own transport, so a
    /// non-UDP span records its real socket protocol.
    ///
    /// The literals below are `Protocol`'s `Display` output.
    #[test]
    fn test_non_udp_protocol_parse() {
        for (protocol, expected) in [
            ("tcp", SocketProtocol::Tcp),
            ("tls", SocketProtocol::Dot),
            ("https", SocketProtocol::Doh),
            ("http3", SocketProtocol::Doh),
            ("quic", SocketProtocol::Doq),
        ] {
            let (sender, receiver) = channel(16);
            let layer = layer_with_sender(sender);

            let _guard =
                tracing::subscriber::set_default(tracing_subscriber::registry().with(layer));
            let span = tracing::span!(
                target: DNSTAP_TARGET,
                tracing::Level::TRACE,
                "dns.request",
                src_addr_bytes = &Ipv4Addr::new(192, 0, 2, 1).octets()[..],
                src_port = 53u64,
                protocol = %protocol,
                server_addr_bytes = &[][..],
                server_port = 0u64,
                class = %"auth",
            );
            let _enter = span.enter();

            tracing::event!(
                target: DNSTAP_TARGET,
                tracing::Level::TRACE,
                kind = "query",
                message_bytes = b"\x12\x34\x01\x00".as_slice(),
            );
            drop(_enter);

            let query = decode(&receiver.try_recv().expect("query event"));
            assert!(query.query_message.is_some(), "expected a query event");
            assert_eq!(
                query.socket_protocol,
                Some(expected as i32),
                "protocol {protocol}"
            );
            drop(_guard);
        }
    }

    #[test]
    fn test_response_carries_answering_zone() {
        let (sender, receiver) = channel(16);
        let layer = layer_with_sender(sender);

        let _guard = tracing::subscriber::set_default(tracing_subscriber::registry().with(layer));
        let span = request_span();
        let _enter = span.enter();

        tracing::event!(
            target: DNSTAP_TARGET,
            tracing::Level::TRACE,
            kind = "zone",
            query_zone = ZONE_WIRE,
        );
        tracing::event!(
            target: DNSTAP_TARGET,
            tracing::Level::TRACE,
            kind = "response",
            message_bytes = b"\x12\x34\x81\x80".as_slice(),
        );
        drop(_enter);

        let response = decode(&receiver.try_recv().expect("response event"));
        assert!(
            response.response_message.is_some(),
            "expected a response event"
        );
        assert_eq!(response.query_zone.as_deref(), Some(ZONE_WIRE));
        drop(_guard);
    }

    #[test]
    fn test_span_fields_parse_to_enums() {
        let (sender, receiver) = channel(16);
        let layer = layer_with_sender(sender);

        let _guard = tracing::subscriber::set_default(tracing_subscriber::registry().with(layer));
        let span = request_span();
        let _enter = span.enter();

        tracing::event!(
            target: DNSTAP_TARGET,
            tracing::Level::TRACE,
            kind = "query",
            message_bytes = b"\x12\x34\x01\x00".as_slice(),
        );
        drop(_enter);

        let query = decode(&receiver.try_recv().expect("query event"));
        assert!(query.query_message.is_some(), "expected a query event");
        assert_eq!(query.socket_protocol, Some(SocketProtocol::Udp as i32));
        assert_eq!(query.r#type, MessageType::AuthQuery as i32);
        assert_eq!(
            query.query_address.as_deref(),
            Some([192, 0, 2, 1].as_slice())
        );
        assert_eq!(query.query_port, Some(53));
        assert_eq!(query.response_address, None);
        drop(_guard);
    }

    #[test]
    fn test_resolver_response_carries_query_time() {
        let (sender, receiver) = channel(16);
        let layer = DnstapLayer {
            queue: EventQueue::with_sender(
                sender,
                MessageTypeFilter::from_config(&DnstapConfig {
                    log_resolver_response: true,
                    ..Default::default()
                }),
            ),
        };

        let _guard = tracing::subscriber::set_default(tracing_subscriber::registry().with(layer));

        // Hop responses run outside the request span and carry the query's
        // send time from the emit site.
        tracing::event!(
            target: DNSTAP_TARGET,
            tracing::Level::TRACE,
            kind = "resolver_response",
            message_bytes = b"\x12\x34\x81\x80".as_slice(),
            query_zone = ZONE_WIRE,
            query_time_sec = 1_000_000u64,
            query_time_nsec = 123u64,
        );

        let response = decode(&receiver.try_recv().expect("resolver response event"));
        assert!(
            response.response_message.is_some(),
            "expected a response event"
        );
        assert_eq!(response.query_time_sec, Some(1_000_000));
        assert_eq!(response.query_time_nsec, Some(123));
        drop(_guard);
    }

    /// Forwarded lookups have no bailiwick; a response without `query_zone`
    /// still emits.
    #[test]
    fn test_resolver_response_without_zone() {
        let (sender, receiver) = channel(16);
        let layer = DnstapLayer {
            queue: EventQueue::with_sender(
                sender,
                MessageTypeFilter::from_config(&DnstapConfig {
                    log_resolver_response: true,
                    ..Default::default()
                }),
            ),
        };

        let _guard = tracing::subscriber::set_default(tracing_subscriber::registry().with(layer));

        tracing::event!(
            target: DNSTAP_TARGET,
            tracing::Level::TRACE,
            kind = "resolver_response",
            message_bytes = b"\x12\x34\x81\x80".as_slice(),
            query_time_sec = 1_000_000u64,
            query_time_nsec = 123u64,
        );

        let response = decode(&receiver.try_recv().expect("resolver response event"));
        assert!(response.query_zone.is_none());
        assert_eq!(response.query_time_sec, Some(1_000_000));
        assert_eq!(response.query_time_nsec, Some(123));
        drop(_guard);
    }

    /// Forwarder events have no span, so the event itself carries the upstream
    /// endpoint and transport, as the protobuf recommends.
    #[test]
    fn test_forwarder_query_carries_upstream_endpoint() {
        let (sender, receiver) = channel(16);
        let layer = DnstapLayer {
            queue: EventQueue::with_sender(
                sender,
                MessageTypeFilter::from_config(&DnstapConfig {
                    log_forwarder_query: true,
                    ..Default::default()
                }),
            ),
        };

        let _guard = tracing::subscriber::set_default(tracing_subscriber::registry().with(layer));

        tracing::event!(
            target: DNSTAP_TARGET,
            tracing::Level::TRACE,
            kind = "forwarder_query",
            message_bytes = b"\x12\x34\x01\x00".as_slice(),
            protocol = %"tls",
            server_addr_bytes = &Ipv4Addr::new(192, 0, 2, 53).octets()[..],
            server_port = 853u64,
        );

        let event = decode(&receiver.try_recv().expect("forwarder query event"));
        assert_eq!(event.r#type, MessageType::ForwarderQuery as i32);
        assert_eq!(event.socket_protocol, Some(SocketProtocol::Dot as i32));
        assert_eq!(
            event.response_address.as_deref(),
            Some([192, 0, 2, 53].as_slice())
        );
        assert_eq!(event.response_port, Some(853));
        assert_eq!(event.query_address, None);
        assert!(event.query_zone.is_none());
        assert!(event.query_message.is_some(), "expected a query event");
        drop(_guard);
    }

    /// The resolver's span predates the client socket, so the initiator rides the event.
    #[test]
    fn test_upstream_query_takes_initiator_from_event() {
        let (sender, receiver) = channel(16);
        let layer = DnstapLayer {
            queue: EventQueue::with_sender(
                sender,
                MessageTypeFilter::from_config(&DnstapConfig {
                    log_forwarder_query: true,
                    ..Default::default()
                }),
            ),
        };

        let _guard = tracing::subscriber::set_default(tracing_subscriber::registry().with(layer));

        let span = tracing::span!(
            target: DNSTAP_TARGET,
            tracing::Level::TRACE,
            "dns.upstream",
            class = %"forwarder",
            protocol = %"udp",
            server_addr_bytes = &Ipv4Addr::new(192, 0, 2, 53).octets()[..],
            server_port = 53u64,
            query_zone = &[][..],
            query_time_sec = 1_000_000u64,
            query_time_nsec = 0u64,
        );

        let _enter = span.enter();
        tracing::event!(
            target: DNSTAP_TARGET,
            tracing::Level::TRACE,
            kind = "query",
            message_bytes = b"\x12\x34\x01\x00".as_slice(),
            src_addr_bytes = &Ipv4Addr::UNSPECIFIED.octets()[..],
            src_port = 35300u64,
        );
        drop(_enter);

        let event = decode(&receiver.try_recv().expect("forwarder query event"));
        assert_eq!(event.r#type, MessageType::ForwarderQuery as i32);
        assert_eq!(event.socket_protocol, Some(SocketProtocol::Udp as i32));
        assert_eq!(event.socket_family, Some(SocketFamily::Inet as i32));
        assert_eq!(event.query_address, None);
        assert_eq!(event.query_port, Some(35300));
        assert_eq!(
            event.response_address.as_deref(),
            Some([192, 0, 2, 53].as_slice())
        );
        assert_eq!(event.response_port, Some(53));
        assert!(event.query_message.is_some(), "expected a query event");
        drop(_guard);
    }

    /// Build a layer that enqueues into the given channel without a
    /// background task, so the tests can inspect the events directly.
    fn layer_with_sender(sender: QueueSender) -> DnstapLayer {
        DnstapLayer {
            queue: EventQueue::with_sender(
                sender,
                MessageTypeFilter::from_config(&DnstapConfig {
                    log_auth_query: true,
                    log_auth_response: true,
                    ..Default::default()
                }),
            ),
        }
    }

    /// An auth-classified request span with the full socket context.
    fn request_span() -> tracing::Span {
        tracing::span!(
            target: DNSTAP_TARGET,
            tracing::Level::TRACE,
            "dns.request",
            src_addr_bytes = &Ipv4Addr::new(192, 0, 2, 1).octets()[..],
            src_port = 53u64,
            protocol = %"udp",
            server_addr_bytes = &[][..],
            server_port = 0u64,
            class = %"auth",
        )
    }

    /// Decode the protobuf message the layer queued for a tracing event.
    fn decode(item: &QueuedEvent) -> DnstapMessage {
        crate::dnstap_message::dnstap_proto::Dnstap::decode(item.message.as_ref())
            .expect("queued message decodes")
            .message
            .expect("queued message carries a body")
    }

    const ZONE_WIRE: &[u8] = b"\x07example\x03com\x00";
}
