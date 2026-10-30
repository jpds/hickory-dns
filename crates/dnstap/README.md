# Overview

`hickory-dnstap` records DNS activity in the [DNSTAP] format: events are
captured through `tracing`, encoded as Protocol Buffers, and transmitted over
Frame Streams to a collector.

Events are captured by installing a `DnstapLayer` in the `tracing` subscriber,
so only the DNS hot path pays for them, and only when a layer is present:

```rust,ignore
use hickory_dnstap::{DnstapConfig, DnstapEndpoint, DnstapLayer};

let (layer, connection) = DnstapLayer::new(DnstapConfig {
    endpoint: DnstapEndpoint::Tcp("127.0.0.1:6000".parse()?),
    ..Default::default()
});
connection.start();

let subscriber = tracing_subscriber::registry().with(layer);
tracing::subscriber::set_global_default(subscriber)?;
```

[DNSTAP]: https://dnstap.info/

## Protocol Buffers

`src/proto.rs` is generated from [`proto/dnstap.proto`] and checked in, so
building the crate does not require `protoc`. Regenerate it after changing the
schema:

```sh
cargo test -p hickory-dnstap generate_dnstap_proto -- --ignored
```

[`proto/dnstap.proto`]: proto/dnstap.proto
