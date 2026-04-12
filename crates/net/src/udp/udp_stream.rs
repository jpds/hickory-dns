// Copyright 2015-2018 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use core::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use core::pin::Pin;
use core::task::{Context, Poll};
use std::collections::HashSet;
use std::io;
#[cfg(unix)]
use std::os::unix::io::AsRawFd;
use std::sync::Arc;
#[cfg(all(feature = "tokio", unix))]
use tokio::io::Interest;

use async_trait::async_trait;
use futures_util::{
    future::{BoxFuture, Future},
    ready,
    stream::Stream,
};
use tracing::{debug, trace, warn};

use crate::error::NetError;
use crate::proto::op::SerialMessage;
use crate::runtime::{DnsUdpSocket, RuntimeProvider};
use crate::udp::MAX_RECEIVE_BUFFER_SIZE;
use crate::xfer::{BufDnsStreamHandle, StreamReceiver};

/// Trait for UdpSocket
#[async_trait]
pub trait UdpSocket: DnsUdpSocket {
    /// setups up a "client" udp connection that will only receive packets from the associated address
    async fn connect(addr: SocketAddr) -> io::Result<Self>;

    /// same as connect, but binds to the specified local address for sending address
    async fn connect_with_bind(addr: SocketAddr, bind_addr: SocketAddr) -> io::Result<Self>;

    /// a "server" UDP socket, that bind to the local listening address, and unbound remote address (can receive from anything)
    async fn bind(addr: SocketAddr) -> io::Result<Self>;
}

/// A UDP stream of DNS binary packets
#[must_use = "futures do nothing unless polled"]
pub struct UdpStream<P: RuntimeProvider> {
    socket: P::Udp,
    outbound_messages: StreamReceiver,
}

impl<P: RuntimeProvider> UdpStream<P> {
    /// This method is intended for client connections, see [`Self::with_bound`] for a method better
    ///  for straight listening. It is expected that the resolver wrapper will be responsible for
    ///  creating and managing new UdpStreams such that each new client would have a random port
    ///  (reduce chance of cache poisoning). This will return a randomly assigned local port, unless
    ///  a nonzero port number is specified in `bind_addr`.
    ///
    /// # Arguments
    ///
    /// * `remote_addr` - socket address for the remote connection (used to determine IPv4 or IPv6)
    /// * `bind_addr` - optional local socket address to connect from (if a nonzero port number is
    ///   specified, it will be used instead of randomly selecting a port)
    /// * `os_port_selection` - Boolean parameter to specify whether to use the operating system's
    ///   standard UDP port selection logic instead of Hickory's logic to
    ///   securely select a random source port. We do not recommend using
    ///   this option unless absolutely necessary, as the operating system
    ///   may select ephemeral ports from a smaller range than Hickory, which
    ///   can make response poisoning attacks easier to conduct. Some
    ///   operating systems (notably, Windows) might display a user-prompt to
    ///   allow a Hickory-specified port to be used, and setting this option
    ///   will prevent those prompts from being displayed. If os_port_selection
    ///   is true, avoid_local_udp_ports will be ignored.
    /// * `provider` - async runtime provider, for I/O and timers
    ///
    /// # Return
    ///
    /// A tuple of a Future of a Stream which will handle sending and receiving messages, and a
    ///  handle which can be used to send messages into the stream.
    pub fn new(
        remote_addr: SocketAddr,
        bind_addr: Option<SocketAddr>,
        avoid_local_ports: Option<Arc<HashSet<u16>>>,
        os_port_selection: bool,
        provider: P,
    ) -> (
        BoxFuture<'static, Result<Self, NetError>>,
        BufDnsStreamHandle,
    ) {
        let (message_sender, outbound_messages) = BufDnsStreamHandle::new(remote_addr);

        // constructs a future for getting the next randomly bound port to a UdpSocket
        let next_socket = NextRandomUdpSocket::new(
            remote_addr,
            bind_addr,
            avoid_local_ports.unwrap_or_default(),
            os_port_selection,
            provider,
        );

        // This set of futures collapses the next udp socket into a stream which can be used for
        //  sending and receiving udp packets.
        let stream = Box::pin(async {
            Ok(Self {
                socket: next_socket.await?,
                outbound_messages,
            })
        });

        (stream, message_sender)
    }
}

impl<P: RuntimeProvider> UdpStream<P> {
    /// Initialize the Stream with an already bound socket. Generally this should be only used for
    ///  server listening sockets. See [`Self::new`] for a client oriented socket. Specifically,
    ///  this requires there is already a bound socket, whereas `new` makes sure to randomize ports
    ///  for additional cache poison prevention.
    ///
    /// # Arguments
    ///
    /// * `socket` - an already bound UDP socket
    /// * `remote_addr` - remote side of this connection
    ///
    /// # Return
    ///
    /// A tuple of a Stream which will handle sending and receiving messages, and a handle which can
    ///  be used to send messages into the stream.
    pub fn with_bound(socket: P::Udp, remote_addr: SocketAddr) -> (Self, BufDnsStreamHandle) {
        socket.enable_pktinfo();
        let (message_sender, outbound_messages) = BufDnsStreamHandle::new(remote_addr);
        let stream = Self {
            socket,
            outbound_messages,
        };

        (stream, message_sender)
    }

    #[cfg(all(feature = "tokio", feature = "mdns"))]
    pub(crate) fn from_parts(socket: P::Udp, outbound_messages: StreamReceiver) -> Self {
        Self {
            socket,
            outbound_messages,
        }
    }
}

impl<P: RuntimeProvider> UdpStream<P> {
    fn pollable_split(&mut self) -> (&mut P::Udp, &mut StreamReceiver) {
        (&mut self.socket, &mut self.outbound_messages)
    }
}

impl<P: RuntimeProvider> Stream for UdpStream<P> {
    type Item = Result<SerialMessage, io::Error>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let (socket, outbound_messages) = self.pollable_split();
        let socket = Pin::new(socket);
        let mut outbound_messages = Pin::new(outbound_messages);

        // this will not accept incoming data while there is data to send
        //  makes this self throttling.
        while let Poll::Ready(Some(message)) = outbound_messages.as_mut().poll_peek(cx) {
            // first try to send
            let addr = message.addr();
            let local_ip = message.local_addr();

            // this will return if not ready,
            //   meaning that sending will be preferred over receiving...

            // TODO: shouldn't this return the error to send to the sender?
            if let Err(e) =
                ready!(socket.poll_send_to_with_src(cx, message.bytes(), addr, local_ip))
            {
                // Drop the UDP packet and continue
                warn!(
                    "error sending message to {} on udp_socket, dropping response: {}",
                    addr, e
                );
            }

            // message sent, need to pop the message
            assert!(outbound_messages.as_mut().poll_next(cx).is_ready());
        }

        // For QoS, this will only accept one message and output that
        // receive all inbound messages

        // TODO: this should match edns settings
        let mut buf = [0u8; MAX_RECEIVE_BUFFER_SIZE];
        let (len, src, dst_ip) = ready!(socket.poll_recv_from_with_dst(cx, &mut buf))?;

        let mut serial_message = SerialMessage::new(buf[..len].to_vec(), src);
        if let Some(ip) = dst_ip {
            serial_message.set_local_addr(ip);
        }
        Poll::Ready(Some(Ok(serial_message)))
    }
}

#[must_use = "futures do nothing unless polled"]
pub(crate) struct NextRandomUdpSocket<P: RuntimeProvider> {
    name_server: SocketAddr,
    bind_address: SocketAddr,
    provider: P,
    /// Number of unsuccessful attempts to pick a port.
    attempted: usize,
    #[allow(clippy::type_complexity)]
    future: Option<Pin<Box<dyn Send + Future<Output = Result<P::Udp, NetError>>>>>,
    avoid_local_ports: Arc<HashSet<u16>>,
    os_port_selection: bool,
}

impl<P: RuntimeProvider> NextRandomUdpSocket<P> {
    /// Creates a future for randomly binding to a local socket address for client connections,
    /// if no port is specified.
    ///
    /// If a port is specified in the bind address it is used.
    pub(crate) fn new(
        name_server: SocketAddr,
        bind_addr: Option<SocketAddr>,
        avoid_local_ports: Arc<HashSet<u16>>,
        os_port_selection: bool,
        provider: P,
    ) -> Self {
        let bind_address = match bind_addr {
            Some(ba) => ba,
            None => match name_server {
                SocketAddr::V4(..) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
                SocketAddr::V6(..) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
            },
        };

        Self {
            name_server,
            bind_address,
            provider,
            attempted: 0,
            future: None,
            avoid_local_ports,
            os_port_selection,
        }
    }
}

impl<P: RuntimeProvider> Future for NextRandomUdpSocket<P> {
    type Output = Result<P::Udp, NetError>;

    /// polls until there is an available next random UDP port,
    /// if no port has been specified in bind_addr.
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        loop {
            this.future = match this.future.take() {
                Some(mut future) => match future.as_mut().poll(cx) {
                    Poll::Ready(Ok(socket)) => {
                        debug!("created socket successfully");
                        return Poll::Ready(Ok(socket));
                    }
                    Poll::Ready(Err(NetError::Io(io)))
                        if matches!(
                            io.kind(),
                            io::ErrorKind::PermissionDenied | io::ErrorKind::AddrInUse
                        ) && this.attempted < ATTEMPT_RANDOM + 1 =>
                    {
                        debug!("unable to bind port, attempt: {}: {io}", this.attempted);
                        this.attempted += 1;
                        None
                    }
                    Poll::Ready(Err(err)) => {
                        debug!("failed to bind port: {err}");
                        return Poll::Ready(Err(err));
                    }
                    Poll::Pending => {
                        debug!("unable to bind port, attempt: {}", this.attempted);
                        this.future = Some(future);
                        return Poll::Pending;
                    }
                },
                None => {
                    let mut bind_addr = this.bind_address;

                    if !this.os_port_selection && bind_addr.port() == 0 {
                        while this.attempted < ATTEMPT_RANDOM {
                            // Per RFC 6056 Section 3.2:
                            //
                            // As mentioned in Section 2.1, the dynamic ports consist of the range
                            // 49152-65535.  However, ephemeral port selection algorithms should use
                            // the whole range 1024-65535.
                            let port = rand::random_range(1024..=u16::MAX);
                            if this.avoid_local_ports.contains(&port) {
                                // Count this against the total number of attempts to pick a port.
                                // RFC 6056 Section 3.3.2 notes that this algorithm should find a
                                // suitable port in one or two attempts with high probability in
                                // common scenarios. If `avoid_local_ports` is pathologically large,
                                // then incrementing the counter here will prevent an infinite loop.
                                this.attempted += 1;
                                continue;
                            } else {
                                bind_addr = SocketAddr::new(bind_addr.ip(), port);
                                break;
                            }
                        }
                    }

                    trace!(port = bind_addr.port(), "binding UDP socket");
                    let future = this.provider.bind_udp(bind_addr, this.name_server);
                    Some(Box::pin(async move { Ok(future.await?) }))
                }
            }
        }
    }
}

const ATTEMPT_RANDOM: usize = 10;

#[cfg(feature = "tokio")]
#[async_trait]
impl UdpSocket for tokio::net::UdpSocket {
    /// sets up up a "client" udp connection that will only receive packets from the associated address
    ///
    /// if the addr is ipv4 then it will bind local addr to 0.0.0.0:0, ipv6 \[::\]0
    async fn connect(addr: SocketAddr) -> io::Result<Self> {
        let bind_addr: SocketAddr = match addr {
            SocketAddr::V4(_addr) => (Ipv4Addr::UNSPECIFIED, 0).into(),
            SocketAddr::V6(_addr) => (Ipv6Addr::UNSPECIFIED, 0).into(),
        };

        Self::connect_with_bind(addr, bind_addr).await
    }

    /// same as connect, but binds to the specified local address for sending address
    async fn connect_with_bind(_addr: SocketAddr, bind_addr: SocketAddr) -> io::Result<Self> {
        let socket = Self::bind(bind_addr).await?;

        // TODO: research connect more, it appears to break UDP receiving tests, etc...
        // socket.connect(addr).await?;

        Ok(socket)
    }

    async fn bind(addr: SocketAddr) -> io::Result<Self> {
        Self::bind(addr).await
    }
}

#[cfg(feature = "tokio")]
#[async_trait]
impl DnsUdpSocket for tokio::net::UdpSocket {
    type Time = crate::runtime::TokioTime;

    fn poll_recv_from(
        &self,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<(usize, SocketAddr)>> {
        let mut buf = tokio::io::ReadBuf::new(buf);
        let addr = ready!(Self::poll_recv_from(self, cx, &mut buf))?;
        let len = buf.filled().len();

        Poll::Ready(Ok((len, addr)))
    }

    fn poll_send_to(
        &self,
        cx: &mut Context<'_>,
        buf: &[u8],
        target: SocketAddr,
    ) -> Poll<io::Result<usize>> {
        Self::poll_send_to(self, cx, buf, target)
    }

    #[cfg(unix)]
    fn enable_pktinfo(&self) {
        pktinfo::enable(self.as_raw_fd());
    }

    #[cfg(unix)]
    fn poll_recv_from_with_dst(
        &self,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<(usize, SocketAddr, Option<IpAddr>)>> {
        loop {
            ready!(self.poll_recv_ready(cx))?;
            match self.try_io(Interest::READABLE, || pktinfo::recv(self.as_raw_fd(), buf)) {
                Ok(result) => return Poll::Ready(Ok(result)),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                Err(e) => return Poll::Ready(Err(e)),
            }
        }
    }

    #[cfg(unix)]
    fn poll_send_to_with_src(
        &self,
        cx: &mut Context<'_>,
        buf: &[u8],
        target: SocketAddr,
        local_ip: Option<IpAddr>,
    ) -> Poll<io::Result<usize>> {
        let Some(src_ip) = local_ip else {
            return self.poll_send_to(cx, buf, target);
        };
        loop {
            ready!(self.poll_send_ready(cx))?;
            match self.try_io(Interest::WRITABLE, || {
                pktinfo::send(self.as_raw_fd(), buf, target, src_ip)
            }) {
                Ok(n) => return Poll::Ready(Ok(n)),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                Err(e) => return Poll::Ready(Err(e)),
            }
        }
    }
}

/// Platform-specific pktinfo helpers for pinning UDP source addresses.
///
/// On Unix, DNS servers bound to `::` / `0.0.0.0` would otherwise let the
/// kernel pick a source address for responses, which may differ from the
/// address the client queried. Using `recvmsg`/`sendmsg` with pktinfo control
/// messages ensures the response comes from the same address the query arrived at.
#[cfg(all(feature = "tokio", unix))]
mod pktinfo {
    use core::mem::{self, size_of};
    use core::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
    use std::io;
    use std::os::unix::io::RawFd;

    /// Enable `IPV6_RECVPKTINFO` (and `IP_PKTINFO` on Linux) on the socket.
    ///
    /// Errors from setsockopt are intentionally ignored: the socket may be
    /// IPv4-only (causing the IPv6 call to fail) or IPv6-only (causing the IPv4
    /// call to fail). In either case the missing option simply means that family's
    /// dst address will be unavailable, and the fallback is a regular sendto.
    pub(super) fn enable(fd: RawFd) {
        let one: libc::c_int = 1;
        // Safety: fd comes from AsRawFd on a live socket and is valid for the duration of this call.
        unsafe {
            libc::setsockopt(
                fd,
                libc::IPPROTO_IPV6,
                libc::IPV6_RECVPKTINFO,
                (&one as *const libc::c_int).cast(),
                size_of::<libc::c_int>() as libc::socklen_t,
            );
            #[cfg(target_os = "linux")]
            libc::setsockopt(
                fd,
                libc::IPPROTO_IP,
                libc::IP_PKTINFO,
                (&one as *const libc::c_int).cast(),
                size_of::<libc::c_int>() as libc::socklen_t,
            );
        }
    }

    /// Receive a UDP datagram via `recvmsg`, returning `(len, src, dst)`.
    ///
    /// `dst` is `Some` when a pktinfo control message is present (i.e. after
    /// `enable` has been called on this socket).
    pub(super) fn recv(
        fd: RawFd,
        buf: &mut [u8],
    ) -> io::Result<(usize, SocketAddr, Option<IpAddr>)> {
        // Safety: sockaddr_storage and msghdr are C structs with no invalid bit patterns; zeroed init is valid.
        let mut src: libc::sockaddr_storage = unsafe { mem::zeroed() };
        let mut iov = libc::iovec {
            iov_base: buf.as_mut_ptr().cast(),
            iov_len: buf.len(),
        };
        let mut cmsg_buf = [0u8; 256];
        let mut msg: libc::msghdr = unsafe { mem::zeroed() };
        msg.msg_name = (&mut src as *mut libc::sockaddr_storage).cast();
        msg.msg_namelen = size_of::<libc::sockaddr_storage>() as _;
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1 as _;
        msg.msg_control = cmsg_buf.as_mut_ptr().cast();
        msg.msg_controllen = cmsg_buf.len() as _;

        // Safety: fd is valid; msg points to live, correctly sized buffers set up above.
        let n = unsafe { libc::recvmsg(fd, &mut msg, 0) };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }

        let src_addr = sockaddr_to_socket_addr(&src, msg.msg_namelen)?;
        let dst_ip = parse_dst_from_cmsg(&msg);
        Ok((n as usize, src_addr, dst_ip))
    }

    /// Send a UDP datagram via `sendmsg` with a pktinfo control message that
    /// sets `src_ip` as the source address of the outgoing packet.
    ///
    /// Falls back to a plain `sendto` when the address families of `target`
    /// and `src_ip` do not match.
    pub(super) fn send(
        fd: RawFd,
        buf: &[u8],
        target: SocketAddr,
        src_ip: IpAddr,
    ) -> io::Result<usize> {
        match (target, src_ip) {
            (SocketAddr::V6(dst), IpAddr::V6(src)) => send_v6(fd, buf, dst, src),
            #[cfg(target_os = "linux")]
            (SocketAddr::V4(dst), IpAddr::V4(src)) => send_v4(fd, buf, dst, src),
            // Dual-stack: IPv4 client on an IPv6 socket. The target is an
            // IPv4-mapped IPv6 address but pktinfo reported a plain IPv4 dst.
            // Map the source to IPv6 so we can use IPV6_PKTINFO.
            (SocketAddr::V6(dst), IpAddr::V4(src)) => send_v6(fd, buf, dst, src.to_ipv6_mapped()),
            _ => send_plain(fd, buf, target),
        }
    }

    fn send_v6(fd: RawFd, buf: &[u8], dst: SocketAddrV6, src: Ipv6Addr) -> io::Result<usize> {
        let dst_sa = libc::sockaddr_in6 {
            sin6_family: libc::AF_INET6 as _,
            sin6_port: dst.port().to_be(),
            sin6_flowinfo: dst.flowinfo(),
            sin6_addr: libc::in6_addr {
                s6_addr: dst.ip().octets(),
            },
            sin6_scope_id: dst.scope_id(),
        };
        let pktinfo = libc::in6_pktinfo {
            ipi6_addr: libc::in6_addr {
                s6_addr: src.octets(),
            },
            ipi6_ifindex: 0,
        };
        let mut cmsg_buf = [0u8; 64];
        let cmsg_space = unsafe { libc::CMSG_SPACE(size_of::<libc::in6_pktinfo>() as _) as usize };
        let iov = libc::iovec {
            iov_base: buf.as_ptr() as *mut _,
            iov_len: buf.len(),
        };
        // Safety: msghdr is a C struct with no invalid bit patterns; zeroed init is valid.
        let mut msg: libc::msghdr = unsafe { mem::zeroed() };
        msg.msg_name = (&dst_sa as *const libc::sockaddr_in6).cast::<libc::c_void>() as *mut _;
        msg.msg_namelen = size_of::<libc::sockaddr_in6>() as _;
        msg.msg_iov = &iov as *const _ as *mut _;
        msg.msg_iovlen = 1 as _;
        msg.msg_control = cmsg_buf.as_mut_ptr().cast();
        msg.msg_controllen = cmsg_space as _;

        // Safety: msg_controllen == CMSG_SPACE(size_of::<in6_pktinfo>()) guarantees CMSG_FIRSTHDR is non-null.
        // CMSG_DATA points into cmsg_buf, which is sized to hold exactly one in6_pktinfo.
        unsafe {
            let cmsg = libc::CMSG_FIRSTHDR(&msg);
            (*cmsg).cmsg_level = libc::IPPROTO_IPV6;
            (*cmsg).cmsg_type = libc::IPV6_PKTINFO;
            (*cmsg).cmsg_len = libc::CMSG_LEN(size_of::<libc::in6_pktinfo>() as _) as _;
            (libc::CMSG_DATA(cmsg) as *mut libc::in6_pktinfo).write(pktinfo);

            let n = libc::sendmsg(fd, &msg, 0);
            if n < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(n as usize)
        }
    }

    #[cfg(target_os = "linux")]
    fn send_v4(fd: RawFd, buf: &[u8], dst: SocketAddrV4, src: Ipv4Addr) -> io::Result<usize> {
        let dst_sa = libc::sockaddr_in {
            sin_family: libc::AF_INET as _,
            sin_port: dst.port().to_be(),
            sin_addr: libc::in_addr {
                s_addr: u32::from_ne_bytes(dst.ip().octets()),
            },
            sin_zero: [0; 8],
        };
        let pktinfo = libc::in_pktinfo {
            ipi_ifindex: 0,
            ipi_spec_dst: libc::in_addr {
                s_addr: u32::from_ne_bytes(src.octets()),
            },
            ipi_addr: libc::in_addr { s_addr: 0 },
        };
        let mut cmsg_buf = [0u8; 64];
        let cmsg_space = unsafe { libc::CMSG_SPACE(size_of::<libc::in_pktinfo>() as _) as usize };
        let iov = libc::iovec {
            iov_base: buf.as_ptr() as *mut _,
            iov_len: buf.len(),
        };
        // Safety: msghdr is a C struct with no invalid bit patterns; zeroed init is valid.
        let mut msg: libc::msghdr = unsafe { mem::zeroed() };
        msg.msg_name = (&dst_sa as *const libc::sockaddr_in).cast::<libc::c_void>() as *mut _;
        msg.msg_namelen = size_of::<libc::sockaddr_in>() as _;
        msg.msg_iov = &iov as *const _ as *mut _;
        msg.msg_iovlen = 1 as _;
        msg.msg_control = cmsg_buf.as_mut_ptr().cast();
        msg.msg_controllen = cmsg_space as _;

        // Safety: msg_controllen == CMSG_SPACE(size_of::<in_pktinfo>()) guarantees CMSG_FIRSTHDR is non-null.
        // CMSG_DATA points into cmsg_buf, which is sized to hold exactly one in_pktinfo.
        unsafe {
            let cmsg = libc::CMSG_FIRSTHDR(&msg);
            (*cmsg).cmsg_level = libc::IPPROTO_IP;
            (*cmsg).cmsg_type = libc::IP_PKTINFO;
            (*cmsg).cmsg_len = libc::CMSG_LEN(size_of::<libc::in_pktinfo>() as _) as _;
            (libc::CMSG_DATA(cmsg) as *mut libc::in_pktinfo).write(pktinfo);

            let n = libc::sendmsg(fd, &msg, 0);
            if n < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(n as usize)
        }
    }

    /// Plain sendto without pktinfo. Used when source address pinning is not
    /// possible (e.g. mismatched address families on non-Linux).
    fn send_plain(fd: RawFd, buf: &[u8], target: SocketAddr) -> io::Result<usize> {
        // Safety: sockaddr structs live on the stack for the duration of sendto.
        let n = unsafe {
            match target {
                SocketAddr::V4(v4) => {
                    let dst_sa = libc::sockaddr_in {
                        sin_family: libc::AF_INET as _,
                        sin_port: v4.port().to_be(),
                        sin_addr: libc::in_addr {
                            s_addr: u32::from_ne_bytes(v4.ip().octets()),
                        },
                        sin_zero: [0; 8],
                    };
                    libc::sendto(
                        fd,
                        buf.as_ptr().cast(),
                        buf.len(),
                        0,
                        (&dst_sa as *const libc::sockaddr_in).cast(),
                        size_of::<libc::sockaddr_in>() as _,
                    )
                }
                SocketAddr::V6(v6) => {
                    let dst_sa = libc::sockaddr_in6 {
                        sin6_family: libc::AF_INET6 as _,
                        sin6_port: v6.port().to_be(),
                        sin6_flowinfo: v6.flowinfo(),
                        sin6_addr: libc::in6_addr {
                            s6_addr: v6.ip().octets(),
                        },
                        sin6_scope_id: v6.scope_id(),
                    };
                    libc::sendto(
                        fd,
                        buf.as_ptr().cast(),
                        buf.len(),
                        0,
                        (&dst_sa as *const libc::sockaddr_in6).cast(),
                        size_of::<libc::sockaddr_in6>() as _,
                    )
                }
            }
        };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(n as usize)
    }

    fn parse_dst_from_cmsg(msg: &libc::msghdr) -> Option<IpAddr> {
        // Safety: msg was filled by recvmsg; msg_control and msg_controllen are valid.
        unsafe {
            let mut cmsg = libc::CMSG_FIRSTHDR(msg);
            while !cmsg.is_null() {
                let hdr = &*cmsg;
                if hdr.cmsg_level == libc::IPPROTO_IPV6 as _
                    && hdr.cmsg_type == libc::IPV6_PKTINFO as _
                    && hdr.cmsg_len >= libc::CMSG_LEN(size_of::<libc::in6_pktinfo>() as _) as _
                {
                    let info = &*(libc::CMSG_DATA(cmsg) as *const libc::in6_pktinfo);
                    return Some(IpAddr::V6(Ipv6Addr::from(info.ipi6_addr.s6_addr)));
                }
                #[cfg(target_os = "linux")]
                if hdr.cmsg_level == libc::IPPROTO_IP as _
                    && hdr.cmsg_type == libc::IP_PKTINFO as _
                    && hdr.cmsg_len >= libc::CMSG_LEN(size_of::<libc::in_pktinfo>() as _) as _
                {
                    let info = &*(libc::CMSG_DATA(cmsg) as *const libc::in_pktinfo);
                    return Some(IpAddr::V4(Ipv4Addr::from(
                        info.ipi_addr.s_addr.to_ne_bytes(),
                    )));
                }
                cmsg = libc::CMSG_NXTHDR(msg, cmsg);
            }
        }
        None
    }

    fn sockaddr_to_socket_addr(
        storage: &libc::sockaddr_storage,
        len: libc::socklen_t,
    ) -> io::Result<SocketAddr> {
        match storage.ss_family as libc::c_int {
            libc::AF_INET => {
                if (len as usize) < size_of::<libc::sockaddr_in>() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "IPv4 sockaddr too short",
                    ));
                }
                // Safety: ss_family == AF_INET guarantees the union holds a sockaddr_in.
                let addr = unsafe { &*(storage as *const _ as *const libc::sockaddr_in) };
                Ok(SocketAddr::V4(SocketAddrV4::new(
                    // s_addr bytes in memory are network byte order; read them directly.
                    Ipv4Addr::from(addr.sin_addr.s_addr.to_ne_bytes()),
                    u16::from_be(addr.sin_port),
                )))
            }
            libc::AF_INET6 => {
                if (len as usize) < size_of::<libc::sockaddr_in6>() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "IPv6 sockaddr too short",
                    ));
                }
                // Safety: ss_family == AF_INET6 guarantees the union holds a sockaddr_in6.
                let addr = unsafe { &*(storage as *const _ as *const libc::sockaddr_in6) };
                Ok(SocketAddr::V6(SocketAddrV6::new(
                    Ipv6Addr::from(addr.sin6_addr.s6_addr),
                    u16::from_be(addr.sin6_port),
                    addr.sin6_flowinfo,
                    addr.sin6_scope_id,
                )))
            }
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unsupported address family in recvmsg",
            )),
        }
    }
}

#[cfg(test)]
#[cfg(feature = "tokio")]
mod tests {
    use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use test_support::subscribe;

    use crate::{
        runtime::TokioRuntimeProvider,
        udp::tests::{next_random_socket_test, udp_stream_test},
    };

    #[tokio::test]
    async fn test_next_random_socket() {
        subscribe();
        let provider = TokioRuntimeProvider::new();
        next_random_socket_test(provider).await;
    }

    #[tokio::test]
    async fn test_udp_stream_ipv4() {
        subscribe();
        let provider = TokioRuntimeProvider::new();
        udp_stream_test(IpAddr::V4(Ipv4Addr::LOCALHOST), provider).await;
    }

    #[tokio::test]
    async fn test_udp_stream_ipv6() {
        subscribe();
        let provider = TokioRuntimeProvider::new();
        udp_stream_test(IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)), provider).await;
    }
}
