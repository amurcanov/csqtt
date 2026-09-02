// SPDX-FileCopyrightText: 2026 amurcanov
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

use super::*;
use crate::stun_codec::{Class as StunClass, Message as StunMessage};
use crate::{
    auth::TurnCredentials,
    dispatcher::Dispatcher,
    events::Events,
    obfs::ObfsMode,
    repair::RepairState,
    session::{
        ConfigDeliveryState, SessionConfig, SessionRuntime, ShutdownCoordinator, run_session,
    },
    stats::Stats,
    wrap::derive_wrap_key,
};
use hmac::{Hmac, Mac};
use md5::{Digest, Md5};
use sha1::Sha1;
#[cfg(unix)]
use std::collections::VecDeque;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicU64, Ordering};
#[cfg(unix)]
use std::{
    fs::File,
    os::{
        fd::{FromRawFd, IntoRawFd},
        unix::net::UnixDatagram as StdUnixDatagram,
    },
};
use tokio::sync::oneshot;
#[cfg(unix)]
use tokio::time::Instant;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
};
use tokio_util::sync::CancellationToken;

const STUN_COOKIE: u32 = 0x2112_a442;
const ALLOCATE_REQUEST: u16 = 0x0003;
const ALLOCATE_SUCCESS: u16 = 0x0103;
const ALLOCATE_ERROR: u16 = 0x0113;
const REFRESH_REQUEST: u16 = 0x0004;
const REFRESH_SUCCESS: u16 = 0x0104;
const CREATE_PERMISSION_REQUEST: u16 = 0x0008;
const CREATE_PERMISSION_SUCCESS: u16 = 0x0108;
const CHANNEL_BIND_REQUEST: u16 = 0x0009;
const CHANNEL_BIND_SUCCESS: u16 = 0x0109;
const CHANNEL_BIND_ERROR: u16 = 0x0119;
const ATTR_USERNAME: u16 = 0x0006;
const ATTR_MESSAGE_INTEGRITY: u16 = 0x0008;
const ATTR_ERROR_CODE: u16 = 0x0009;
const ATTR_CHANNEL_NUMBER: u16 = 0x000c;
const ATTR_LIFETIME: u16 = 0x000d;
const ATTR_XOR_PEER_ADDRESS: u16 = 0x0012;
const ATTR_REALM: u16 = 0x0014;
const ATTR_NONCE: u16 = 0x0015;
const ATTR_XOR_RELAYED_ADDRESS: u16 = 0x0016;
const ATTR_FINGERPRINT: u16 = 0x8028;
const FINGERPRINT_XOR: u32 = 0x5354_554e;
const USERNAME: &str = "user";
const PASSWORD: &str = "pass";
const REALM: &str = "realm";
const NONCE: &str = "nonce-1";

struct MessageBuilder {
    bytes: Vec<u8>,
    transaction: [u8; 12],
}

impl MessageBuilder {
    fn new(kind: u16, transaction: [u8; 12]) -> Self {
        let mut bytes = Vec::with_capacity(256);
        bytes.extend_from_slice(&kind.to_be_bytes());
        bytes.extend_from_slice(&0u16.to_be_bytes());
        bytes.extend_from_slice(&STUN_COOKIE.to_be_bytes());
        bytes.extend_from_slice(&transaction);
        Self { bytes, transaction }
    }

    fn attribute(&mut self, kind: u16, value: &[u8]) {
        self.bytes.extend_from_slice(&kind.to_be_bytes());
        self.bytes
            .extend_from_slice(&(value.len() as u16).to_be_bytes());
        self.bytes.extend_from_slice(value);
        while !self.bytes.len().is_multiple_of(4) {
            self.bytes.push(0);
        }
    }

    fn xor_address(&mut self, kind: u16, address: SocketAddr) {
        let encoded = encode_xor_address(address, &self.transaction);
        self.attribute(kind, &encoded);
    }

    fn finish(mut self) -> Vec<u8> {
        self.add_fingerprint();
        self.bytes
    }

    fn finish_authenticated(mut self, key: &[u8; 16]) -> Vec<u8> {
        let signed_length = (self.bytes.len() - 20 + 24) as u16;
        self.bytes[2..4].copy_from_slice(&signed_length.to_be_bytes());
        let mut mac = <Hmac<Sha1> as hmac::digest::KeyInit>::new_from_slice(key).unwrap();
        mac.update(&self.bytes);
        let integrity = mac.finalize().into_bytes();
        self.attribute(ATTR_MESSAGE_INTEGRITY, &integrity);
        self.add_fingerprint();
        self.bytes
    }

    fn add_fingerprint(&mut self) {
        let final_length = (self.bytes.len() - 20 + 8) as u16;
        self.bytes[2..4].copy_from_slice(&final_length.to_be_bytes());
        let fingerprint = crc32fast::hash(&self.bytes) ^ FINGERPRINT_XOR;
        self.attribute(ATTR_FINGERPRINT, &fingerprint.to_be_bytes());
    }
}

fn long_term_key() -> [u8; 16] {
    let mut digest = Md5::new();
    digest.update(USERNAME.as_bytes());
    digest.update(b":");
    digest.update(REALM.as_bytes());
    digest.update(b":");
    digest.update(PASSWORD.as_bytes());
    digest.finalize().into()
}

fn encode_xor_address(address: SocketAddr, transaction: &[u8; 12]) -> Vec<u8> {
    let mut value = Vec::with_capacity(if address.is_ipv4() { 8 } else { 20 });
    value.push(0);
    value.push(if address.is_ipv4() { 1 } else { 2 });
    value.extend_from_slice(&(address.port() ^ (STUN_COOKIE >> 16) as u16).to_be_bytes());
    match address.ip() {
        IpAddr::V4(ip) => {
            value.extend_from_slice(&(u32::from_be_bytes(ip.octets()) ^ STUN_COOKIE).to_be_bytes());
        }
        IpAddr::V6(ip) => {
            let mut mask = [0u8; 16];
            mask[..4].copy_from_slice(&STUN_COOKIE.to_be_bytes());
            mask[4..].copy_from_slice(transaction);
            for (byte, key) in ip.octets().iter().zip(mask) {
                value.push(byte ^ key);
            }
        }
    }
    value
}

fn decode_xor_address(value: &[u8], transaction: &[u8; 12]) -> SocketAddr {
    assert!(value.len() >= 4);
    let port = u16::from_be_bytes([value[2], value[3]]) ^ (STUN_COOKIE >> 16) as u16;
    let family = u16::from_be_bytes([value[0], value[1]]);
    let ip = match (family, value.len()) {
        (1, 8) => {
            let encoded = u32::from_be_bytes(value[4..8].try_into().unwrap());
            IpAddr::V4((encoded ^ STUN_COOKIE).into())
        }
        (2, 20) => {
            let mut mask = [0u8; 16];
            mask[..4].copy_from_slice(&STUN_COOKIE.to_be_bytes());
            mask[4..].copy_from_slice(transaction);
            let mut bytes = [0u8; 16];
            for index in 0..16 {
                bytes[index] = value[4 + index] ^ mask[index];
            }
            IpAddr::V6(bytes.into())
        }
        _ => panic!("invalid XOR address"),
    };
    SocketAddr::new(ip, port)
}

fn challenge_response(transaction: [u8; 12]) -> Vec<u8> {
    let mut response = MessageBuilder::new(ALLOCATE_ERROR, transaction);
    response.attribute(ATTR_ERROR_CODE, &[0, 0, 4, 1]);
    response.attribute(ATTR_REALM, REALM.as_bytes());
    response.attribute(ATTR_NONCE, NONCE.as_bytes());
    response.finish()
}

fn authenticated_error(kind: u16, transaction: [u8; 12], code: u16) -> Vec<u8> {
    let mut response = MessageBuilder::new(kind, transaction);
    let reason = format!("TURN {code}");
    let mut value = vec![0, 0, (code / 100) as u8, (code % 100) as u8];
    value.extend_from_slice(reason.as_bytes());
    response.attribute(ATTR_ERROR_CODE, &value);
    response.finish_authenticated(&long_term_key())
}

fn allocate_success(transaction: [u8; 12], relay: SocketAddr) -> Vec<u8> {
    let mut response = MessageBuilder::new(ALLOCATE_SUCCESS, transaction);
    response.xor_address(ATTR_XOR_RELAYED_ADDRESS, relay);
    response.attribute(ATTR_LIFETIME, &600u32.to_be_bytes());
    response.finish_authenticated(&long_term_key())
}

fn empty_authenticated_success(kind: u16, transaction: [u8; 12]) -> Vec<u8> {
    MessageBuilder::new(kind, transaction).finish_authenticated(&long_term_key())
}

fn refresh_zero_success(transaction: [u8; 12]) -> Vec<u8> {
    let mut response = MessageBuilder::new(REFRESH_SUCCESS, transaction);
    response.attribute(ATTR_LIFETIME, &0u32.to_be_bytes());
    response.finish_authenticated(&long_term_key())
}

fn assert_fingerprint(message: &StunMessage<'_>) {
    assert_eq!(message.fingerprint_valid(), Some(true));
    let fingerprint = message.attribute(ATTR_FINGERPRINT).unwrap();
    assert_eq!(fingerprint.value.len(), 4);
}

fn assert_message_integrity(wire: &[u8], key: &[u8; 16]) {
    let message = StunMessage::decode(wire).unwrap();
    let integrity = message.attribute(ATTR_MESSAGE_INTEGRITY).unwrap();
    assert_eq!(integrity.value.len(), 20);
    let mut signed = wire[..integrity.header_start].to_vec();
    let signed_length = (integrity.header_start + 24 - 20) as u16;
    signed[2..4].copy_from_slice(&signed_length.to_be_bytes());
    let mut mac = <Hmac<Sha1> as hmac::digest::KeyInit>::new_from_slice(key).unwrap();
    mac.update(&signed);
    mac.verify_slice(integrity.value).unwrap();
}

fn assert_authenticated_request(wire: &[u8], method: u16) -> StunMessage<'_> {
    let message = StunMessage::decode(wire).unwrap();
    assert_eq!(message.class(), StunClass::Request);
    assert_eq!(message.method(), method);
    assert_fingerprint(&message);
    assert_eq!(
        message.attribute(ATTR_USERNAME).unwrap().value,
        USERNAME.as_bytes()
    );
    assert_eq!(
        message.attribute(ATTR_REALM).unwrap().value,
        REALM.as_bytes()
    );
    assert_eq!(
        message.attribute(ATTR_NONCE).unwrap().value,
        NONCE.as_bytes()
    );
    assert_message_integrity(wire, &long_term_key());
    message
}

fn attribute_u32(message: &StunMessage<'_>, kind: u16) -> u32 {
    let value: [u8; 4] = message.attribute(kind).unwrap().value.try_into().unwrap();
    u32::from_be_bytes(value)
}

fn channel_number(message: &StunMessage<'_>) -> u16 {
    let value = message.attribute(ATTR_CHANNEL_NUMBER).unwrap().value;
    assert_eq!(value.len(), 4);
    assert_eq!(&value[2..], &[0, 0]);
    let channel = u16::from_be_bytes([value[0], value[1]]);
    assert!((0x4000..=0x7fff).contains(&channel));
    channel
}

fn channel_data(channel: u16, payload: &[u8]) -> Vec<u8> {
    let mut wire = Vec::with_capacity(4 + payload.len() + 3);
    wire.extend_from_slice(&channel.to_be_bytes());
    wire.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    wire.extend_from_slice(payload);
    while !wire.len().is_multiple_of(4) {
        wire.push(0);
    }
    wire
}

async fn recv_datagram(socket: &UdpSocket) -> (Vec<u8>, SocketAddr) {
    let mut buffer = [0u8; 4096];
    let (length, source) =
        tokio::time::timeout(Duration::from_secs(3), socket.recv_from(&mut buffer))
            .await
            .unwrap()
            .unwrap();
    (buffer[..length].to_vec(), source)
}

async fn recv_stream_message(stream: &mut TcpStream) -> Vec<u8> {
    let mut header = [0u8; 20];
    tokio::time::timeout(Duration::from_secs(3), stream.read_exact(&mut header))
        .await
        .unwrap()
        .unwrap();
    let attributes = u16::from_be_bytes([header[2], header[3]]) as usize;
    let mut wire = vec![0u8; 20 + attributes];
    wire[..20].copy_from_slice(&header);
    if attributes > 0 {
        stream.read_exact(&mut wire[20..]).await.unwrap();
    }
    wire
}

async fn recv_stream_channel_data(stream: &mut TcpStream) -> Vec<u8> {
    let mut header = [0u8; 4];
    tokio::time::timeout(Duration::from_secs(3), stream.read_exact(&mut header))
        .await
        .unwrap()
        .unwrap();
    let payload = u16::from_be_bytes([header[2], header[3]]) as usize;
    let length = 4 + payload;
    let padded = (length + 3) & !3;
    let mut wire = vec![0u8; padded];
    wire[..4].copy_from_slice(&header);
    if padded > 4 {
        stream.read_exact(&mut wire[4..]).await.unwrap();
    }
    wire
}

async fn receive_challenged_allocate(server: &UdpSocket, relay: SocketAddr) -> SocketAddr {
    let (first_wire, client) = recv_datagram(server).await;
    let first = StunMessage::decode(&first_wire).unwrap();
    assert_eq!(first.class(), StunClass::Request);
    assert_eq!(first.kind(), ALLOCATE_REQUEST);
    assert_eq!(first.method(), 3);
    assert_fingerprint(&first);
    assert!(first.attribute(ATTR_MESSAGE_INTEGRITY).is_none());
    server
        .send_to(&challenge_response(first.transaction()), client)
        .await
        .unwrap();

    let (authenticated_wire, authenticated_client) = recv_datagram(server).await;
    assert_eq!(authenticated_client, client);
    let authenticated = assert_authenticated_request(&authenticated_wire, 3);
    server
        .send_to(
            &allocate_success(authenticated.transaction(), relay),
            client,
        )
        .await
        .unwrap();
    client
}

async fn receive_create_permission(server: &UdpSocket, client: SocketAddr, peer: SocketAddr) {
    let (permission_wire, permission_client) = recv_datagram(server).await;
    assert_eq!(permission_client, client);
    let permission = assert_authenticated_request(&permission_wire, CREATE_PERMISSION_REQUEST);
    let encoded_peer = permission.attribute(ATTR_XOR_PEER_ADDRESS).unwrap();
    assert_eq!(
        decode_xor_address(encoded_peer.value, &permission.transaction()),
        peer
    );
    server
        .send_to(
            &empty_authenticated_success(CREATE_PERMISSION_SUCCESS, permission.transaction()),
            client,
        )
        .await
        .unwrap();
}

async fn connect(
    server: SocketAddr,
    peer: SocketAddr,
    pool: Arc<PacketPool>,
) -> Arc<TurnAllocation> {
    tokio::time::timeout(
        Duration::from_secs(5),
        TurnAllocation::connect(
            TurnConnectTarget {
                address: &server.to_string(),
                override_host: None,
                override_port: None,
                transport_mode: TurnTransportMode::Udp,
            },
            Arc::from(USERNAME),
            Arc::from(PASSWORD),
            peer,
            pool,
        ),
    )
    .await
    .unwrap()
    .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tcp_turn_transport_allocates_without_udp_fallback() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_address = listener.local_addr().unwrap();
    let relay: SocketAddr = "127.0.0.1:49009".parse().unwrap();
    let (data_tx, data_rx) = oneshot::channel();
    let server_task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let first = recv_stream_message(&mut stream).await;
        let initial = StunMessage::decode(&first).unwrap();
        assert_eq!(initial.class(), StunClass::Request);
        assert_eq!(initial.method(), ALLOCATE_REQUEST);
        stream
            .write_all(&challenge_response(initial.transaction()))
            .await
            .unwrap();
        let authenticated_wire = recv_stream_message(&mut stream).await;
        let authenticated = assert_authenticated_request(&authenticated_wire, ALLOCATE_REQUEST);
        stream
            .write_all(&allocate_success(authenticated.transaction(), relay))
            .await
            .unwrap();
        let permission_wire = recv_stream_message(&mut stream).await;
        let permission = assert_authenticated_request(&permission_wire, CREATE_PERMISSION_REQUEST);
        stream
            .write_all(&empty_authenticated_success(
                CREATE_PERMISSION_SUCCESS,
                permission.transaction(),
            ))
            .await
            .unwrap();
        let channel_wire = recv_stream_message(&mut stream).await;
        let channel_request = assert_authenticated_request(&channel_wire, CHANNEL_BIND_REQUEST);
        let channel = channel_number(&channel_request);
        stream
            .write_all(&empty_authenticated_success(
                CHANNEL_BIND_SUCCESS,
                channel_request.transaction(),
            ))
            .await
            .unwrap();
        let data = recv_stream_channel_data(&mut stream).await;
        assert_eq!(data, channel_data(channel, b"tcp-data"));
        data_tx.send(()).unwrap();
        let refresh_wire = recv_stream_message(&mut stream).await;
        let refresh = assert_authenticated_request(&refresh_wire, REFRESH_REQUEST);
        assert_eq!(attribute_u32(&refresh, ATTR_LIFETIME), 0);
        stream
            .write_all(&refresh_zero_success(refresh.transaction()))
            .await
            .unwrap();
    });
    let endpoint = format!("turn:127.0.0.1:{}?transport=tcp", server_address.port());
    let allocation = TurnAllocation::connect(
        TurnConnectTarget {
            address: &endpoint,
            override_host: None,
            override_port: None,
            transport_mode: TurnTransportMode::TcpTls,
        },
        Arc::from(USERNAME),
        Arc::from(PASSWORD),
        "127.0.0.1:39009".parse().unwrap(),
        PacketPool::new(4),
    )
    .await
    .unwrap();
    assert_eq!(allocation.local_addr(), relay);
    allocation.prepare_channel().await.unwrap();
    let pool = PacketPool::new(1);
    let mut packet = pool.acquire();
    packet.read_area()[..8].copy_from_slice(b"tcp-data");
    packet.set_read_len(8).unwrap();
    allocation.send_with_duplicate(packet, false).await.unwrap();
    tokio::time::timeout(Duration::from_secs(3), data_rx)
        .await
        .unwrap()
        .unwrap();
    allocation.deallocate().await;
    tokio::time::timeout(Duration::from_secs(3), server_task)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn authenticated_flow_survives_pool_deficit_and_keeps_channel_data_zero_copy() {
    let server = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let server_address = server.local_addr().unwrap();
    let peer: SocketAddr = "127.0.0.1:39001".parse().unwrap();
    let relay: SocketAddr = "127.0.0.1:49001".parse().unwrap();
    let server_task = tokio::spawn({
        let server = server.clone();
        async move {
            let client = receive_challenged_allocate(&server, relay).await;
            receive_create_permission(&server, client, peer).await;

            let (channel_wire, channel_client) = recv_datagram(&server).await;
            assert_eq!(channel_client, client);
            let channel_request = assert_authenticated_request(&channel_wire, CHANNEL_BIND_REQUEST);
            let channel = channel_number(&channel_request);
            let encoded_peer = channel_request.attribute(ATTR_XOR_PEER_ADDRESS).unwrap();
            assert_eq!(
                decode_xor_address(encoded_peer.value, &channel_request.transaction()),
                peer
            );
            server
                .send_to(
                    &empty_authenticated_success(
                        CHANNEL_BIND_SUCCESS,
                        channel_request.transaction(),
                    ),
                    client,
                )
                .await
                .unwrap();

            let (outbound, outbound_client) = recv_datagram(&server).await;
            assert_eq!(outbound_client, client);
            assert_eq!(outbound, channel_data(channel, b"outbound"));

            let wrong_channel = if channel == 0x7fff {
                channel - 1
            } else {
                channel + 1
            };
            server
                .send_to(&channel_data(wrong_channel, b"wrong"), client)
                .await
                .unwrap();
            let mut malformed = Vec::from(channel.to_be_bytes());
            malformed.extend_from_slice(&9u16.to_be_bytes());
            malformed.extend_from_slice(b"bad");
            server.send_to(&malformed, client).await.unwrap();
            server
                .send_to(&channel_data(channel, b"inbound"), client)
                .await
                .unwrap();

            let (refresh_wire, refresh_client) = recv_datagram(&server).await;
            assert_eq!(refresh_client, client);
            let refresh = assert_authenticated_request(&refresh_wire, REFRESH_REQUEST);
            assert_eq!(attribute_u32(&refresh, ATTR_LIFETIME), 0);
            server
                .send_to(&refresh_zero_success(refresh.transaction()), client)
                .await
                .unwrap();
            channel
        }
    });

    let pool = PacketPool::new(1);
    let mut held = pool.acquire();
    let storage = held.storage_mut().as_ptr();
    assert_eq!(pool.available(), 0);
    let allocation = connect(server_address, peer, pool.clone()).await;
    assert_eq!(allocation.local_addr(), relay);
    assert_eq!(pool.available(), 0);
    tokio::time::timeout(Duration::from_secs(5), allocation.prepare_channel())
        .await
        .unwrap()
        .unwrap();
    let mut receiver = allocation.take_receiver().unwrap();
    assert!(allocation.take_receiver().is_err());
    assert_eq!(allocation.ingress_pool_deficit_drops(), 0);
    assert_eq!(allocation.ingress_queue_full_drops(), 0);
    let pumps_before_data = allocation.native_pump_count();

    held.read_area()[..8].copy_from_slice(b"outbound");
    held.set_read_len(8).unwrap();
    allocation.send_with_duplicate(held, false).await.unwrap();

    let mut inbound = tokio::time::timeout(Duration::from_secs(3), receiver.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(inbound.as_slice(), b"inbound");
    assert_eq!(inbound.storage_mut().as_ptr(), storage);
    drop(inbound);
    assert_eq!(allocation.ingress_pool_deficit_drops(), 0);
    assert_eq!(allocation.ingress_queue_full_drops(), 0);
    assert_eq!(allocation.native_pump_count(), pumps_before_data);
    assert!(
        tokio::time::timeout(Duration::from_millis(100), receiver.recv())
            .await
            .is_err()
    );

    tokio::time::timeout(Duration::from_secs(2), allocation.deallocate())
        .await
        .unwrap();
    let channel = tokio::time::timeout(Duration::from_secs(2), server_task)
        .await
        .unwrap()
        .unwrap();
    assert!((0x4000..=0x7fff).contains(&channel));
    assert_eq!(pool.available(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn data_batches_preserve_channel_order_and_release_idle_pool_leases() {
    const OUTBOUND: [&[u8]; 8] = [
        b"batch-0", b"batch-1", b"batch-2", b"batch-3", b"batch-4", b"batch-5", b"batch-6",
        b"batch-7",
    ];
    const INBOUND_COUNT: usize = 16;

    let server = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let server_address = server.local_addr().unwrap();
    let peer: SocketAddr = "127.0.0.1:39007".parse().unwrap();
    let relay: SocketAddr = "127.0.0.1:49007".parse().unwrap();
    let (send_inbound, wait_inbound) = oneshot::channel();
    let server_task = tokio::spawn({
        let server = server.clone();
        async move {
            let client = receive_challenged_allocate(&server, relay).await;
            receive_create_permission(&server, client, peer).await;

            let (channel_wire, channel_client) = recv_datagram(&server).await;
            assert_eq!(channel_client, client);
            let channel_request = assert_authenticated_request(&channel_wire, CHANNEL_BIND_REQUEST);
            let channel = channel_number(&channel_request);
            server
                .send_to(
                    &empty_authenticated_success(
                        CHANNEL_BIND_SUCCESS,
                        channel_request.transaction(),
                    ),
                    client,
                )
                .await
                .unwrap();

            wait_inbound.await.unwrap();
            for index in 0..INBOUND_COUNT {
                let payload = format!("inbound-{index}");
                server
                    .send_to(&channel_data(channel, payload.as_bytes()), client)
                    .await
                    .unwrap();
            }

            for payload in OUTBOUND {
                let (wire, outbound_client) = recv_datagram(&server).await;
                assert_eq!(outbound_client, client);
                assert_eq!(wire, channel_data(channel, payload));
            }

            let (refresh_wire, refresh_client) = recv_datagram(&server).await;
            assert_eq!(refresh_client, client);
            let refresh = assert_authenticated_request(&refresh_wire, REFRESH_REQUEST);
            assert_eq!(attribute_u32(&refresh, ATTR_LIFETIME), 0);
            server
                .send_to(&refresh_zero_success(refresh.transaction()), client)
                .await
                .unwrap();
        }
    });

    let pool = PacketPool::new(64);
    let allocation = connect(server_address, peer, pool.clone()).await;
    tokio::time::timeout(Duration::from_secs(5), allocation.prepare_channel())
        .await
        .unwrap()
        .unwrap();

    // The driver must not reserve its mmsg receive slots while it is waiting
    // for the next UDP readiness event.
    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            if pool.available() == pool.capacity() {
                return;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();

    send_inbound.send(()).unwrap();
    let mut receiver = allocation.take_receiver().unwrap();
    for index in 0..INBOUND_COUNT {
        let packet = tokio::time::timeout(Duration::from_secs(3), receiver.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(packet.as_slice(), format!("inbound-{index}").as_bytes());
        drop(packet);
    }

    let mut packets = Vec::with_capacity(OUTBOUND.len());
    for payload in OUTBOUND {
        let mut packet = pool.acquire();
        packet.read_area()[..payload.len()].copy_from_slice(payload);
        packet.set_read_len(payload.len()).unwrap();
        packets.push(packet);
    }
    allocation.send_data_batch(&mut packets).await.unwrap();
    drop(packets);

    tokio::time::timeout(Duration::from_secs(2), allocation.deallocate())
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(5), server_task)
        .await
        .unwrap()
        .unwrap();
    drop(receiver);
    assert_eq!(pool.available(), pool.capacity());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn final_allocate_errors_preserve_stun_codes() {
    for code in [486u16, 441, 437, 508] {
        let server = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let server_address = server.local_addr().unwrap();
        let server_task = tokio::spawn({
            let server = server.clone();
            async move {
                let (first_wire, client) = recv_datagram(&server).await;
                let first = StunMessage::decode(&first_wire).unwrap();
                assert_eq!(first.kind(), ALLOCATE_REQUEST);
                assert_fingerprint(&first);
                server
                    .send_to(&challenge_response(first.transaction()), client)
                    .await
                    .unwrap();

                let (authenticated_wire, authenticated_client) = recv_datagram(&server).await;
                assert_eq!(authenticated_client, client);
                let authenticated = assert_authenticated_request(&authenticated_wire, 3);
                server
                    .send_to(
                        &authenticated_error(ALLOCATE_ERROR, authenticated.transaction(), code),
                        client,
                    )
                    .await
                    .unwrap();
            }
        });

        let result = tokio::time::timeout(
            Duration::from_secs(5),
            TurnAllocation::connect(
                TurnConnectTarget {
                    address: &server_address.to_string(),
                    override_host: None,
                    override_port: None,
                    transport_mode: TurnTransportMode::Udp,
                },
                Arc::from(USERNAME),
                Arc::from(PASSWORD),
                "127.0.0.1:39002".parse().unwrap(),
                PacketPool::new(1),
            ),
        )
        .await
        .unwrap();
        let error = result.err().expect("Allocate error was accepted");
        let message = format!("{error:#}");
        assert!(message.contains(&code.to_string()), "{message}");
        assert!(
            !message.to_ascii_lowercase().contains("attribute not found"),
            "{message}"
        );
        assert!(!message.to_lowercase().contains("атрибут"), "{message}");
        tokio::time::timeout(Duration::from_secs(2), server_task)
            .await
            .unwrap()
            .unwrap();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn channel_bind_error_closes_data_gate_but_preserves_refresh_zero_control_plane() {
    let server = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let server_address = server.local_addr().unwrap();
    let peer: SocketAddr = "127.0.0.1:39003".parse().unwrap();
    let relay: SocketAddr = "127.0.0.1:49003".parse().unwrap();
    let server_task = tokio::spawn({
        let server = server.clone();
        async move {
            let client = receive_challenged_allocate(&server, relay).await;
            receive_create_permission(&server, client, peer).await;

            let (channel_wire, _) = recv_datagram(&server).await;
            let channel_request = assert_authenticated_request(&channel_wire, CHANNEL_BIND_REQUEST);
            server
                .send_to(
                    &authenticated_error(CHANNEL_BIND_ERROR, channel_request.transaction(), 403),
                    client,
                )
                .await
                .unwrap();

            let (refresh_wire, refresh_client) = recv_datagram(&server).await;
            assert_eq!(refresh_client, client);
            let refresh = assert_authenticated_request(&refresh_wire, REFRESH_REQUEST);
            assert_eq!(attribute_u32(&refresh, ATTR_LIFETIME), 0);
            server
                .send_to(&refresh_zero_success(refresh.transaction()), client)
                .await
                .unwrap();
            true
        }
    });

    let pool = PacketPool::new(2);
    let allocation = connect(server_address, peer, pool.clone()).await;
    let error = tokio::time::timeout(Duration::from_secs(5), allocation.prepare_channel())
        .await
        .unwrap()
        .unwrap_err();
    let message = format!("{error:#}");
    assert!(message.contains("ChannelBind"), "{message}");
    assert!(message.contains("403"), "{message}");

    let mut packet = pool.acquire();
    packet.read_area()[..7].copy_from_slice(b"blocked");
    packet.set_read_len(7).unwrap();
    let send_error = allocation
        .send_with_duplicate(packet, false)
        .await
        .unwrap_err();
    assert!(format!("{send_error:#}").contains("ChannelBind"));

    tokio::time::timeout(Duration::from_secs(2), allocation.deallocate())
        .await
        .unwrap();
    assert!(
        tokio::time::timeout(Duration::from_secs(2), server_task)
            .await
            .unwrap()
            .unwrap()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dropped_ready_allocation_retransmits_refresh_zero_in_background() {
    let server = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let server_address = server.local_addr().unwrap();
    let peer: SocketAddr = "127.0.0.1:39004".parse().unwrap();
    let relay: SocketAddr = "127.0.0.1:49004".parse().unwrap();
    let server_task = tokio::spawn({
        let server = server.clone();
        async move {
            let client = receive_challenged_allocate(&server, relay).await;
            let mut transaction = None;
            for _ in 0..4 {
                let (refresh_wire, refresh_client) = recv_datagram(&server).await;
                assert_eq!(refresh_client, client);
                let refresh = assert_authenticated_request(&refresh_wire, REFRESH_REQUEST);
                assert_eq!(attribute_u32(&refresh, ATTR_LIFETIME), 0);
                if let Some(expected) = transaction {
                    assert_eq!(refresh.transaction(), expected);
                } else {
                    transaction = Some(refresh.transaction());
                }
            }
            server
                .send_to(&refresh_zero_success(transaction.unwrap()), client)
                .await
                .unwrap();
        }
    });

    let allocation = connect(server_address, peer, PacketPool::new(1)).await;
    assert_eq!(allocation.local_addr(), relay);
    drop(allocation);
    tokio::time::timeout(Duration::from_secs(5), server_task)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancelled_connect_deallocates_server_allocation_after_late_success() {
    let server = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let server_address = server.local_addr().unwrap();
    let peer: SocketAddr = "127.0.0.1:39005".parse().unwrap();
    let relay: SocketAddr = "127.0.0.1:49005".parse().unwrap();
    let (authenticated_tx, authenticated_rx) = oneshot::channel();
    let (continue_tx, continue_rx) = oneshot::channel();
    let server_task = tokio::spawn({
        let server = server.clone();
        async move {
            let (first_wire, client) = recv_datagram(&server).await;
            let first = StunMessage::decode(&first_wire).unwrap();
            assert_eq!(first.kind(), ALLOCATE_REQUEST);
            server
                .send_to(&challenge_response(first.transaction()), client)
                .await
                .unwrap();

            let (authenticated_wire, authenticated_client) = recv_datagram(&server).await;
            assert_eq!(authenticated_client, client);
            let authenticated = assert_authenticated_request(&authenticated_wire, 3);
            authenticated_tx
                .send((client, authenticated.transaction()))
                .unwrap();
            continue_rx.await.unwrap();
            server
                .send_to(
                    &allocate_success(authenticated.transaction(), relay),
                    client,
                )
                .await
                .unwrap();

            let (refresh_wire, refresh_client) = recv_datagram(&server).await;
            assert_eq!(refresh_client, client);
            let refresh = assert_authenticated_request(&refresh_wire, REFRESH_REQUEST);
            assert_eq!(attribute_u32(&refresh, ATTR_LIFETIME), 0);
            server
                .send_to(&refresh_zero_success(refresh.transaction()), client)
                .await
                .unwrap();
        }
    });

    let connect_task = tokio::spawn(async move {
        TurnAllocation::connect(
            TurnConnectTarget {
                address: &server_address.to_string(),
                override_host: None,
                override_port: None,
                transport_mode: TurnTransportMode::Udp,
            },
            Arc::from(USERNAME),
            Arc::from(PASSWORD),
            peer,
            PacketPool::new(1),
        )
        .await
    });
    tokio::time::timeout(Duration::from_secs(3), authenticated_rx)
        .await
        .unwrap()
        .unwrap();
    connect_task.abort();
    assert!(matches!(
        connect_task.await,
        Err(error) if error.is_cancelled()
    ));
    continue_tx.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(5), server_task)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancelled_before_first_control_send_never_creates_allocation() {
    let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let server_address = server.local_addr().unwrap();
    let peer: SocketAddr = "127.0.0.1:39006".parse().unwrap();
    let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    socket.connect(server_address).await.unwrap();
    let core = NativeCore::create(server_address, USERNAME, PASSWORD, peer).unwrap();
    let (snapshot, _) = watch::channel(CoreSnapshot::default());
    let shared = Arc::new(DriverShared {
        snapshot,
        wake: Notify::new(),
        closing: AtomicBool::new(false),
        terminal_present: AtomicBool::new(false),
        control_sent: AtomicBool::new(false),
        channel: AtomicU16::new(0),
        queue_full_drops: AtomicU64::new(0),
        pool_deficit_drops: AtomicU64::new(0),
        native_pumps: AtomicU64::new(0),
    });
    let (incoming, _receiver) = mpsc::channel(1);
    core.start_allocation().unwrap();
    shared.request_cleanup();
    let driver = tokio::spawn(driver_loop(DriverRuntime {
        outbound: TurnOutbound::Udp(socket.clone()),
        inbound: TurnInbound::Udp(socket),
        core,
        pool: PacketPool::new(1),
        incoming,
        shared,
        server: server_address,
        peer,
    }));
    tokio::time::timeout(Duration::from_secs(1), driver)
        .await
        .unwrap()
        .unwrap();
    let mut wire = [0u8; 2048];
    assert!(
        tokio::time::timeout(Duration::from_millis(200), server.recv_from(&mut wire))
            .await
            .is_err()
    );
}

fn parse_channel_payload(wire: &[u8], channel: u16) -> Option<&[u8]> {
    if wire.len() < 4 || u16::from_be_bytes([wire[0], wire[1]]) != channel {
        return None;
    }
    let payload_len = usize::from(u16::from_be_bytes([wire[2], wire[3]]));
    let end = 4usize.checked_add(payload_len)?;
    (end <= wire.len()).then_some(&wire[4..end])
}

async fn relay_bound_turn_channel_to_peer(
    relay: Arc<UdpSocket>,
    peer: SocketAddr,
    stop: CancellationToken,
) {
    let relay_address = SocketAddr::from(([127, 0, 0, 1], relay.local_addr().unwrap().port()));
    let client = receive_challenged_allocate(&relay, relay_address).await;
    receive_create_permission(&relay, client, peer).await;

    let (channel_wire, channel_client) = recv_datagram(&relay).await;
    assert_eq!(channel_client, client);
    let channel_request = assert_authenticated_request(&channel_wire, CHANNEL_BIND_REQUEST);
    let channel = channel_number(&channel_request);
    let encoded_peer = channel_request.attribute(ATTR_XOR_PEER_ADDRESS).unwrap();
    assert_eq!(
        decode_xor_address(encoded_peer.value, &channel_request.transaction()),
        peer
    );
    relay
        .send_to(
            &empty_authenticated_success(CHANNEL_BIND_SUCCESS, channel_request.transaction()),
            client,
        )
        .await
        .unwrap();

    let mut buffer = [0u8; 65_535];
    loop {
        tokio::select! {
            _ = stop.cancelled() => return,
            received = relay.recv_from(&mut buffer) => {
                let (length, source) = received.unwrap();
                let wire = &buffer[..length];
                if source == client {
                    if let Some(payload) = parse_channel_payload(wire, channel) {
                        relay.send_to(payload, peer).await.unwrap();
                        continue;
                    }
                    let control = assert_authenticated_request(wire, REFRESH_REQUEST);
                    assert_eq!(attribute_u32(&control, ATTR_LIFETIME), 0);
                    relay
                        .send_to(&refresh_zero_success(control.transaction()), client)
                        .await
                        .unwrap();
                } else if source == peer {
                    relay.send_to(&channel_data(channel, wire), client).await.unwrap();
                }
            }
        }
    }
}

#[cfg(unix)]
struct LimitedRelayMeter {
    upstream_bytes: AtomicU64,
    downstream_bytes: AtomicU64,
}

#[cfg(unix)]
struct LimitedRelayRuntime {
    endpoints: Vec<Arc<str>>,
    meters: Vec<Arc<LimitedRelayMeter>>,
    stop: CancellationToken,
    task: std::thread::JoinHandle<f64>,
}

#[cfg(unix)]
impl LimitedRelayRuntime {
    fn stop(self) -> f64 {
        self.stop.cancel();
        self.task
            .join()
            .expect("the limited relay runtime panicked")
    }
}

#[cfg(unix)]
struct StreamRateLimiter {
    available_bits: u128,
    last_refill: Instant,
    bits_per_second: u64,
    maximum_bits: u128,
}

#[cfg(unix)]
impl StreamRateLimiter {
    fn new(bits_per_second: u64) -> Self {
        Self {
            available_bits: 0,
            last_refill: Instant::now(),
            bits_per_second,
            maximum_bits: u128::from(bits_per_second) / 4,
        }
    }

    fn refill(&mut self, now: Instant) {
        let elapsed = now.saturating_duration_since(self.last_refill);
        let added = elapsed
            .as_nanos()
            .saturating_mul(u128::from(self.bits_per_second))
            / 1_000_000_000;
        self.available_bits = self
            .available_bits
            .saturating_add(added)
            .min(self.maximum_bits);
        self.last_refill = now;
    }

    fn try_take(&mut self, bytes: usize, now: Instant) -> bool {
        self.refill(now);
        let required = (bytes as u128).saturating_mul(8);
        if self.available_bits < required {
            return false;
        }
        self.available_bits -= required;
        true
    }

    fn ready_at(&mut self, bytes: usize, now: Instant) -> Instant {
        self.refill(now);
        let required = (bytes as u128).saturating_mul(8);
        if self.available_bits >= required {
            return now;
        }
        let wait_ns = required
            .saturating_sub(self.available_bits)
            .saturating_mul(1_000_000_000)
            .div_ceil(u128::from(self.bits_per_second))
            .max(1);
        now.checked_add(std::time::Duration::from_nanos(
            wait_ns.min(u128::from(u64::MAX)) as u64,
        ))
        .unwrap_or(now)
    }
}

#[cfg(unix)]
async fn flush_limited_relay_queue(
    queue: &mut VecDeque<Vec<u8>>,
    limiter: &mut StreamRateLimiter,
    relay: &UdpSocket,
    destination: SocketAddr,
    counter: &AtomicU64,
) {
    while let Some(payload) = queue.front() {
        if !limiter.try_take(payload.len(), Instant::now()) {
            return;
        }
        let payload = queue.pop_front().expect("the queued packet disappeared");
        relay.send_to(&payload, destination).await.unwrap();
        counter.fetch_add(payload.len() as u64, Ordering::Relaxed);
    }
}

#[cfg(unix)]
fn next_limited_relay_deadline(
    queue: &VecDeque<Vec<u8>>,
    limiter: &mut StreamRateLimiter,
    now: Instant,
) -> Option<Instant> {
    queue
        .front()
        .map(|payload| limiter.ready_at(payload.len(), now))
}

#[cfg(unix)]
fn enqueue_limited_relay_packet(queue: &mut VecDeque<Vec<u8>>, packet: Vec<u8>) {
    const LIMITED_RELAY_QUEUE_CAPACITY: usize = 256;
    assert!(
        queue.len() < LIMITED_RELAY_QUEUE_CAPACITY,
        "a per-stream TURN limiter queue overflowed"
    );
    queue.push_back(packet);
}

#[cfg(unix)]
async fn relay_limited_turn_channel_to_peer(
    relay: Arc<UdpSocket>,
    peer: SocketAddr,
    bits_per_second: u64,
    meter: Arc<LimitedRelayMeter>,
    stop: CancellationToken,
) {
    let relay_address = SocketAddr::from(([127, 0, 0, 1], relay.local_addr().unwrap().port()));
    let client = receive_challenged_allocate(&relay, relay_address).await;
    receive_create_permission(&relay, client, peer).await;

    let (channel_wire, channel_client) = recv_datagram(&relay).await;
    assert_eq!(channel_client, client);
    let channel_request = assert_authenticated_request(&channel_wire, CHANNEL_BIND_REQUEST);
    let channel = channel_number(&channel_request);
    let encoded_peer = channel_request.attribute(ATTR_XOR_PEER_ADDRESS).unwrap();
    assert_eq!(
        decode_xor_address(encoded_peer.value, &channel_request.transaction()),
        peer
    );
    relay
        .send_to(
            &empty_authenticated_success(CHANNEL_BIND_SUCCESS, channel_request.transaction()),
            client,
        )
        .await
        .unwrap();

    let mut upstream = StreamRateLimiter::new(bits_per_second);
    let mut downstream = StreamRateLimiter::new(bits_per_second);
    let mut upstream_queue = VecDeque::with_capacity(256);
    let mut downstream_queue = VecDeque::with_capacity(256);
    let mut buffer = [0u8; 65_535];
    loop {
        flush_limited_relay_queue(
            &mut upstream_queue,
            &mut upstream,
            &relay,
            peer,
            &meter.upstream_bytes,
        )
        .await;
        flush_limited_relay_queue(
            &mut downstream_queue,
            &mut downstream,
            &relay,
            client,
            &meter.downstream_bytes,
        )
        .await;

        let now = Instant::now();
        let deadline = [
            next_limited_relay_deadline(&upstream_queue, &mut upstream, now),
            next_limited_relay_deadline(&downstream_queue, &mut downstream, now),
        ]
        .into_iter()
        .flatten()
        .min();
        let received = match deadline {
            Some(deadline) => tokio::select! {
                _ = stop.cancelled() => return,
                result = relay.recv_from(&mut buffer) => result.unwrap(),
                _ = tokio::time::sleep_until(deadline) => continue,
            },
            None => tokio::select! {
                _ = stop.cancelled() => return,
                result = relay.recv_from(&mut buffer) => result.unwrap(),
            },
        };
        let (length, source) = received;
        let wire = &buffer[..length];
        if source == client {
            if let Some(payload) = parse_channel_payload(wire, channel) {
                enqueue_limited_relay_packet(&mut upstream_queue, payload.to_vec());
                continue;
            }
            let control = assert_authenticated_request(wire, REFRESH_REQUEST);
            assert_eq!(attribute_u32(&control, ATTR_LIFETIME), 0);
            relay
                .send_to(&refresh_zero_success(control.transaction()), client)
                .await
                .unwrap();
        } else if source == peer {
            enqueue_limited_relay_packet(&mut downstream_queue, channel_data(channel, wire));
        }
    }
}

#[cfg(unix)]
fn start_limited_relay_runtime(
    peer: SocketAddr,
    workers: usize,
    bits_per_second: u64,
) -> LimitedRelayRuntime {
    let stop = CancellationToken::new();
    let runtime_stop = stop.clone();
    let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel(1);
    let task = std::thread::Builder::new()
        .name("csqtt-e2e-relay".to_owned())
        .spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("could not create the limited relay runtime");
            runtime.block_on(async move {
                let mut relays = Vec::with_capacity(workers);
                let mut endpoints = Vec::with_capacity(workers);
                let mut meters = Vec::with_capacity(workers);
                for _ in 0..workers {
                    let relay = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
                    endpoints.push(Arc::from(format!(
                        "turn:127.0.0.1:{}?transport=udp",
                        relay.local_addr().unwrap().port()
                    )));
                    meters.push(Arc::new(LimitedRelayMeter {
                        upstream_bytes: AtomicU64::new(0),
                        downstream_bytes: AtomicU64::new(0),
                    }));
                    relays.push(relay);
                }
                ready_tx.send((endpoints, meters.clone())).unwrap();
                let cpu_start = e2e_thread_cpu_seconds();
                let relay_tasks: Vec<_> = relays
                    .into_iter()
                    .zip(meters)
                    .map(|(relay, meter)| {
                        tokio::spawn(relay_limited_turn_channel_to_peer(
                            relay,
                            peer,
                            bits_per_second,
                            meter,
                            runtime_stop.clone(),
                        ))
                    })
                    .collect();
                runtime_stop.cancelled().await;
                for relay_task in relay_tasks {
                    tokio::time::timeout(Duration::from_secs(5), relay_task)
                        .await
                        .expect("a limited relay did not stop")
                        .expect("a limited relay panicked");
                }
                (e2e_thread_cpu_seconds() - cpu_start).max(0.0)
            })
        })
        .expect("could not spawn the limited relay runtime");
    let (endpoints, meters) = ready_rx
        .recv()
        .expect("the limited relay runtime did not initialize");
    LimitedRelayRuntime {
        endpoints,
        meters,
        stop,
        task,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires a separately started CSQTT WSL server and CSQTT_E2E_PEER"]
async fn windows_client_reaches_wsl_server_through_a_real_turn_channel_and_dispatcher() {
    let peer: SocketAddr = std::env::var("CSQTT_E2E_PEER")
        .expect("CSQTT_E2E_PEER is required")
        .parse()
        .expect("CSQTT_E2E_PEER must be an IP:port socket address");
    let relay = Arc::new(UdpSocket::bind("0.0.0.0:0").await.unwrap());
    let endpoint = format!(
        "turn:127.0.0.1:{}?transport=udp",
        relay.local_addr().unwrap().port()
    );
    let relay_stop = CancellationToken::new();
    let relay_task = tokio::spawn(relay_bound_turn_channel_to_peer(
        relay,
        peer,
        relay_stop.clone(),
    ));

    let cancel = CancellationToken::new();
    let pool = PacketPool::new(96);
    let stats = Arc::new(Stats::default());
    let (dispatcher, local_port) = Dispatcher::start(
        "127.0.0.1:0",
        None,
        pool.clone(),
        stats.clone(),
        cancel.clone(),
    )
    .await
    .unwrap();
    let password: Arc<str> = Arc::from("e2e-local-password-20260830");
    let device_id: Arc<str> = Arc::from("e2e-windows-client");
    let (config_tx, mut config_rx) = tokio::sync::mpsc::channel(1);
    let delivered = Arc::new(AtomicBool::new(false));
    let in_flight = Arc::new(AtomicBool::new(true));
    let (ready_tx, ready_rx) = oneshot::channel();
    let session = tokio::spawn(run_session(
        SessionConfig {
            id: 1,
            peer,
            turn_host: None,
            turn_port: None,
            turn_transport: TurnTransportMode::Udp,
            local_port: Arc::from(local_port),
            device_id: device_id.clone(),
            password: password.clone(),
            generation: 20_260_830,
            turn_endpoint_cursor: 0,
            salt: Arc::from("e2e-windows-generation"),
            mode: ObfsMode::Audio,
            wrap_key: derive_wrap_key(&password).unwrap(),
            get_config: true,
            desired_count: 9,
            server_stream_repair: Arc::new(AtomicBool::new(false)),
            repair: RepairState::new(9),
        },
        TurnCredentials {
            username: Arc::from(USERNAME),
            password: Arc::from(PASSWORD),
            server_addresses: vec![Arc::from(endpoint)].into(),
        },
        SessionRuntime {
            dispatcher: dispatcher.clone(),
            pool,
            stats,
            events: Events::new(false),
            config_tx,
            config_delivery: Some(ConfigDeliveryState {
                sent: delivered.clone(),
                in_flight: in_flight.clone(),
            }),
            cancel: cancel.clone(),
            shutdown: Arc::new(ShutdownCoordinator::new()),
            ready_tx: Some(ready_tx),
            allocation_started: None,
            allocation_ready: None,
        },
    ));

    let configuration = tokio::time::timeout(Duration::from_secs(12), config_rx.recv())
        .await
        .expect("the client did not receive TUNCONF from the WSL server")
        .expect("the configuration channel was closed");
    assert!(configuration.starts_with("TUNCONF:"), "{configuration}");
    tokio::time::timeout(Duration::from_secs(3), ready_rx)
        .await
        .expect("the dispatcher was not registered")
        .expect("the ready signal was dropped");
    assert!(delivered.load(Ordering::Acquire));
    assert!(!in_flight.load(Ordering::Acquire));
    assert_eq!(dispatcher.active_count(), 1);

    cancel.cancel();
    assert!(
        tokio::time::timeout(Duration::from_secs(6), session)
            .await
            .expect("the client session did not stop")
            .expect("the client session panicked")
            .expect("the client session returned an error")
    );
    dispatcher.shutdown().await;
    relay_stop.cancel();
    tokio::time::timeout(Duration::from_secs(3), relay_task)
        .await
        .expect("the local TURN relay did not stop")
        .expect("the local TURN relay panicked");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires a separately started CSQTT WSL server, CSQTT_E2E_PEER, and CSQTT_E2E_WEB"]
async fn running_client_receives_hot_dns_configuration_without_reconnect() {
    let peer: SocketAddr = std::env::var("CSQTT_E2E_PEER")
        .expect("CSQTT_E2E_PEER is required")
        .parse()
        .expect("CSQTT_E2E_PEER must be an IP:port socket address");
    let web_url = std::env::var("CSQTT_E2E_WEB").expect("CSQTT_E2E_WEB is required");
    let relay = Arc::new(UdpSocket::bind("0.0.0.0:0").await.unwrap());
    let endpoint = format!(
        "turn:127.0.0.1:{}?transport=udp",
        relay.local_addr().unwrap().port()
    );
    let relay_stop = CancellationToken::new();
    let relay_task = tokio::spawn(relay_bound_turn_channel_to_peer(
        relay,
        peer,
        relay_stop.clone(),
    ));
    let cancel = CancellationToken::new();
    let pool = PacketPool::new(96);
    let stats = Arc::new(Stats::default());
    let (dispatcher, local_port) = Dispatcher::start(
        "127.0.0.1:0",
        None,
        pool.clone(),
        stats.clone(),
        cancel.clone(),
    )
    .await
    .unwrap();
    let password: Arc<str> = Arc::from("e2e-local-password-20260830");
    let (config_tx, mut config_rx) = tokio::sync::mpsc::channel(4);
    let (ready_tx, ready_rx) = oneshot::channel();
    let session = tokio::spawn(run_session(
        SessionConfig {
            id: 1,
            peer,
            turn_host: None,
            turn_port: None,
            turn_transport: TurnTransportMode::Udp,
            local_port: Arc::from(local_port),
            device_id: Arc::from("e2e-windows-client"),
            password: password.clone(),
            generation: 20_260_830,
            turn_endpoint_cursor: 0,
            salt: Arc::from("e2e-windows-generation"),
            mode: ObfsMode::Audio,
            wrap_key: derive_wrap_key(&password).unwrap(),
            get_config: true,
            desired_count: 1,
            server_stream_repair: Arc::new(AtomicBool::new(false)),
            repair: RepairState::new(1),
        },
        TurnCredentials {
            username: Arc::from(USERNAME),
            password: Arc::from(PASSWORD),
            server_addresses: vec![Arc::from(endpoint)].into(),
        },
        SessionRuntime {
            dispatcher: dispatcher.clone(),
            pool,
            stats,
            events: Events::new(false),
            config_tx,
            config_delivery: Some(ConfigDeliveryState {
                sent: Arc::new(AtomicBool::new(false)),
                in_flight: Arc::new(AtomicBool::new(true)),
            }),
            cancel: cancel.clone(),
            shutdown: Arc::new(ShutdownCoordinator::new()),
            ready_tx: Some(ready_tx),
            allocation_started: None,
            allocation_ready: None,
        },
    ));

    let initial = tokio::time::timeout(Duration::from_secs(12), config_rx.recv())
        .await
        .expect("the client did not receive its initial TUNCONF")
        .expect("the configuration channel was closed");
    assert!(initial.starts_with("TUNCONF:"), "{initial}");
    tokio::time::timeout(Duration::from_secs(3), ready_rx)
        .await
        .expect("the dispatcher was not registered")
        .expect("the ready signal was dropped");
    let (dns_provider, expected_dns) = if initial.contains(":8.8.8.8,8.8.4.4:") {
        ("yandex", "77.88.8.8,77.88.8.1")
    } else {
        ("google", "8.8.8.8,8.8.4.4")
    };
    apply_e2e_dns(&web_url, dns_provider);
    let changed = tokio::time::timeout(Duration::from_secs(12), config_rx.recv())
        .await
        .expect("the running client did not receive hot TUNCONF")
        .expect("the configuration channel was closed");
    assert!(
        changed.contains(&format!(":{expected_dns}:")),
        "unexpected hot DNS configuration: {changed}"
    );
    assert_eq!(dispatcher.active_count(), 1);
    println!("CSQTT_E2E_HOT_DNS received={changed}");

    cancel.cancel();
    assert!(
        tokio::time::timeout(Duration::from_secs(6), session)
            .await
            .expect("the client session did not stop")
            .expect("the client session panicked")
            .expect("the client session returned an error")
    );
    dispatcher.shutdown().await;
    relay_stop.cancel();
    tokio::time::timeout(Duration::from_secs(3), relay_task)
        .await
        .expect("the local TURN relay did not stop")
        .expect("the local TURN relay panicked");
}

fn apply_e2e_dns(web_url: &str, provider: &str) {
    let cookie_path = format!("/tmp/csqtt-e2e-dns-{}.cookie", std::process::id());
    let login = std::process::Command::new("curl")
        .args([
            "-kfsS",
            "-c",
            &cookie_path,
            "-H",
            "content-type: application/json",
            "-d",
            r#"{"user":"e2e-test","pass":"e2e-test-password"}"#,
            &format!("{web_url}/api/login"),
        ])
        .output()
        .expect("could not invoke curl for CSQTT panel login");
    assert!(
        login.status.success(),
        "CSQTT panel login failed: {}",
        String::from_utf8_lossy(&login.stderr)
    );
    let update = std::process::Command::new("curl")
        .args([
            "-kfsS",
            "-b",
            &cookie_path,
            "-H",
            "content-type: application/json",
            "-d",
            &format!(r#"{{"dns_provider":"{provider}"}}"#),
            &format!("{web_url}/api/settings"),
        ])
        .output()
        .expect("could not invoke curl for CSQTT DNS update");
    let _ = std::fs::remove_file(&cookie_path);
    assert!(
        update.status.success(),
        "CSQTT hot DNS update failed: {}",
        String::from_utf8_lossy(&update.stderr)
    );
    assert!(
        String::from_utf8_lossy(&update.stdout).contains("\"restart_required\":false"),
        "CSQTT hot DNS update unexpectedly requires restart"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires a separately started CSQTT WSL server and CSQTT_E2E_PEER"]
async fn nine_windows_workers_register_with_a_wsl_server_without_missing_or_duplicate_streams() {
    const WORKERS: usize = 9;
    let peer: SocketAddr = std::env::var("CSQTT_E2E_PEER")
        .expect("CSQTT_E2E_PEER is required")
        .parse()
        .expect("CSQTT_E2E_PEER must be an IP:port socket address");
    let cancel = CancellationToken::new();
    let pool = PacketPool::new(96 * WORKERS);
    let stats = Arc::new(Stats::default());
    let (dispatcher, local_port) = Dispatcher::start(
        "127.0.0.1:0",
        None,
        pool.clone(),
        stats.clone(),
        cancel.clone(),
    )
    .await
    .unwrap();
    let password: Arc<str> = Arc::from("e2e-local-password-20260830");
    let device_id: Arc<str> = Arc::from("e2e-windows-client");
    let wrap_key = derive_wrap_key(&password).unwrap();
    let repair = RepairState::new(WORKERS);
    let server_stream_repair = Arc::new(AtomicBool::new(false));
    let shutdown = Arc::new(ShutdownCoordinator::new());
    let (config_tx, mut config_rx) = tokio::sync::mpsc::channel(1);
    let delivered = Arc::new(AtomicBool::new(false));
    let in_flight = Arc::new(AtomicBool::new(true));
    let mut sessions = Vec::with_capacity(WORKERS);
    let mut ready = Vec::with_capacity(WORKERS);
    let mut relay_stops = Vec::with_capacity(WORKERS);
    let mut relay_tasks = Vec::with_capacity(WORKERS);

    for id in 1..=WORKERS {
        let relay = Arc::new(UdpSocket::bind("0.0.0.0:0").await.unwrap());
        let endpoint = format!(
            "turn:127.0.0.1:{}?transport=udp",
            relay.local_addr().unwrap().port()
        );
        let relay_stop = CancellationToken::new();
        relay_tasks.push(tokio::spawn(relay_bound_turn_channel_to_peer(
            relay,
            peer,
            relay_stop.clone(),
        )));
        relay_stops.push(relay_stop);
        let (ready_tx, ready_rx) = oneshot::channel();
        ready.push(ready_rx);
        let get_config = id == 1;
        sessions.push(tokio::spawn(run_session(
            SessionConfig {
                id,
                peer,
                turn_host: None,
                turn_port: None,
                turn_transport: TurnTransportMode::Udp,
                local_port: Arc::from(local_port.clone()),
                device_id: device_id.clone(),
                password: password.clone(),
                generation: 20_260_830,
                turn_endpoint_cursor: 0,
                salt: Arc::from("e2e-windows-generation"),
                mode: ObfsMode::Audio,
                wrap_key,
                get_config,
                desired_count: WORKERS,
                server_stream_repair: server_stream_repair.clone(),
                repair: repair.clone(),
            },
            TurnCredentials {
                username: Arc::from(USERNAME),
                password: Arc::from(PASSWORD),
                server_addresses: vec![Arc::from(endpoint)].into(),
            },
            SessionRuntime {
                dispatcher: dispatcher.clone(),
                pool: pool.clone(),
                stats: stats.clone(),
                events: Events::new(false),
                config_tx: config_tx.clone(),
                config_delivery: get_config.then(|| ConfigDeliveryState {
                    sent: delivered.clone(),
                    in_flight: in_flight.clone(),
                }),
                cancel: cancel.clone(),
                shutdown: shutdown.clone(),
                ready_tx: Some(ready_tx),
                allocation_started: None,
                allocation_ready: None,
            },
        )));
    }
    drop(config_tx);

    let configuration = tokio::time::timeout(Duration::from_secs(15), config_rx.recv())
        .await
        .expect("the first worker did not receive TUNCONF from the WSL server")
        .expect("the configuration channel was closed");
    assert!(configuration.starts_with("TUNCONF:"), "{configuration}");
    for ready_rx in ready {
        tokio::time::timeout(Duration::from_secs(8), ready_rx)
            .await
            .expect("a worker was not registered in the dispatcher")
            .expect("a worker ready signal was dropped");
    }
    assert!(delivered.load(Ordering::Acquire));
    assert!(!in_flight.load(Ordering::Acquire));
    assert_eq!(dispatcher.active_count(), WORKERS);

    cancel.cancel();
    for (index, session) in sessions.into_iter().enumerate() {
        let delivered = tokio::time::timeout(Duration::from_secs(8), session)
            .await
            .expect("a client worker did not stop")
            .expect("a client worker panicked")
            .expect("a client worker returned an error");
        assert_eq!(delivered, index == 0);
    }
    dispatcher.shutdown().await;
    for stop in relay_stops {
        stop.cancel();
    }
    for relay_task in relay_tasks {
        tokio::time::timeout(Duration::from_secs(3), relay_task)
            .await
            .expect("a local TURN relay did not stop")
            .expect("a local TURN relay panicked");
    }
}

#[cfg(unix)]
fn e2e_env_u64(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| *value != 0)
        .unwrap_or(default)
}

#[cfg(unix)]
fn e2e_process_cpu_seconds() -> f64 {
    let mut usage = std::mem::MaybeUninit::<libc::rusage>::zeroed();
    let result = unsafe { libc::getrusage(libc::RUSAGE_SELF, usage.as_mut_ptr()) };
    assert_eq!(result, 0, "getrusage failed");
    let usage = unsafe { usage.assume_init() };
    let user = usage.ru_utime.tv_sec as f64 + usage.ru_utime.tv_usec as f64 / 1_000_000.0;
    let system = usage.ru_stime.tv_sec as f64 + usage.ru_stime.tv_usec as f64 / 1_000_000.0;
    user + system
}

#[cfg(unix)]
fn e2e_thread_cpu_seconds() -> f64 {
    let mut time = std::mem::MaybeUninit::<libc::timespec>::zeroed();
    let result = unsafe { libc::clock_gettime(libc::CLOCK_THREAD_CPUTIME_ID, time.as_mut_ptr()) };
    assert_eq!(result, 0, "clock_gettime failed");
    let time = unsafe { time.assume_init() };
    time.tv_sec as f64 + time.tv_nsec as f64 / 1_000_000_000.0
}

#[cfg(unix)]
fn e2e_tunnel_ip(configuration: &str) -> [u8; 4] {
    configuration
        .split(':')
        .nth(1)
        .and_then(|value| value.parse::<std::net::Ipv4Addr>().ok())
        .map(|value| value.octets())
        .expect("TUNCONF must contain a client tunnel IPv4 address")
}

#[cfg(unix)]
fn e2e_ipv4_checksum(header: &[u8]) -> u16 {
    let mut sum = 0u32;
    for word in header.chunks_exact(2) {
        sum = sum.saturating_add(u16::from_be_bytes([word[0], word[1]]) as u32);
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

#[cfg(unix)]
fn e2e_udp_packet(source: [u8; 4], destination_port: u16, sequence: u64) -> [u8; 1_200] {
    let mut packet = [0u8; 1_200];
    let packet_length = packet.len();
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&(packet_length as u16).to_be_bytes());
    packet[4..6].copy_from_slice(&(sequence as u16).to_be_bytes());
    packet[8] = 64;
    packet[9] = 17;
    packet[12..16].copy_from_slice(&source);
    packet[16..20].copy_from_slice(&[10, 66, 67, 1]);
    packet[20..22].copy_from_slice(&47_214u16.to_be_bytes());
    packet[22..24].copy_from_slice(&destination_port.to_be_bytes());
    packet[24..26].copy_from_slice(&((packet_length - 20) as u16).to_be_bytes());
    packet[28..36].copy_from_slice(&sequence.to_be_bytes());
    for (offset, value) in packet[36..].iter_mut().enumerate() {
        *value = sequence.wrapping_add(offset as u64) as u8;
    }
    let checksum = e2e_ipv4_checksum(&packet[..20]);
    packet[10..12].copy_from_slice(&checksum.to_be_bytes());
    packet
}

#[cfg(unix)]
fn e2e_echo_sequence(packet: &[u8], destination: [u8; 4], destination_port: u16) -> Option<u64> {
    if packet.len() != 1_200
        || packet.first().copied()? != 0x45
        || packet[9] != 17
        || packet[16..20] != destination
        || u16::from_be_bytes([packet[22], packet[23]]) != destination_port
    {
        return None;
    }
    Some(u64::from_be_bytes(packet[28..36].try_into().ok()?))
}

#[cfg(unix)]
async fn collect_e2e_echoes(
    tun: Arc<tokio::net::UnixDatagram>,
    tunnel_ip: [u8; 4],
    destination_port: u16,
    received_bytes: Arc<AtomicU64>,
    received_packets: Arc<AtomicU64>,
    stop: CancellationToken,
) {
    let mut packet = [0u8; 2_048];
    loop {
        tokio::select! {
            _ = stop.cancelled() => return,
            received = tun.recv(&mut packet) => {
                match received {
                    Ok(length) if e2e_echo_sequence(&packet[..length], tunnel_ip, destination_port).is_some() => {
                        received_bytes.fetch_add(length as u64, Ordering::Relaxed);
                        received_packets.fetch_add(1, Ordering::Relaxed);
                    }
                    Ok(_) => {}
                    Err(_) => return,
                }
            }
        }
    }
}

#[cfg(unix)]
struct E2eTunResult {
    sent_bytes: u64,
    received_bytes: u64,
    received_packets: u64,
    cpu_seconds: f64,
}

#[cfg(unix)]
struct E2eTunRuntime {
    task: std::thread::JoinHandle<E2eTunResult>,
}

#[cfg(unix)]
impl E2eTunRuntime {
    async fn finish(self) -> E2eTunResult {
        tokio::task::spawn_blocking(move || self.task.join().expect("the E2E TUN runtime panicked"))
            .await
            .expect("the E2E TUN runtime join task panicked")
    }
}

#[cfg(unix)]
fn start_e2e_tun_runtime(
    test_tun: StdUnixDatagram,
    tunnel_ip: [u8; 4],
    destination_port: u16,
    target_mbit: u64,
    duration_seconds: u64,
) -> E2eTunRuntime {
    let task = std::thread::Builder::new()
        .name("csqtt-e2e-tun".to_owned())
        .spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("could not create the E2E TUN runtime");
            runtime.block_on(async move {
                let tun = Arc::new(tokio::net::UnixDatagram::from_std(test_tun).unwrap());
                let received_bytes = Arc::new(AtomicU64::new(0));
                let received_packets = Arc::new(AtomicU64::new(0));
                let collector_stop = CancellationToken::new();
                let collector = tokio::spawn(collect_e2e_echoes(
                    tun.clone(),
                    tunnel_ip,
                    destination_port,
                    received_bytes.clone(),
                    received_packets.clone(),
                    collector_stop.clone(),
                ));
                let packet_bytes = 1_200u64;
                let start = Instant::now();
                let cpu_start = e2e_thread_cpu_seconds();
                let duration = Duration::from_secs(duration_seconds);
                let deadline = start + duration;
                let mut next_tick = start;
                let mut sequence = 0u64;
                let mut sent_bytes = 0u64;
                while Instant::now() < deadline {
                    let now = Instant::now();
                    let due_packets = now
                        .saturating_duration_since(start)
                        .as_nanos()
                        .saturating_mul(u128::from(target_mbit).saturating_mul(1_000_000))
                        / (u128::from(packet_bytes)
                            .saturating_mul(8)
                            .saturating_mul(1_000_000_000));
                    let missing_packets = due_packets.saturating_sub(u128::from(sequence)) as usize;
                    if missing_packets == 0 {
                        let next = next_tick + Duration::from_millis(4);
                        next_tick = if next <= now {
                            now + Duration::from_millis(4)
                        } else {
                            next
                        };
                        tokio::time::sleep_until(next_tick.min(deadline)).await;
                        continue;
                    }
                    for _ in 0..missing_packets.min(256) {
                        let packet = e2e_udp_packet(tunnel_ip, destination_port, sequence);
                        if tun.send(&packet).await.unwrap() != packet.len() {
                            panic!("test TUN accepted a short packet");
                        }
                        sequence = sequence.wrapping_add(1);
                        sent_bytes = sent_bytes.saturating_add(packet_bytes);
                    }
                    if missing_packets > 256 {
                        tokio::task::yield_now().await;
                    }
                }
                tokio::time::sleep(Duration::from_secs(3)).await;
                collector_stop.cancel();
                collector.await.unwrap();
                E2eTunResult {
                    sent_bytes,
                    received_bytes: received_bytes.load(Ordering::Relaxed),
                    received_packets: received_packets.load(Ordering::Relaxed),
                    cpu_seconds: (e2e_thread_cpu_seconds() - cpu_start).max(0.0),
                }
            })
        })
        .expect("could not spawn the E2E TUN runtime");
    E2eTunRuntime { task }
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "requires a separately started CSQTT WSL server and CSQTT_E2E_PEER"]
async fn seventy_two_linux_workers_hold_per_stream_rate_through_server_dataplane() {
    const WORKERS: usize = 72;
    const STREAM_RATE_BITS_PER_SECOND: u64 = 2_300_000;
    const DEFAULT_TARGET_MBIT: u64 = 160;
    const DEFAULT_MIN_MBIT: u64 = 144;
    const DEFAULT_MIN_STREAM_KBIT: u64 = 2_000;
    const DEFAULT_DURATION_SECONDS: u64 = 12;
    const ECHO_PORT: u16 = 47_214;

    let peer: SocketAddr = std::env::var("CSQTT_E2E_PEER")
        .expect("CSQTT_E2E_PEER is required")
        .parse()
        .expect("CSQTT_E2E_PEER must be an IP:port socket address");
    let duration_seconds = e2e_env_u64("CSQTT_E2E_DURATION_SECONDS", DEFAULT_DURATION_SECONDS);
    let target_mbit = e2e_env_u64("CSQTT_E2E_TARGET_MBIT", DEFAULT_TARGET_MBIT);
    let min_mbit = e2e_env_u64("CSQTT_E2E_MIN_MBIT", DEFAULT_MIN_MBIT);
    let min_stream_mbit =
        e2e_env_u64("CSQTT_E2E_MIN_STREAM_KBIT", DEFAULT_MIN_STREAM_KBIT) as f64 / 1_000.0;
    let echo_port = e2e_env_u64("CSQTT_E2E_ECHO_PORT", u64::from(ECHO_PORT)) as u16;
    assert!(target_mbit <= (WORKERS as u64 * STREAM_RATE_BITS_PER_SECOND) / 1_000_000);

    let (test_tun, dispatcher_tun) = StdUnixDatagram::pair().unwrap();
    test_tun.set_nonblocking(true).unwrap();
    dispatcher_tun.set_nonblocking(true).unwrap();
    let dispatcher_file = unsafe { File::from_raw_fd(dispatcher_tun.into_raw_fd()) };
    let cancel = CancellationToken::new();
    let pool = PacketPool::new(12_288);
    let stats = Arc::new(Stats::default());
    let dispatcher =
        Dispatcher::start_test_tun(dispatcher_file, pool.clone(), stats, cancel.clone()).await;
    let password: Arc<str> = Arc::from("e2e-local-password-20260830");
    let device_id: Arc<str> = Arc::from("e2e-windows-client");
    let wrap_key = derive_wrap_key(&password).unwrap();
    let repair = RepairState::new(WORKERS);
    let server_stream_repair = Arc::new(AtomicBool::new(false));
    let shutdown = Arc::new(ShutdownCoordinator::new());
    let (config_tx, mut config_rx) = tokio::sync::mpsc::channel(1);
    let delivered = Arc::new(AtomicBool::new(false));
    let in_flight = Arc::new(AtomicBool::new(true));
    let mut sessions = Vec::with_capacity(WORKERS);
    let mut ready = Vec::with_capacity(WORKERS);
    let relay_runtime = start_limited_relay_runtime(peer, WORKERS, STREAM_RATE_BITS_PER_SECOND);

    for id in 1..=WORKERS {
        let (ready_tx, ready_rx) = oneshot::channel();
        ready.push(ready_rx);
        let get_config = id == 1;
        sessions.push(tokio::spawn(run_session(
            SessionConfig {
                id,
                peer,
                turn_host: None,
                turn_port: None,
                turn_transport: TurnTransportMode::Udp,
                local_port: Arc::from("0"),
                device_id: device_id.clone(),
                password: password.clone(),
                generation: 20_260_901,
                turn_endpoint_cursor: 0,
                salt: Arc::from("e2e-wsl-throughput-generation"),
                mode: ObfsMode::Audio,
                wrap_key,
                get_config,
                desired_count: WORKERS,
                server_stream_repair: server_stream_repair.clone(),
                repair: repair.clone(),
            },
            TurnCredentials {
                username: Arc::from(USERNAME),
                password: Arc::from(PASSWORD),
                server_addresses: vec![relay_runtime.endpoints[id - 1].clone()].into(),
            },
            SessionRuntime {
                dispatcher: dispatcher.clone(),
                pool: pool.clone(),
                stats: Arc::new(Stats::default()),
                events: Events::new(false),
                config_tx: config_tx.clone(),
                config_delivery: get_config.then(|| ConfigDeliveryState {
                    sent: delivered.clone(),
                    in_flight: in_flight.clone(),
                }),
                cancel: cancel.clone(),
                shutdown: shutdown.clone(),
                ready_tx: Some(ready_tx),
                allocation_started: None,
                allocation_ready: None,
            },
        )));
    }
    drop(config_tx);

    let configuration = tokio::time::timeout(Duration::from_secs(30), config_rx.recv())
        .await
        .expect("the first worker did not receive TUNCONF")
        .expect("the configuration channel was closed");
    let tunnel_ip = e2e_tunnel_ip(&configuration);
    for ready_rx in ready {
        tokio::time::timeout(Duration::from_secs(20), ready_rx)
            .await
            .expect("a throughput worker was not registered")
            .expect("a throughput worker ready signal was dropped");
    }
    assert!(delivered.load(Ordering::Acquire));
    assert!(!in_flight.load(Ordering::Acquire));
    assert_eq!(dispatcher.active_count(), WORKERS);

    let start = Instant::now();
    let cpu_start = e2e_process_cpu_seconds();
    let tun_result = start_e2e_tun_runtime(
        test_tun,
        tunnel_ip,
        echo_port,
        target_mbit,
        duration_seconds,
    )
    .finish()
    .await;
    let elapsed = Duration::from_secs(duration_seconds).as_secs_f64();
    let measurement_elapsed = start.elapsed().as_secs_f64();
    let process_cpu_percent =
        (e2e_process_cpu_seconds() - cpu_start).max(0.0) * 100.0 / measurement_elapsed;
    let tun_harness_cpu_percent = tun_result.cpu_seconds * 100.0 / measurement_elapsed;
    let sent_mbit = tun_result.sent_bytes as f64 * 8.0 / elapsed / 1_000_000.0;
    let received_mbit = tun_result.received_bytes as f64 * 8.0 / elapsed / 1_000_000.0;
    let per_stream_up: Vec<f64> = relay_runtime
        .meters
        .iter()
        .map(|meter| {
            meter.upstream_bytes.load(Ordering::Relaxed) as f64 * 8.0 / elapsed / 1_000_000.0
        })
        .collect();
    let per_stream_down: Vec<f64> = relay_runtime
        .meters
        .iter()
        .map(|meter| {
            meter.downstream_bytes.load(Ordering::Relaxed) as f64 * 8.0 / elapsed / 1_000_000.0
        })
        .collect();
    let min_stream_up = per_stream_up.iter().copied().fold(f64::INFINITY, f64::min);
    let min_stream_down = per_stream_down
        .iter()
        .copied()
        .fold(f64::INFINITY, f64::min);
    assert!(
        sent_mbit >= min_mbit as f64,
        "client TUN input was only {sent_mbit:.2} Mbit/s"
    );
    assert!(
        received_mbit >= min_mbit as f64,
        "client TUN output was only {received_mbit:.2} Mbit/s"
    );
    assert!(
        min_stream_up >= min_stream_mbit,
        "a stream received less than {min_stream_mbit:.2} Mbit/s upstream"
    );
    assert!(
        min_stream_down >= min_stream_mbit,
        "a stream received less than {min_stream_mbit:.2} Mbit/s downstream"
    );

    cancel.cancel();
    for (index, session) in sessions.into_iter().enumerate() {
        let delivered = tokio::time::timeout(Duration::from_secs(12), session)
            .await
            .expect("a throughput worker did not stop")
            .expect("a throughput worker panicked")
            .expect("a throughput worker returned an error");
        assert_eq!(delivered, index == 0);
    }
    dispatcher.shutdown().await;
    let relay_cpu_percent = relay_runtime.stop() * 100.0 / measurement_elapsed;
    let client_cpu_percent =
        (process_cpu_percent - relay_cpu_percent - tun_harness_cpu_percent).max(0.0);
    println!(
        "CSQTT_E2E_72 sent_mbit={sent_mbit:.2} received_mbit={received_mbit:.2} packets={} min_stream_up={min_stream_up:.2} min_stream_down={min_stream_down:.2} client_path_cpu_percent={client_cpu_percent:.2} relay_cpu_percent={relay_cpu_percent:.2} tun_harness_cpu_percent={tun_harness_cpu_percent:.2}",
        tun_result.received_packets,
    );
}
