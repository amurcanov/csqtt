// SPDX-FileCopyrightText: 2026 amurcanov
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

use super::*;
use crate::stun_codec::{Class as StunClass, Message as StunMessage};
use hmac::{Hmac, Mac};
use md5::{Digest, Md5};
use sha1::Sha1;
use std::net::{IpAddr, SocketAddr};
use tokio::sync::oneshot;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
};

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
