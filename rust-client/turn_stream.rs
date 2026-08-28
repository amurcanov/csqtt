// SPDX-FileCopyrightText: 2026 amurcanov
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

use crate::{
    packet::{PACKET_CAPACITY, PACKET_HEADROOM, PacketBuf, PacketPool},
    turn_endpoint::{TurnEndpoint, TurnWireTransport},
};
use anyhow::{Context, Result, bail};
use bytes::{Bytes, BytesMut};
use socket2::SockRef;
use std::{
    net::SocketAddr,
    sync::{Arc, OnceLock},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf},
    net::TcpStream,
    sync::{mpsc, watch},
};
use turn_rustls::{ClientConfig, RootCertStore, pki_types::ServerName};
use turn_tokio_rustls::TlsConnector;

pub const MAX_CONTROL_FRAME_BYTES: usize = 4096;
const MAX_DATA_FRAME_BYTES: usize = PACKET_CAPACITY - PACKET_HEADROOM;
const CONTROL_QUEUE_CAPACITY: usize = 16;
const DATA_QUEUE_CAPACITY: usize = 8;
const TCP_SEND_BUFFER_BYTES: usize = 32 * 1024;
const STREAM_READ_BUFFER_BYTES: usize = MAX_CONTROL_FRAME_BYTES;

trait AsyncTurnStream: AsyncRead + AsyncWrite + Send + Unpin {}

impl<T> AsyncTurnStream for T where T: AsyncRead + AsyncWrite + Send + Unpin {}

type BoxedTurnStream = Box<dyn AsyncTurnStream>;
pub type TurnStreamWriteFailure = watch::Receiver<Option<Arc<str>>>;

pub struct TurnStreamWriter {
    control: mpsc::Sender<Bytes>,
    data: mpsc::Sender<PacketBuf>,
}

pub struct TurnStreamReader {
    inner: ReadHalf<BoxedTurnStream>,
    buffer: BytesMut,
}

pub enum TurnStreamFrame {
    Control(Vec<u8>),
    Data(PacketBuf),
    DataDropped,
}

pub async fn connect(
    endpoint: &TurnEndpoint,
    server: SocketAddr,
) -> Result<(
    Arc<TurnStreamWriter>,
    TurnStreamReader,
    TurnStreamWriteFailure,
)> {
    let socket = TcpStream::connect(server)
        .await
        .with_context(|| format!("TURN {} connect {server}", endpoint.transport.as_str()))?;
    socket
        .set_nodelay(true)
        .context("TURN TCP_NODELAY configuration failed")?;
    let _ = SockRef::from(&socket).set_send_buffer_size(TCP_SEND_BUFFER_BYTES);
    let stream: BoxedTurnStream = match endpoint.transport {
        TurnWireTransport::Tcp => Box::new(socket),
        TurnWireTransport::Tls => {
            let server_name = ServerName::try_from(endpoint.tls_server_name()?.to_owned())
                .context("TURN TLS server name is invalid")?;
            let connector = TlsConnector::from(tls_config());
            let stream = connector
                .connect(server_name, socket)
                .await
                .with_context(|| format!("TURN TLS handshake to {} failed", endpoint.host))?;
            Box::new(stream)
        }
        TurnWireTransport::Udp => bail!("UDP endpoint cannot create a TURN stream"),
    };
    let (reader, writer) = tokio::io::split(stream);
    let (control_tx, control_rx) = mpsc::channel(CONTROL_QUEUE_CAPACITY);
    let (data_tx, data_rx) = mpsc::channel(DATA_QUEUE_CAPACITY);
    let (write_failure_tx, write_failure_rx) = watch::channel(None);
    tokio::spawn(writer_loop(writer, control_rx, data_rx, write_failure_tx));
    Ok((
        Arc::new(TurnStreamWriter {
            control: control_tx,
            data: data_tx,
        }),
        TurnStreamReader {
            inner: reader,
            buffer: BytesMut::with_capacity(STREAM_READ_BUFFER_BYTES),
        },
        write_failure_rx,
    ))
}

impl TurnStreamWriter {
    pub async fn write_control(&self, wire: &[u8]) -> Result<()> {
        self.control
            .send(Bytes::copy_from_slice(wire))
            .await
            .context("TURN stream control queue closed")
    }

    pub fn try_write_data(&self, packet: PacketBuf) -> Result<bool> {
        match self.data.try_send(packet) {
            Ok(()) => Ok(true),
            Err(mpsc::error::TrySendError::Full(_)) => Ok(false),
            Err(mpsc::error::TrySendError::Closed(_)) => {
                bail!("TURN stream data queue closed")
            }
        }
    }
}

enum TurnStreamOutbound {
    Control(Bytes),
    Data(PacketBuf),
}

async fn writer_loop(
    mut writer: WriteHalf<BoxedTurnStream>,
    mut control: mpsc::Receiver<Bytes>,
    mut data: mpsc::Receiver<PacketBuf>,
    write_failure: watch::Sender<Option<Arc<str>>>,
) {
    loop {
        let next = if let Ok(control) = control.try_recv() {
            Some(TurnStreamOutbound::Control(control))
        } else if control.is_closed() {
            data.recv().await.map(TurnStreamOutbound::Data)
        } else if data.is_closed() {
            control.recv().await.map(TurnStreamOutbound::Control)
        } else {
            tokio::select! {
                biased;
                control = control.recv() => control.map(TurnStreamOutbound::Control),
                data = data.recv() => data.map(TurnStreamOutbound::Data),
            }
        };
        let Some(next) = next else {
            if control.is_closed() && data.is_closed() {
                return;
            }
            continue;
        };
        let wire = match &next {
            TurnStreamOutbound::Control(wire) => wire.as_ref(),
            TurnStreamOutbound::Data(packet) => packet.as_slice(),
        };
        if let Err(error) = writer.write_all(wire).await {
            let _ = write_failure.send(Some(Arc::from(format!("{error}"))));
            return;
        }
    }
}

impl TurnStreamReader {
    pub async fn read_frame(&mut self, pool: &Arc<PacketPool>) -> Result<TurnStreamFrame> {
        loop {
            if let Some(frame) = self.take_frame(pool)? {
                return Ok(frame);
            }
            if self.buffer.len() >= STREAM_READ_BUFFER_BYTES {
                bail!("TURN stream frame buffer reached its hard limit")
            }
            let read = self
                .inner
                .read_buf(&mut self.buffer)
                .await
                .context("TURN stream read failed")?;
            if read == 0 {
                bail!("TURN stream closed by remote peer")
            }
        }
    }

    fn take_frame(&mut self, pool: &Arc<PacketPool>) -> Result<Option<TurnStreamFrame>> {
        match self.decode_frame(pool)? {
            StreamDecode::Frame(frame) => Ok(Some(frame)),
            StreamDecode::NeedMore => Ok(None),
        }
    }

    fn decode_frame(&mut self, pool: &Arc<PacketPool>) -> Result<StreamDecode> {
        let bytes = self.buffer.as_ref();
        let kind = match frame_start(bytes)? {
            Some(kind) => kind,
            None => return Ok(StreamDecode::NeedMore),
        };
        match kind {
            FrameKind::Control(frame_bytes) => {
                if bytes.len() < frame_bytes {
                    return Ok(StreamDecode::NeedMore);
                }
                let frame = self.buffer.split_to(frame_bytes).to_vec();
                Ok(StreamDecode::Frame(TurnStreamFrame::Control(frame)))
            }
            FrameKind::ChannelData {
                frame_bytes,
                padding,
            } => {
                if bytes.len() < frame_bytes + padding {
                    return Ok(StreamDecode::NeedMore);
                }
                let wire = self.buffer.split_to(frame_bytes + padding);
                Ok(StreamDecode::Frame(copy_channel_data(wire, pool)?))
            }
        }
    }
}

enum StreamDecode {
    Frame(TurnStreamFrame),
    NeedMore,
}

enum FrameKind {
    Control(usize),
    ChannelData { frame_bytes: usize, padding: usize },
}

fn frame_start(bytes: &[u8]) -> Result<Option<FrameKind>> {
    if bytes.len() < 4 {
        return Ok(None);
    }
    let declared = u16::from_be_bytes([bytes[2], bytes[3]]) as usize;
    if bytes[0] & 0xc0 == 0 {
        if !declared.is_multiple_of(4) {
            bail!("TURN stream control frame has an unaligned length")
        }
        let Some(frame_bytes) = 20usize.checked_add(declared) else {
            bail!("TURN stream control frame length overflows")
        };
        if frame_bytes > MAX_CONTROL_FRAME_BYTES {
            bail!("TURN stream control frame exceeds the hard limit")
        }
        if bytes.len() < 8 {
            return Ok(None);
        }
        if bytes[4..8] != [0x21, 0x12, 0xa4, 0x42] {
            bail!("TURN stream control frame has an invalid magic cookie")
        }
        return Ok(Some(FrameKind::Control(frame_bytes)));
    }
    if bytes[0] & 0xc0 != 0x40 {
        bail!("TURN stream received a frame in the reserved type range")
    }
    let Some(frame_bytes) = 4usize.checked_add(declared) else {
        bail!("TURN stream ChannelData frame length overflows")
    };
    let padding = (4 - declared % 4) % 4;
    if frame_bytes + padding > MAX_DATA_FRAME_BYTES {
        bail!("TURN stream ChannelData frame exceeds packet capacity")
    }
    Ok(Some(FrameKind::ChannelData {
        frame_bytes,
        padding,
    }))
}

fn copy_channel_data(wire: BytesMut, pool: &Arc<PacketPool>) -> Result<TurnStreamFrame> {
    let Some(mut packet) = pool.try_acquire() else {
        return Ok(TurnStreamFrame::DataDropped);
    };
    packet.set_read_len(wire.len())?;
    packet.as_mut_slice().copy_from_slice(&wire);
    Ok(TurnStreamFrame::Data(packet))
}

fn tls_config() -> Arc<ClientConfig> {
    static CONFIG: OnceLock<Arc<ClientConfig>> = OnceLock::new();
    CONFIG
        .get_or_init(|| {
            let mut roots = RootCertStore::empty();
            roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            Arc::new(
                ClientConfig::builder()
                    .with_root_certificates(roots)
                    .with_no_client_auth(),
            )
        })
        .clone()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn stream_reader_parses_control_and_padded_channel_data() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            stream
                .write_all(&[
                    0x01, 0x01, 0x00, 0x00, 0x21, 0x12, 0xa4, 0x42, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0,
                ])
                .await
                .unwrap();
            stream
                .write_all(&[0x40, 0x00, 0x00, 0x03, 0xa1, 0xb2, 0xc3, 0])
                .await
                .unwrap();
        });
        let endpoint = TurnEndpoint {
            host: Arc::from("127.0.0.1"),
            port: address.port(),
            transport: TurnWireTransport::Tcp,
        };
        let (_, mut reader, _) = connect(&endpoint, address).await.unwrap();
        match reader.read_frame(&PacketPool::new(1)).await.unwrap() {
            TurnStreamFrame::Control(frame) => assert_eq!(frame.len(), 20),
            _ => panic!("expected control frame"),
        }
        match reader.read_frame(&PacketPool::new(1)).await.unwrap() {
            TurnStreamFrame::Data(packet) => {
                assert_eq!(packet.as_slice(), &[0x40, 0, 0, 3, 0xa1, 0xb2, 0xc3, 0])
            }
            _ => panic!("expected channel data frame"),
        }
        server.await.unwrap();
    }

    #[tokio::test]
    async fn stream_reader_consumes_channel_data_padding_before_control() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut wire = vec![0x40, 0x00, 0x00, 0x03, 0xa1, 0xb2, 0xc3, 0];
            wire.extend_from_slice(&[
                0x01, 0x01, 0x00, 0x00, 0x21, 0x12, 0xa4, 0x42, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            ]);
            stream.write_all(&wire).await.unwrap();
        });
        let endpoint = TurnEndpoint {
            host: Arc::from("127.0.0.1"),
            port: address.port(),
            transport: TurnWireTransport::Tcp,
        };
        let (_, mut reader, _) = connect(&endpoint, address).await.unwrap();
        match reader.read_frame(&PacketPool::new(1)).await.unwrap() {
            TurnStreamFrame::Data(packet) => {
                assert_eq!(packet.as_slice(), &[0x40, 0, 0, 3, 0xa1, 0xb2, 0xc3, 0])
            }
            _ => panic!("expected channel data frame"),
        }
        match reader.read_frame(&PacketPool::new(1)).await.unwrap() {
            TurnStreamFrame::Control(frame) => assert_eq!(frame.len(), 20),
            _ => panic!("expected control frame"),
        }
        server.await.unwrap();
    }

    #[tokio::test]
    async fn stream_reader_rejects_invalid_prefix() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            stream.write_all(&[0x80, 0x00, 0xff, 0xff]).await.unwrap();
        });
        let endpoint = TurnEndpoint {
            host: Arc::from("127.0.0.1"),
            port: address.port(),
            transport: TurnWireTransport::Tcp,
        };
        let (_, mut reader, _) = connect(&endpoint, address).await.unwrap();
        match reader.read_frame(&PacketPool::new(1)).await {
            Err(error) => assert!(error.to_string().contains("reserved type range")),
            Ok(_) => panic!("invalid TURN stream frame was accepted"),
        }
        server.await.unwrap();
    }
}
