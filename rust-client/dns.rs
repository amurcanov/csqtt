// SPDX-FileCopyrightText: 2026 amurcanov
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

use anyhow::{Context, Result, bail};
use primp::dns::{Addrs, Name, Resolve, Resolving};
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{
        Arc, OnceLock,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use tokio::{net::UdpSocket, time::timeout};

const YANDEX_DNS_SERVERS: [SocketAddr; 2] = [
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(77, 88, 8, 8)), 53),
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(77, 88, 8, 1)), 53),
];
const DNS_TIMEOUT: Duration = Duration::from_secs(5);
const DNS_A_RECORD: u16 = 1;
const DNS_AAAA_RECORD: u16 = 28;
static TUNNEL_ACTIVE: AtomicBool = AtomicBool::new(false);

enum YandexDnsError {
    TimedOut,
    Failed(anyhow::Error),
}

pub struct DnsResolver;

impl DnsResolver {
    pub async fn lookup(&self, host: &str) -> Result<Vec<IpAddr>> {
        if let Ok(address) = host.parse::<IpAddr>() {
            return Ok(vec![address]);
        }

        match yandex_lookup(host).await {
            Ok(addresses) if !addresses.is_empty() => Ok(addresses),
            Ok(_) => bail!("пустой DNS-ответ Yandex для {host}"),
            Err(YandexDnsError::TimedOut) if !tunnel_active() => system_lookup(host).await,
            Err(YandexDnsError::TimedOut) => {
                bail!("Yandex DNS не ответил за 5 секунд для {host}");
            }
            Err(YandexDnsError::Failed(error)) => {
                Err(error).with_context(|| format!("DNS lookup Yandex {host}"))
            }
        }
    }
}

async fn system_lookup(host: &str) -> Result<Vec<IpAddr>> {
    let mut addresses = Vec::new();
    for address in tokio::net::lookup_host((host, 0))
        .await
        .with_context(|| format!("системный DNS lookup {host}"))?
    {
        let address = address.ip();
        if !addresses.contains(&address) {
            addresses.push(address);
        }
    }
    if addresses.is_empty() {
        bail!("пустой системный DNS-ответ для {host}");
    }
    Ok(addresses)
}

async fn yandex_lookup(host: &str) -> std::result::Result<Vec<IpAddr>, YandexDnsError> {
    let query_id = rand::random::<u16>();
    let a_query = build_query(host, query_id, DNS_A_RECORD).map_err(YandexDnsError::Failed)?;
    let a_answers = query_yandex(a_query, query_id).await?;
    if !a_answers.is_empty() {
        return Ok(a_answers);
    }

    let aaaa_id = query_id.wrapping_add(1);
    let aaaa_query = build_query(host, aaaa_id, DNS_AAAA_RECORD).map_err(YandexDnsError::Failed)?;
    query_yandex(aaaa_query, aaaa_id).await
}

async fn query_yandex(
    query: Vec<u8>,
    query_id: u16,
) -> std::result::Result<Vec<IpAddr>, YandexDnsError> {
    let response = timeout(DNS_TIMEOUT, async {
        let primary = query_dns_server(YANDEX_DNS_SERVERS[0], query.clone(), query_id);
        let secondary = query_dns_server(YANDEX_DNS_SERVERS[1], query, query_id);
        tokio::pin!(primary);
        tokio::pin!(secondary);

        let (first_primary, first_result) = tokio::select! {
            result = &mut primary => (true, result),
            result = &mut secondary => (false, result),
        };
        match first_result {
            Ok(addresses) => Ok(addresses),
            Err(first_error) => {
                let second_result = if first_primary {
                    secondary.await
                } else {
                    primary.await
                };
                second_result.map_err(|second_error| {
                    anyhow::anyhow!(
                        "оба сервера Yandex DNS отклонили запрос: {first_error}; {second_error}"
                    )
                })
            }
        }
    })
    .await;

    match response {
        Ok(Ok(addresses)) => Ok(addresses),
        Ok(Err(error)) => Err(YandexDnsError::Failed(error)),
        Err(_) => Err(YandexDnsError::TimedOut),
    }
}

async fn query_dns_server(
    server: SocketAddr,
    query: Vec<u8>,
    query_id: u16,
) -> Result<Vec<IpAddr>> {
    let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))
        .await
        .context("создание UDP-сокета DNS")?;
    socket
        .send_to(&query, server)
        .await
        .with_context(|| format!("отправка DNS-запроса к {server}"))?;

    let mut response = [0_u8; 1500];
    loop {
        let (length, source) = socket
            .recv_from(&mut response)
            .await
            .with_context(|| format!("получение DNS-ответа от {server}"))?;
        if source != server {
            continue;
        }
        return parse_response(&response[..length], query_id);
    }
}

fn build_query(host: &str, query_id: u16, record_type: u16) -> Result<Vec<u8>> {
    let host = host.trim_end_matches('.');
    if host.is_empty() || host.len() > 253 {
        bail!("некорректное DNS-имя {host:?}");
    }

    let mut query = Vec::with_capacity(host.len() + 18);
    query.extend_from_slice(&query_id.to_be_bytes());
    query.extend_from_slice(&0x0100_u16.to_be_bytes());
    query.extend_from_slice(&1_u16.to_be_bytes());
    query.extend_from_slice(&0_u16.to_be_bytes());
    query.extend_from_slice(&0_u16.to_be_bytes());
    query.extend_from_slice(&0_u16.to_be_bytes());
    for label in host.split('.') {
        if label.is_empty() || label.len() > 63 || !label.is_ascii() {
            bail!("некорректная DNS-метка {label:?}");
        }
        query.push(label.len() as u8);
        query.extend_from_slice(label.as_bytes());
    }
    query.push(0);
    query.extend_from_slice(&record_type.to_be_bytes());
    query.extend_from_slice(&1_u16.to_be_bytes());
    Ok(query)
}

fn parse_response(response: &[u8], query_id: u16) -> Result<Vec<IpAddr>> {
    if response.len() < 12 {
        bail!("слишком короткий DNS-ответ");
    }
    if read_u16(response, 0)? != query_id {
        bail!("DNS-ответ с чужим идентификатором");
    }
    let flags = read_u16(response, 2)?;
    if flags & 0x8000 == 0 {
        bail!("DNS-ответ без флага response");
    }
    if flags & 0x0200 != 0 {
        bail!("DNS-ответ требует TCP-повторения");
    }
    let status = flags & 0x000f;
    if status != 0 {
        bail!("DNS-ответ с кодом {status}");
    }

    let questions = read_u16(response, 4)? as usize;
    let answers = read_u16(response, 6)? as usize;
    let mut offset = 12;
    for _ in 0..questions {
        offset = skip_name(response, offset)?;
        offset = offset
            .checked_add(4)
            .filter(|value| *value <= response.len())
            .context("повреждён DNS-вопрос")?;
    }

    let mut addresses = Vec::new();
    for _ in 0..answers {
        offset = skip_name(response, offset)?;
        let record_type = read_u16(response, offset)?;
        let record_class = read_u16(response, offset + 2)?;
        let data_length = read_u16(response, offset + 8)? as usize;
        let data_offset = offset
            .checked_add(10)
            .filter(|value| *value <= response.len())
            .context("повреждён DNS-ответ")?;
        let next_offset = data_offset
            .checked_add(data_length)
            .filter(|value| *value <= response.len())
            .context("повреждён DNS resource record")?;
        if record_class == 1 && record_type == DNS_A_RECORD && data_length == 4 {
            let address = IpAddr::V4(Ipv4Addr::new(
                response[data_offset],
                response[data_offset + 1],
                response[data_offset + 2],
                response[data_offset + 3],
            ));
            if !addresses.contains(&address) {
                addresses.push(address);
            }
        }
        if record_class == 1 && record_type == DNS_AAAA_RECORD && data_length == 16 {
            let mut octets = [0_u8; 16];
            octets.copy_from_slice(&response[data_offset..next_offset]);
            let address = IpAddr::V6(Ipv6Addr::from(octets));
            if !addresses.contains(&address) {
                addresses.push(address);
            }
        }
        offset = next_offset;
    }
    Ok(addresses)
}

fn skip_name(message: &[u8], mut offset: usize) -> Result<usize> {
    loop {
        let length = *message.get(offset).context("повреждён DNS name")?;
        if length & 0xc0 == 0xc0 {
            return offset
                .checked_add(2)
                .filter(|value| *value <= message.len())
                .context("повреждён DNS compression pointer");
        }
        if length & 0xc0 != 0 {
            bail!("некорректный DNS name");
        }
        offset = offset.checked_add(1).context("переполнение DNS name")?;
        if length == 0 {
            return Ok(offset);
        }
        offset = offset
            .checked_add(length as usize)
            .filter(|value| *value <= message.len())
            .context("обрезанный DNS name")?;
    }
}

fn read_u16(message: &[u8], offset: usize) -> Result<u16> {
    let bytes = message
        .get(offset..offset + 2)
        .context("обрезанный DNS-заголовок")?;
    Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
}

pub fn mark_tunnel_active() {
    TUNNEL_ACTIVE.store(true, Ordering::Release);
}

fn tunnel_active() -> bool {
    TUNNEL_ACTIVE.load(Ordering::Acquire)
}

impl Resolve for DnsResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let host = name.as_str().to_owned();
        let resolver = global();
        Box::pin(async move {
            let addresses = resolver
                .lookup(&host)
                .await
                .map_err(|error| -> Box<dyn std::error::Error + Send + Sync> { error.into() })?;
            Ok(Box::new(
                addresses
                    .into_iter()
                    .map(|address| SocketAddr::new(address, 0)),
            ) as Addrs)
        })
    }
}

pub fn global() -> Arc<DnsResolver> {
    static RESOLVER: OnceLock<Arc<DnsResolver>> = OnceLock::new();
    RESOLVER.get_or_init(|| Arc::new(DnsResolver)).clone()
}

pub async fn resolve_socket(address: &str) -> Result<SocketAddr> {
    if let Ok(address) = address.parse::<SocketAddr>() {
        return Ok(address);
    }
    let parsed = url::Url::parse(&format!("udp://{address}"))
        .with_context(|| format!("разбор адреса {address:?}"))?;
    let host = parsed.host_str().context("адрес не содержит имя хоста")?;
    let port = parsed.port().context("адрес не содержит порт")?;
    let ip = global()
        .lookup(host)
        .await?
        .into_iter()
        .next()
        .context("пустой DNS-ответ")?;
    Ok(SocketAddr::new(ip, port))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_compressed_ipv4_answer() {
        let response = [
            0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x02, b'v',
            b'k', 0x02, b'r', b'u', 0x00, 0x00, 0x01, 0x00, 0x01, 0xc0, 0x0c, 0x00, 0x01, 0x00,
            0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x04, 77, 88, 8, 8,
        ];
        assert_eq!(
            parse_response(&response, 0x1234).unwrap(),
            vec![IpAddr::V4(Ipv4Addr::new(77, 88, 8, 8))]
        );
    }

    #[test]
    fn query_rejects_invalid_dns_name() {
        assert!(build_query("", 1, DNS_A_RECORD).is_err());
        assert!(build_query("a..vk.ru", 1, DNS_A_RECORD).is_err());
    }

    #[tokio::test]
    async fn literal_socket_does_not_require_dns() {
        assert_eq!(
            resolve_socket("127.0.0.1:46000").await.unwrap(),
            "127.0.0.1:46000".parse().unwrap()
        );
        assert_eq!(
            resolve_socket("[::1]:46000").await.unwrap(),
            "[::1]:46000".parse().unwrap()
        );
    }
}
