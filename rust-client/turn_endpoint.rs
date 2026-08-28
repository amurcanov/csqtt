// SPDX-FileCopyrightText: 2026 amurcanov
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

use anyhow::{Context, Result, anyhow, bail};
use std::{net::IpAddr, str::FromStr, sync::Arc};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TurnTransportMode {
    Udp,
    TcpTls,
}

impl TurnTransportMode {
    pub fn parse(value: &str) -> Result<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "udp" => Ok(Self::Udp),
            "tcp" | "tcp_tls" | "tcp-tls" | "tcp/tls" => Ok(Self::TcpTls),
            value => bail!("unsupported TURN transport mode {value:?}"),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Udp => "UDP",
            Self::TcpTls => "TCP",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TurnWireTransport {
    Udp,
    Tcp,
    Tls,
}

impl TurnWireTransport {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Udp => "UDP",
            Self::Tcp => "TCP",
            Self::Tls => "TLS",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TurnEndpoint {
    pub host: Arc<str>,
    pub port: u16,
    pub transport: TurnWireTransport,
}

impl TurnEndpoint {
    pub fn socket_authority(&self) -> String {
        if self.host.contains(':') {
            format!("[{}]:{}", self.host, self.port)
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }

    pub fn tls_server_name(&self) -> Result<&str> {
        if self.transport != TurnWireTransport::Tls {
            bail!("TURN endpoint is not TLS")
        }
        if IpAddr::from_str(&self.host).is_ok() {
            bail!("TURN TLS endpoint requires a DNS hostname")
        }
        Ok(&self.host)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TurnScheme {
    Turn,
    Turns,
    Bare,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum UriTransport {
    Udp,
    Tcp,
}

pub fn resolve_turn_endpoints(
    value: &str,
    override_host: Option<&str>,
    override_port: Option<&str>,
    mode: TurnTransportMode,
) -> Result<Vec<TurnEndpoint>> {
    let (scheme, authority, uri_transport) = parse_turn_uri(value)?;
    let (original_host, original_port) = parse_authority(authority, scheme)?;
    let host = override_host
        .filter(|value| !value.trim().is_empty())
        .map(str::trim)
        .unwrap_or(original_host);
    let port = override_port
        .filter(|value| !value.trim().is_empty())
        .map(str::trim)
        .map(str::parse)
        .transpose()
        .context("TURN port is invalid")?
        .unwrap_or(original_port);
    if host.is_empty() {
        bail!("TURN host is empty")
    }
    let host: Arc<str> = Arc::from(host);

    let transports: &[TurnWireTransport] = match mode {
        TurnTransportMode::Udp => match (scheme, uri_transport) {
            (TurnScheme::Turns, _) => bail!("TURN TLS endpoint cannot be used in UDP mode"),
            (_, Some(UriTransport::Tcp)) => bail!("TURN TCP endpoint cannot be used in UDP mode"),
            _ => &[TurnWireTransport::Udp],
        },
        TurnTransportMode::TcpTls => match (scheme, uri_transport) {
            (_, Some(UriTransport::Udp)) => {
                bail!("TURN UDP endpoint cannot be used in TCP mode")
            }
            (TurnScheme::Turns, _) => &[TurnWireTransport::Tls],
            (_, Some(UriTransport::Tcp)) => &[TurnWireTransport::Tcp],
            (_, None) => &[TurnWireTransport::Tcp],
        },
    };

    Ok(transports
        .iter()
        .copied()
        .map(|transport| TurnEndpoint {
            host: host.clone(),
            port,
            transport,
        })
        .collect())
}

pub fn is_supported_turn_uri(value: &str) -> bool {
    parse_turn_uri(value).is_ok()
}

fn parse_turn_uri(value: &str) -> Result<(TurnScheme, &str, Option<UriTransport>)> {
    let value = value.trim();
    if value.is_empty() {
        bail!("TURN endpoint is empty")
    }
    let lower = value.to_ascii_lowercase();
    let (scheme, value) = if lower.starts_with("turns:") {
        (TurnScheme::Turns, &value["turns:".len()..])
    } else if lower.starts_with("turn:") {
        (TurnScheme::Turn, &value["turn:".len()..])
    } else {
        (TurnScheme::Bare, value)
    };
    let (authority, query) = value.split_once('?').unwrap_or((value, ""));
    if authority.is_empty() {
        bail!("TURN authority is empty")
    }
    let mut uri_transport = None;
    for parameter in query.split('&').filter(|parameter| !parameter.is_empty()) {
        let (key, value) = parameter.split_once('=').unwrap_or((parameter, ""));
        if key.eq_ignore_ascii_case("transport") {
            let parsed = match value.to_ascii_lowercase().as_str() {
                "udp" => UriTransport::Udp,
                "tcp" => UriTransport::Tcp,
                _ => bail!("TURN URI contains an unsupported transport"),
            };
            if uri_transport.replace(parsed).is_some() {
                bail!("TURN URI contains duplicate transport parameters")
            }
        }
    }
    if scheme == TurnScheme::Turns && uri_transport == Some(UriTransport::Udp) {
        bail!("turns URI cannot use UDP")
    }
    Ok((scheme, authority, uri_transport))
}

fn parse_authority(value: &str, scheme: TurnScheme) -> Result<(&str, u16)> {
    let default_port = match scheme {
        TurnScheme::Turns => 5349,
        TurnScheme::Turn | TurnScheme::Bare => 3478,
    };
    if let Some(rest) = value.strip_prefix('[') {
        let Some((host, port)) = rest.split_once("]:") else {
            let host = rest
                .strip_suffix(']')
                .ok_or_else(|| anyhow!("TURN IPv6 address is malformed"))?;
            return Ok((host, default_port));
        };
        return Ok((host, port.parse().context("TURN port is invalid")?));
    }
    if value.matches(':').count() > 1 {
        bail!("TURN IPv6 address must use brackets")
    }
    if let Some((host, port)) = value.rsplit_once(':') {
        if host.is_empty() {
            bail!("TURN host is empty")
        }
        return Ok((host, port.parse().context("TURN port is invalid")?));
    }
    Ok((value, default_port))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tcp_mode_accepts_current_and_legacy_cli_values() {
        assert_eq!(
            TurnTransportMode::parse("tcp").unwrap(),
            TurnTransportMode::TcpTls
        );
        assert_eq!(
            TurnTransportMode::parse("tcp_tls").unwrap(),
            TurnTransportMode::TcpTls
        );
        assert_eq!(TurnTransportMode::TcpTls.as_str(), "TCP");
    }

    #[test]
    fn udp_mode_accepts_bare_and_explicit_udp_uris() {
        let bare = resolve_turn_endpoints(
            "turn:relay.example:3478",
            None,
            None,
            TurnTransportMode::Udp,
        )
        .unwrap();
        assert_eq!(bare[0].transport, TurnWireTransport::Udp);
        let explicit = resolve_turn_endpoints(
            "turn:relay.example:3478?transport=udp",
            None,
            None,
            TurnTransportMode::Udp,
        )
        .unwrap();
        assert_eq!(explicit[0].socket_authority(), "relay.example:3478");
    }

    #[test]
    fn tcp_mode_uses_raw_tcp_for_turn_uris() {
        let candidates = resolve_turn_endpoints(
            "turn:relay.example:3478",
            None,
            None,
            TurnTransportMode::TcpTls,
        )
        .unwrap();
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].transport, TurnWireTransport::Tcp);
        assert!(
            resolve_turn_endpoints(
                "turn:relay.example:3478?transport=udp",
                None,
                None,
                TurnTransportMode::TcpTls,
            )
            .is_err()
        );
    }

    #[test]
    fn turns_uri_requires_tls_with_hostname() {
        let candidates = resolve_turn_endpoints(
            "turns:relay.example:5349?transport=tcp",
            None,
            None,
            TurnTransportMode::TcpTls,
        )
        .unwrap();
        assert_eq!(candidates[0].transport, TurnWireTransport::Tls);
        assert_eq!(candidates[0].tls_server_name().unwrap(), "relay.example");
        assert!(
            resolve_turn_endpoints(
                "turns:192.0.2.1:5349",
                None,
                None,
                TurnTransportMode::TcpTls,
            )
            .unwrap()[0]
                .tls_server_name()
                .is_err()
        );
    }

    #[test]
    fn tcp_uri_is_preserved_for_tcp_mode() {
        let candidates = resolve_turn_endpoints(
            "turn:relay.example:3478?transport=tcp",
            Some("override.example"),
            Some("19302"),
            TurnTransportMode::TcpTls,
        )
        .unwrap();
        assert_eq!(candidates[0].transport, TurnWireTransport::Tcp);
        assert_eq!(candidates[0].socket_authority(), "override.example:19302");
    }
}
