use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use igd_next::{aio::tokio::search_gateway, PortMappingProtocol, SearchOptions};

use crate::config::NatConfig;
use crate::events::model::LogLevel;
use crate::network::events::emit_network_event;
use crate::network::peer_manager::PeerManager;

const DEFAULT_LEASE_DURATION_SECS: u32 = 3600;
const SEARCH_TIMEOUT_SECS: u64 = 2;
const SINGLE_SEARCH_TIMEOUT_MS: u64 = 750;
const PORT_MAPPING_DESCRIPTION: &str = "TheNodes listen port";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NatType {
    Unknown,
    UpnpMapped,
    ConeLike,
    SymmetricLike,
    DoubleNatLikely,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NatDiagnostic {
    pub nat_type: NatType,
    pub direct_tcp_hint: bool,
    pub gateway_external_ip: Option<IpAddr>,
    pub mapped_tcp_addr: Option<SocketAddr>,
    pub observed_udp_endpoints: Vec<SocketAddr>,
}

impl NatDiagnostic {
    fn summary(&self) -> String {
        let observed = self
            .observed_udp_endpoints
            .iter()
            .map(SocketAddr::to_string)
            .collect::<Vec<_>>()
            .join(",");
        format!(
            "classification={:?} direct_tcp_hint={} gateway_external_ip={:?} mapped_tcp_addr={:?} observed_udp_endpoints=[{}]",
            self.nat_type,
            self.direct_tcp_hint,
            self.gateway_external_ip,
            self.mapped_tcp_addr,
            observed
        )
    }
}

pub async fn initialize_port_mapping(
    peer_manager: &PeerManager,
    cfg: &NatConfig,
    listen_port: u16,
    allow_console: bool,
) {
    if !cfg.enabled.unwrap_or(false) {
        return;
    }

    let lease_duration_secs = cfg
        .lease_duration_secs
        .unwrap_or(DEFAULT_LEASE_DURATION_SECS);
    if !attempt_port_mapping(
        peer_manager,
        lease_duration_secs,
        listen_port,
        allow_console,
    )
    .await
        || lease_duration_secs == 0
    {
        return;
    }

    let peer_manager = peer_manager.clone();
    tokio::spawn(async move {
        let renewal_delay = Duration::from_secs(u64::from(
            lease_duration_secs
                .saturating_mul(3)
                .saturating_div(4)
                .max(1),
        ));
        let retry_delay = Duration::from_secs(60);
        let mut delay = renewal_delay;
        loop {
            tokio::time::sleep(delay).await;
            let renewed = attempt_port_mapping(
                &peer_manager,
                lease_duration_secs,
                listen_port,
                allow_console,
            )
            .await;
            delay = if renewed { renewal_delay } else { retry_delay };
        }
    });
}

async fn attempt_port_mapping(
    peer_manager: &PeerManager,
    lease_duration_secs: u32,
    listen_port: u16,
    allow_console: bool,
) -> bool {
    peer_manager.set_gateway_external_ip(None);
    peer_manager.set_public_tcp_hello_addr(None);
    peer_manager.set_direct_tcp_hint(false);

    let gateway = match discover_gateway().await {
        Ok(gateway) => gateway,
        Err(err) => {
            emit_network_event(
                "nat_portmap",
                LogLevel::Debug,
                "upnp_gateway_unavailable",
                None,
                Some(err),
                allow_console,
            );
            refresh_nat_diagnostic(peer_manager, allow_console).await;
            return false;
        }
    };

    let local_addr = match infer_local_mapping_addr(gateway.addr, listen_port).await {
        Ok(addr) => addr,
        Err(err) => {
            emit_network_event(
                "nat_portmap",
                LogLevel::Warn,
                "upnp_local_addr_resolve_failed",
                Some(gateway.addr.to_string()),
                Some(err.to_string()),
                allow_console,
            );
            refresh_nat_diagnostic(peer_manager, allow_console).await;
            return false;
        }
    };

    let external_ip = match gateway.get_external_ip().await {
        Ok(ip) => ip,
        Err(err) => {
            emit_network_event(
                "nat_portmap",
                LogLevel::Warn,
                "upnp_external_ip_failed",
                Some(gateway.addr.to_string()),
                Some(err.to_string()),
                allow_console,
            );
            refresh_nat_diagnostic(peer_manager, allow_console).await;
            return false;
        }
    };

    peer_manager.set_gateway_external_ip(Some(external_ip.to_string()));

    let behind_nat = local_addr.ip() != external_ip || !is_publicly_routable(local_addr.ip());
    if !behind_nat {
        let public_addr = SocketAddr::new(external_ip, listen_port);
        if is_publicly_routable(public_addr.ip()) {
            peer_manager.set_public_tcp_hello_addr(Some(public_addr.to_string()));
        }
        refresh_nat_diagnostic(peer_manager, allow_console).await;
        emit_network_event(
            "nat_portmap",
            LogLevel::Info,
            "upnp_public_direct",
            Some(gateway.addr.to_string()),
            Some(format!(
                "listen_addr={} external_ip={}",
                local_addr, external_ip
            )),
            allow_console,
        );
        return false;
    }

    let mapped = match gateway
        .add_port(
            PortMappingProtocol::TCP,
            listen_port,
            local_addr,
            lease_duration_secs,
            PORT_MAPPING_DESCRIPTION,
        )
        .await
    {
        Ok(()) => {
            let mapped_addr = SocketAddr::new(external_ip, listen_port);
            if is_publicly_routable(mapped_addr.ip()) {
                peer_manager.set_public_tcp_hello_addr(Some(mapped_addr.to_string()));
            }
            emit_network_event(
                "nat_portmap",
                LogLevel::Info,
                "upnp_mapping_established",
                Some(gateway.addr.to_string()),
                Some(format!(
                    "local_addr={} mapped_addr={} lease_duration_secs={}",
                    local_addr, mapped_addr, lease_duration_secs
                )),
                allow_console,
            );
            true
        }
        Err(err) => {
            emit_network_event(
                "nat_portmap",
                LogLevel::Warn,
                "upnp_mapping_failed",
                Some(gateway.addr.to_string()),
                Some(format!(
                    "local_addr={} external_ip={} port={} error={}",
                    local_addr, external_ip, listen_port, err
                )),
                allow_console,
            );
            false
        }
    };

    refresh_nat_diagnostic(peer_manager, allow_console).await;
    mapped
}

pub async fn refresh_nat_diagnostic(peer_manager: &PeerManager, allow_console: bool) {
    let max_age_secs = peer_manager.nat_observation_refresh_secs().await;
    let observed_udp_endpoints = peer_manager
        .own_udp_observed_records_if_fresh(max_age_secs)
        .await
        .into_iter()
        .filter_map(|record| record.addr.parse::<SocketAddr>().ok())
        .collect::<Vec<_>>();
    let gateway_external_ip = peer_manager
        .gateway_external_ip()
        .and_then(|value| value.parse::<IpAddr>().ok());
    let mapped_tcp_addr = peer_manager
        .public_tcp_hello_addr()
        .and_then(|value| value.parse::<SocketAddr>().ok());
    let diagnostic = classify_nat(
        gateway_external_ip,
        mapped_tcp_addr,
        &observed_udp_endpoints,
    );
    peer_manager.set_direct_tcp_hint(diagnostic.direct_tcp_hint);

    let summary = diagnostic.summary();
    if peer_manager.replace_nat_diagnostic_summary(Some(summary.clone())) {
        emit_network_event(
            "nat_portmap",
            LogLevel::Info,
            "nat_diagnostic_updated",
            None,
            Some(summary),
            allow_console,
        );
    }
}

pub fn classify_nat(
    gateway_external_ip: Option<IpAddr>,
    mapped_tcp_addr: Option<SocketAddr>,
    observed_udp_endpoints: &[SocketAddr],
) -> NatDiagnostic {
    let observation_count = observed_udp_endpoints.len();
    let observed_udp_endpoints = {
        let mut deduped = observed_udp_endpoints.to_vec();
        deduped.sort_unstable();
        deduped.dedup();
        deduped
    };
    let observed_ips = observed_udp_endpoints
        .iter()
        .map(|addr| addr.ip())
        .collect::<BTreeSet<_>>();
    let observed_ports = observed_udp_endpoints
        .iter()
        .map(|addr| addr.port())
        .collect::<BTreeSet<_>>();
    let mapped_tcp_public = mapped_tcp_addr.filter(|addr| is_publicly_routable(addr.ip()));

    let nat_type = if observation_count == 0 {
        if mapped_tcp_public.is_some() {
            NatType::UpnpMapped
        } else {
            NatType::Unknown
        }
    } else if observation_count == 1 {
        NatType::Unknown
    } else if observed_ips.len() > 1 {
        NatType::DoubleNatLikely
    } else {
        let observed_ip = observed_ips.iter().next().copied();
        if gateway_external_ip
            .zip(observed_ip)
            .is_some_and(|(gateway_ip, observed_ip)| {
                is_publicly_routable(observed_ip) && gateway_ip != observed_ip
            })
        {
            NatType::DoubleNatLikely
        } else if observed_ports.len() > 1 {
            NatType::SymmetricLike
        } else {
            NatType::ConeLike
        }
    };

    NatDiagnostic {
        nat_type,
        direct_tcp_hint: mapped_tcp_public.is_some() && nat_type != NatType::DoubleNatLikely,
        gateway_external_ip,
        mapped_tcp_addr: mapped_tcp_public,
        observed_udp_endpoints,
    }
}

async fn discover_gateway() -> Result<igd_next::aio::Gateway<igd_next::aio::tokio::Tokio>, String> {
    search_gateway(SearchOptions {
        timeout: Some(Duration::from_secs(SEARCH_TIMEOUT_SECS)),
        single_search_timeout: Some(Duration::from_millis(SINGLE_SEARCH_TIMEOUT_MS)),
        ..Default::default()
    })
    .await
    .map_err(|err| err.to_string())
}

async fn infer_local_mapping_addr(
    gateway_addr: SocketAddr,
    listen_port: u16,
) -> Result<SocketAddr, std::io::Error> {
    let bind_addr = if gateway_addr.is_ipv4() {
        SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0))
    } else {
        "[::]:0".parse().expect("valid IPv6 bind address")
    };
    let socket = tokio::net::UdpSocket::bind(bind_addr).await?;
    socket.connect(gateway_addr).await?;
    Ok(SocketAddr::new(socket.local_addr()?.ip(), listen_port))
}

fn is_publicly_routable(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ipv4) => {
            let [a, b, ..] = ipv4.octets();
            !ipv4.is_private()
                && !ipv4.is_loopback()
                && !ipv4.is_link_local()
                && !ipv4.is_multicast()
                && !ipv4.is_broadcast()
                && !ipv4.is_documentation()
                && !ipv4.is_unspecified()
                && !(a == 100 && (64..=127).contains(&b))
                && !(a == 198 && (b == 18 || b == 19))
                && a != 0
                && a < 224
        }
        IpAddr::V6(ipv6) => {
            let segments = ipv6.segments();
            let is_unique_local = segments[0] & 0xfe00 == 0xfc00;
            let is_unicast_link_local = segments[0] & 0xffc0 == 0xfe80;
            !ipv6.is_loopback()
                && !ipv6.is_multicast()
                && !ipv6.is_unspecified()
                && !is_unique_local
                && !is_unicast_link_local
                && !(segments[0] == 0x2001 && segments[1] == 0x0db8)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{classify_nat, discover_gateway, NatType};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    #[test]
    fn classifies_consistent_observed_endpoints_as_cone_like() {
        let diagnostic = classify_nat(
            Some(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))),
            Some("8.8.8.8:50000".parse().unwrap()),
            &[
                "8.8.8.8:46000".parse().unwrap(),
                "8.8.8.8:46000".parse().unwrap(),
            ],
        );

        assert_eq!(diagnostic.nat_type, NatType::ConeLike);
        assert!(diagnostic.direct_tcp_hint);
        assert_eq!(
            diagnostic.mapped_tcp_addr,
            Some("8.8.8.8:50000".parse().unwrap())
        );
    }

    #[test]
    fn keeps_single_observed_endpoint_unknown() {
        let diagnostic = classify_nat(
            Some(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))),
            None,
            &["8.8.8.8:46000".parse().unwrap()],
        );

        assert_eq!(diagnostic.nat_type, NatType::Unknown);
    }

    #[test]
    fn classifies_mismatched_external_ip_as_double_nat() {
        let diagnostic = classify_nat(
            Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))),
            None,
            &[
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 4, 4)), 40100),
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 4, 4)), 40100),
            ],
        );

        assert_eq!(diagnostic.nat_type, NatType::DoubleNatLikely);
        assert!(!diagnostic.direct_tcp_hint);
    }

    #[test]
    fn classifies_port_variation_as_symmetric_like() {
        let diagnostic = classify_nat(
            Some(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))),
            Some("1.1.1.1:50000".parse().unwrap()),
            &[
                "1.1.1.1:41000".parse().unwrap(),
                "1.1.1.1:41032".parse().unwrap(),
            ],
        );

        assert_eq!(diagnostic.nat_type, NatType::SymmetricLike);
        assert!(diagnostic.direct_tcp_hint);
    }

    #[tokio::test]
    async fn igd_gateway_path_skips_cleanly_without_device() {
        match discover_gateway().await {
            Ok(gateway) => {
                let external_ip = gateway.get_external_ip().await.expect("external IP");
                assert_ne!(external_ip, IpAddr::V4(Ipv4Addr::UNSPECIFIED));
            }
            Err(err) => {
                eprintln!("skipping IGD gateway path test: {err}");
            }
        }
    }
}
