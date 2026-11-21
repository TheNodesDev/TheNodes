//! Resource limits for the TCP transport: frame size, handshake and idle
//! timeouts, and inbound connection caps.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;

use crate::config::{Config, NetworkLimitsConfig};

/// Resolved transport limits derived from `[network.limits]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NetworkLimits {
    /// Maximum size of one wire frame on an established connection.
    pub max_frame_bytes: usize,
    /// Time budget for the secure-channel handshake plus the HELLO exchange.
    pub handshake_timeout: Duration,
    /// Close a connection that delivered no frame within this window.
    /// `None` disables the idle timeout.
    pub idle_timeout: Option<Duration>,
    /// Maximum concurrently accepted inbound connections.
    pub max_inbound_connections: usize,
    /// Maximum concurrently accepted inbound connections per remote IP.
    pub max_inbound_connections_per_ip: usize,
}

impl NetworkLimits {
    pub const DEFAULT_MAX_FRAME_BYTES: usize = 1024 * 1024;
    /// Bound on a HELLO frame. Applies before the peer is authenticated and is
    /// therefore fixed rather than configurable.
    pub const MAX_HELLO_FRAME_BYTES: usize = 64 * 1024;
    pub const DEFAULT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
    pub const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(300);
    pub const DEFAULT_MAX_INBOUND_CONNECTIONS: usize = 1024;
    pub const DEFAULT_MAX_INBOUND_CONNECTIONS_PER_IP: usize = 32;

    pub fn from_limits_config(cfg: Option<&NetworkLimitsConfig>) -> Self {
        let defaults = Self::default();
        let Some(cfg) = cfg else {
            return defaults;
        };
        Self {
            max_frame_bytes: cfg
                .max_frame_bytes
                .unwrap_or(defaults.max_frame_bytes)
                .max(1),
            handshake_timeout: cfg
                .handshake_timeout_ms
                .map(|ms| Duration::from_millis(ms.max(1)))
                .unwrap_or(defaults.handshake_timeout),
            idle_timeout: match cfg.idle_timeout_ms {
                Some(0) => None,
                Some(ms) => Some(Duration::from_millis(ms)),
                None => defaults.idle_timeout,
            },
            max_inbound_connections: cfg
                .max_inbound_connections
                .unwrap_or(defaults.max_inbound_connections)
                .max(1),
            max_inbound_connections_per_ip: cfg
                .max_inbound_connections_per_ip
                .unwrap_or(defaults.max_inbound_connections_per_ip)
                .max(1),
        }
    }

    pub fn from_config(config: &Config) -> Self {
        Self::from_limits_config(config.network.as_ref().and_then(|n| n.limits.as_ref()))
    }
}

impl Default for NetworkLimits {
    fn default() -> Self {
        Self {
            max_frame_bytes: Self::DEFAULT_MAX_FRAME_BYTES,
            handshake_timeout: Self::DEFAULT_HANDSHAKE_TIMEOUT,
            idle_timeout: Some(Self::DEFAULT_IDLE_TIMEOUT),
            max_inbound_connections: Self::DEFAULT_MAX_INBOUND_CONNECTIONS,
            max_inbound_connections_per_ip: Self::DEFAULT_MAX_INBOUND_CONNECTIONS_PER_IP,
        }
    }
}

/// Why an inbound connection was refused by [`InboundConnectionLimiter`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InboundLimitReason {
    TotalCap,
    PerIpCap,
}

/// An inbound connection that was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InboundLimitRejection {
    pub reason: InboundLimitReason,
    /// True for the first rejection since the limiter last admitted a connection,
    /// so callers can log the transition into saturation once rather than per attempt.
    pub newly_saturated: bool,
}

#[derive(Default)]
struct LimiterState {
    total: usize,
    per_ip: HashMap<IpAddr, usize>,
    rejecting: bool,
}

/// Counts live inbound connections globally and per remote IP.
///
/// A connection is accounted for from [`try_acquire`](Self::try_acquire) until
/// the returned [`InboundConnectionPermit`] is dropped.
#[derive(Clone)]
pub struct InboundConnectionLimiter {
    state: Arc<Mutex<LimiterState>>,
    max_total: usize,
    max_per_ip: usize,
}

impl InboundConnectionLimiter {
    pub fn new(max_total: usize, max_per_ip: usize) -> Self {
        Self {
            state: Arc::new(Mutex::new(LimiterState::default())),
            max_total: max_total.max(1),
            max_per_ip: max_per_ip.max(1),
        }
    }

    pub fn from_limits(limits: &NetworkLimits) -> Self {
        Self::new(
            limits.max_inbound_connections,
            limits.max_inbound_connections_per_ip,
        )
    }

    pub fn try_acquire(
        &self,
        ip: IpAddr,
    ) -> Result<InboundConnectionPermit, InboundLimitRejection> {
        let mut state = self.state.lock();
        let reason = if state.total >= self.max_total {
            Some(InboundLimitReason::TotalCap)
        } else if state.per_ip.get(&ip).copied().unwrap_or(0) >= self.max_per_ip {
            Some(InboundLimitReason::PerIpCap)
        } else {
            None
        };
        if let Some(reason) = reason {
            let newly_saturated = !state.rejecting;
            state.rejecting = true;
            return Err(InboundLimitRejection {
                reason,
                newly_saturated,
            });
        }
        state.total += 1;
        *state.per_ip.entry(ip).or_insert(0) += 1;
        state.rejecting = false;
        Ok(InboundConnectionPermit {
            limiter: self.clone(),
            ip,
        })
    }

    pub fn active(&self) -> usize {
        self.state.lock().total
    }

    pub fn active_for_ip(&self, ip: IpAddr) -> usize {
        self.state.lock().per_ip.get(&ip).copied().unwrap_or(0)
    }

    fn release(&self, ip: IpAddr) {
        let mut state = self.state.lock();
        state.total = state.total.saturating_sub(1);
        if let Some(count) = state.per_ip.get_mut(&ip) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                state.per_ip.remove(&ip);
            }
        }
    }
}

/// Holds one slot in an [`InboundConnectionLimiter`] for as long as it lives.
pub struct InboundConnectionPermit {
    limiter: InboundConnectionLimiter,
    ip: IpAddr,
}

impl std::fmt::Debug for InboundConnectionPermit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InboundConnectionPermit")
            .field("ip", &self.ip)
            .finish_non_exhaustive()
    }
}

impl Drop for InboundConnectionPermit {
    fn drop(&mut self) {
        self.limiter.release(self.ip);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(last: u8) -> IpAddr {
        IpAddr::from([10, 0, 0, last])
    }

    #[test]
    fn defaults_apply_when_section_is_missing() {
        let limits = NetworkLimits::from_limits_config(None);
        assert_eq!(limits, NetworkLimits::default());
        assert_eq!(limits.idle_timeout, Some(Duration::from_secs(300)));
    }

    #[test]
    fn zero_idle_timeout_disables_it() {
        let cfg = NetworkLimitsConfig {
            idle_timeout_ms: Some(0),
            ..NetworkLimitsConfig::default()
        };
        assert_eq!(
            NetworkLimits::from_limits_config(Some(&cfg)).idle_timeout,
            None
        );
    }

    #[test]
    fn per_ip_and_total_caps_release_on_drop() {
        let limiter = InboundConnectionLimiter::new(3, 2);
        let a1 = limiter.try_acquire(ip(1)).unwrap();
        let _a2 = limiter.try_acquire(ip(1)).unwrap();
        let per_ip = limiter.try_acquire(ip(1)).unwrap_err();
        assert_eq!(per_ip.reason, InboundLimitReason::PerIpCap);
        assert!(per_ip.newly_saturated);

        let _b1 = limiter.try_acquire(ip(2)).unwrap();
        let total = limiter.try_acquire(ip(3)).unwrap_err();
        assert_eq!(total.reason, InboundLimitReason::TotalCap);
        assert!(total.newly_saturated);
        assert!(!limiter.try_acquire(ip(3)).unwrap_err().newly_saturated);

        drop(a1);
        assert_eq!(limiter.active(), 2);
        assert_eq!(limiter.active_for_ip(ip(1)), 1);
        let _a3 = limiter.try_acquire(ip(1)).unwrap();
        assert_eq!(limiter.active(), 3);
    }
}
