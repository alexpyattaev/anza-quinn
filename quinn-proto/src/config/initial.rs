use std::net::{IpAddr, SocketAddr};

use crate::Instant;

/// Synchronous policy for Initial packets not already routed to a connection.
///
/// Callbacks run in the endpoint receive path, potentially under its lock. They must
/// be cheap, must not block, and must not re-enter the endpoint. They may see repeated
/// Initials. Address validation is not authentication of an application identity.
pub trait InitialFilter: Send + Sync {
    /// Admit a new Initial before token authentication or Initial-key derivation.
    ///
    /// Returning false silently drops it without a response or incoming state.
    /// This applies equally to absent, forged, and valid tokens. Metadata is
    /// unauthenticated. The default imposes no limit; override to bound work with
    /// a global budget. Per-source limits alone do not bound spoofed-source traffic.
    fn allow_initial(&self, _metadata: &InitialMetadata) -> bool {
        true
    }

    /// Choose a disposition after token validation, before Initial keys or incoming state.
    ///
    /// Token processing may already have consumed a NEW_TOKEN in its replay log.
    /// Retry tokens can be replayed within their lifetime; address validation must
    /// not exempt a peer from expensive-handshake admission limits.
    fn decide(&self, context: &InitialContext) -> InitialDecision;
}

/// Disposition of an admitted Initial.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
#[non_exhaustive]
pub enum InitialDecision {
    /// Continue normal processing and create an Incoming if the packet is valid.
    Proceed,
    /// Send Retry without allocating incoming state.
    ///
    /// Avoids Initial-key derivation with the built-in provider. Custom providers
    /// must override [`crate::crypto::ServerConfig::supports_version`] with a cheap
    /// check to avoid the default key-derivation fallback.
    ///
    /// Becomes Proceed when `InitialContext::may_retry()` is false. Repeated
    /// Initials can each elicit a Retry; clients process at most one per attempt,
    /// and a Retry is far smaller than the Initial that provoked it.
    Retry,
    /// Silently drop, without Initial keys or incoming state, after token processing.
    Ignore,
}

/// Unauthenticated metadata available before token processing.
#[derive(Debug, Copy, Clone)]
pub struct InitialMetadata {
    pub(crate) remote: SocketAddr,
    pub(crate) local_ip: Option<IpAddr>,
    pub(crate) received_at: Instant,
    pub(crate) datagram_len: usize,
}

impl InitialMetadata {
    /// Source address, which may be spoofed.
    pub fn remote_address(&self) -> SocketAddr {
        self.remote
    }
    /// Destination IP, when reported by the platform.
    pub fn local_ip(&self) -> Option<IpAddr> {
        self.local_ip
    }
    /// Endpoint receive timestamp, suitable for admission budgets.
    pub fn received_at(&self) -> Instant {
        self.received_at
    }
    /// Size of the UDP datagram containing the Initial.
    pub fn datagram_len(&self) -> usize {
        self.datagram_len
    }
}

/// Metadata and token-validation results for an admitted Initial.
#[derive(Debug, Copy, Clone)]
pub struct InitialContext {
    pub(crate) metadata: InitialMetadata,
    pub(crate) validated: bool,
    pub(crate) may_retry: bool,
}

impl InitialContext {
    /// Metadata observed before token validation.
    pub fn metadata(&self) -> &InitialMetadata {
        &self.metadata
    }
    /// Source address of the packet.
    pub fn remote_address(&self) -> SocketAddr {
        self.metadata.remote
    }
    /// Destination IP, when reported by the platform.
    pub fn local_ip(&self) -> Option<IpAddr> {
        self.metadata.local_ip
    }
    /// Whether a token validated the address.
    ///
    /// NEW_TOKEN validates the IP only; Retry tokens bind both IP and port.
    pub fn remote_address_validated(&self) -> bool {
        self.validated
    }
    /// Whether another Retry is permitted (false after a valid Retry token).
    pub fn may_retry(&self) -> bool {
        self.may_retry
    }
}
