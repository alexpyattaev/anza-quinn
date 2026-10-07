//! Admission ordering and fast Retry regressions
use super::*;
use crate::{
    crypto::{HandshakeTokenKey, Keys, UnsupportedVersion},
    token::{Token, TokenPayload},
};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

/// `InitialFilter` with a switchable admission gate and a fixed verdict, recording what it saw
struct Policy {
    allow: AtomicBool,
    verdict: InitialDecision,
    seen: Mutex<Vec<InitialContext>>,
    admitted: AtomicUsize,
}

impl Policy {
    fn new(verdict: InitialDecision) -> Arc<Self> {
        Arc::new(Self {
            allow: AtomicBool::new(true),
            verdict,
            seen: Mutex::new(Vec::new()),
            admitted: AtomicUsize::new(0),
        })
    }

    fn seen(&self) -> Vec<InitialContext> {
        self.seen.lock().expect("policy mutex poisoned").clone()
    }
}

impl InitialFilter for Policy {
    fn allow_initial(&self, meta: &InitialMetadata) -> bool {
        assert!(
            meta.datagram_len() >= usize::from(MIN_INITIAL_SIZE),
            "short datagrams must be dropped before the admission gate"
        );
        self.admitted.fetch_add(1, Ordering::Relaxed);
        self.allow.load(Ordering::Relaxed)
    }

    fn decide(&self, context: &InitialContext) -> InitialDecision {
        self.seen
            .lock()
            .expect("policy mutex poisoned")
            .push(*context);
        self.verdict
    }
}

/// Number of expensive operations performed by the server
#[derive(Default)]
struct Counts {
    initial_keys: AtomicUsize,
    retry_tags: AtomicUsize,
    token_aeads: AtomicUsize,
    token_log: AtomicUsize,
}

impl Counts {
    /// `[initial_keys, retry_tags, token_aeads, token_log]`
    fn values(&self) -> [usize; 4] {
        [
            &self.initial_keys,
            &self.retry_tags,
            &self.token_aeads,
            &self.token_log,
        ]
        .map(|v| v.load(Ordering::Relaxed))
    }
}

/// Crypto provider counting expensive operations, optionally rejecting every version
///
/// Intentionally uses the default `supports_version`, exercising custom-provider compatibility.
struct SpyCrypto {
    inner: Arc<dyn crypto::ServerConfig>,
    counts: Arc<Counts>,
    reject: bool,
}

impl crypto::ServerConfig for SpyCrypto {
    fn initial_keys(&self, version: u32, cid: ConnectionId) -> Result<Keys, UnsupportedVersion> {
        self.counts.initial_keys.fetch_add(1, Ordering::Relaxed);
        if self.reject {
            return Err(UnsupportedVersion);
        }
        self.inner.initial_keys(version, cid)
    }

    fn retry_tag(&self, version: u32, cid: ConnectionId, packet: &[u8]) -> [u8; 16] {
        assert!(
            !self.reject,
            "retry_tag called for a version the provider rejected"
        );
        self.counts.retry_tags.fetch_add(1, Ordering::Relaxed);
        self.inner.retry_tag(version, cid, packet)
    }

    fn start_session(
        self: Arc<Self>,
        version: u32,
        params: &TransportParameters,
    ) -> Box<dyn crypto::Session> {
        self.inner.clone().start_session(version, params)
    }
}

struct SpyToken {
    inner: Arc<dyn HandshakeTokenKey>,
    counts: Arc<Counts>,
}

impl HandshakeTokenKey for SpyToken {
    fn aead_from_hkdf(&self, random: &[u8]) -> Box<dyn crypto::AeadKey> {
        self.counts.token_aeads.fetch_add(1, Ordering::Relaxed);
        self.inner.aead_from_hkdf(random)
    }
}

struct SpyLog(Arc<Counts>);

impl TokenLog for SpyLog {
    fn check_and_insert(&self, _: u128, _: SystemTime, _: Duration) -> Result<(), TokenReuseError> {
        self.0.token_log.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }
}

fn instrument(config: &mut ServerConfig, reject_versions: bool) -> Arc<Counts> {
    let counts = Arc::new(Counts::default());
    config.crypto = Arc::new(SpyCrypto {
        inner: config.crypto.clone(),
        counts: counts.clone(),
        reject: reject_versions,
    });
    config.token_key = Arc::new(SpyToken {
        inner: config.token_key.clone(),
        counts: counts.clone(),
    });
    config.validation_token.log = Arc::new(SpyLog(counts.clone()));
    counts
}

/// Encode a protected, padded client Initial with the given DCID and token
fn initial_packet(config: &ServerConfig, dst_cid: ConnectionId, token: &[u8]) -> BytesMut {
    let mut buf = Vec::new();
    let encode = Header::Initial(InitialHeader {
        dst_cid,
        src_cid: ConnectionId::new(&[2; 8]),
        token: token.to_vec().into(),
        number: PacketNumber::U8(0),
        version: 1,
    })
    .encode(&mut buf);
    buf.resize(MIN_INITIAL_SIZE.into(), 0);
    let keys = config
        .crypto
        .initial_keys(1, dst_cid)
        .expect("QUIC v1 is supported");
    encode.finish(
        &mut buf,
        &*keys.header.remote,
        Some((0, &*keys.packet.remote)),
    );
    buf.as_slice().into()
}

fn server_endpoint(config: ServerConfig) -> Endpoint {
    Endpoint::new(Default::default(), Some(Arc::new(config)), true)
}

/// Issue a NEW_TOKEN (`validation`) or Retry token for `addr`
fn issue_token(config: &ServerConfig, addr: SocketAddr, validation: bool) -> Vec<u8> {
    let payload = if validation {
        TokenPayload::Validation {
            ip: addr.ip(),
            issued: config.time_source.now(),
        }
    } else {
        TokenPayload::Retry {
            address: addr,
            orig_dst_cid: ConnectionId::new(&[1; 8]),
            issued: config.time_source.now(),
        }
    };
    Token::new(payload, &mut rand::rng()).encode(&*config.token_key)
}

fn is_retry(datagram: &[u8]) -> bool {
    datagram.first().is_some_and(|byte| byte & 0xf0 == 0xf0)
}

#[test]
fn admission_rejects_all_tokens_before_crypto_and_replay_log() {
    let addr = "[::1]:4433".parse().unwrap();
    let mut config = server_config();
    let policy = Policy::new(InitialDecision::Proceed);
    policy.allow.store(false, Ordering::Relaxed);
    let validation = true;
    let tokens = [
        vec![],
        vec![7; 80],
        vec![7; 1000],
        issue_token(&config, addr, !validation),
        issue_token(&config, addr, validation),
    ];
    let packets: Vec<_> = tokens
        .iter()
        .map(|token| initial_packet(&config, ConnectionId::new(&[1; 8]), token))
        .collect();
    let reject_versions = false;
    let counts = instrument(&mut config, reject_versions);
    config.initial_filter(policy.clone());
    let mut endpoint = server_endpoint(config);
    for data in &packets {
        let mut out = Vec::new();
        let event = endpoint.handle(Instant::now(), addr, None, None, data.clone(), &mut out);
        assert!(event.is_none(), "gate-rejected initial produced an event");
        assert!(out.is_empty(), "gate-rejected initial drew a response");
        assert_eq!(
            endpoint.open_connections(),
            0,
            "gate rejection opened state"
        );
        assert_eq!(
            endpoint.incoming_buffer_bytes(),
            0,
            "gate rejection buffered data"
        );
    }
    assert_eq!(
        counts.values(),
        [0; 4],
        "gate rejection must precede all crypto and replay-log work"
    );
    assert!(
        policy.seen().is_empty(),
        "decide must not run for gate-rejected initials"
    );

    // A gate-rejected NEW_TOKEN was not consumed; it remains valid when admitted.
    policy.allow.store(true, Ordering::Relaxed);
    let Some(DatagramEvent::NewConnection(incoming)) = endpoint.handle(
        Instant::now(),
        addr,
        None,
        None,
        packets[4].clone(),
        &mut Vec::new(),
    ) else {
        panic!("expected an Incoming for the admitted NEW_TOKEN initial")
    };
    assert!(incoming.remote_address_validated(), "NEW_TOKEN not honored");
    assert!(incoming.may_retry(), "NEW_TOKEN peer may still be retried");
    endpoint.ignore(incoming);
    assert_eq!(
        counts.values(),
        [1, 0, 1, 1],
        "Proceed must not decode the token a second time"
    );
}

#[test]
fn filtered_handshake_proceed_and_retry() {
    for verdict in [InitialDecision::Proceed, InitialDecision::Retry] {
        let policy = Policy::new(verdict);
        let mut config = server_config();
        config.initial_filter(policy.clone());
        let mut pair = Pair::new(Default::default(), config);
        pair.connect();
        let seen = policy.seen();
        assert!(
            !seen[0].remote_address_validated(),
            "first flight carries no token"
        );
        assert!(seen[0].may_retry(), "first flight may be retried");
        assert_eq!(seen[0].remote_address(), pair.client.addr);
        if verdict == InitialDecision::Retry {
            assert_eq!(seen.len(), 2, "expected first flight and retried attempt");
            assert!(
                seen[1].remote_address_validated(),
                "retried attempt must carry a valid Retry token"
            );
            assert!(
                !seen[1].may_retry(),
                "RFC 9000 §8.1.2 forbids retrying a peer holding a Retry token"
            );
        } else {
            assert_eq!(seen.len(), 1, "Proceed must consult the filter once");
        }
    }
}

/// An `Ignore` verdict drops the datagram outright: no state is allocated, nothing is sent back,
/// and the client times out rather than learning it was refused.
#[test]
fn filtered_handshake_ignore() {
    let _guard = subscribe();
    let policy = Policy::new(InitialDecision::Ignore);
    let mut config = server_config();
    config.initial_filter(policy.clone());
    let mut pair = Pair::new(Default::default(), config);
    let client_addr = pair.client.addr;

    let client_ch = pair.begin_connect(client_config());
    pair.drive();
    pair.server.assert_no_accept();
    assert!(
        pair.server.outbound.is_empty(),
        "an ignored initial must not draw any response"
    );

    // `drive()` stops once the client's only remaining timer is its idle timeout; advance past it
    // so the unanswered attempt gives up.
    pair.time += Duration::from_secs(60);
    pair.drive();
    assert_matches!(
        pair.client_conn_mut(client_ch).poll(),
        Some(Event::ConnectionLost {
            reason: ConnectionError::TimedOut,
        })
    );

    let seen = policy.seen();
    assert!(
        !seen.is_empty(),
        "the filter should have been consulted at least once"
    );
    assert!(
        seen.iter()
            .all(|ctx| !ctx.remote_address_validated() && ctx.remote_address() == client_addr),
        "a dropped initial issues no token, so every retransmit stays unvalidated: {seen:?}"
    );
}

#[test]
fn post_token_ignore_pays_token_cost_only() {
    let addr = "[::1]:4433".parse().unwrap();
    for validation in [false, true] {
        let mut config = server_config();
        let token = if validation {
            issue_token(&config, addr, validation)
        } else {
            vec![7; 80]
        };
        let data = initial_packet(&config, ConnectionId::new(&[1; 8]), &token);
        let reject_versions = false;
        let counts = instrument(&mut config, reject_versions);
        config.initial_filter(Policy::new(InitialDecision::Ignore));
        let mut endpoint = server_endpoint(config);
        let event = endpoint.handle(Instant::now(), addr, None, None, data, &mut Vec::new());
        assert!(event.is_none(), "Ignore must not produce an event");
        assert_eq!(
            counts.values(),
            [0, 0, 1, usize::from(validation)],
            "Ignore must pay only token decoding (validation token: {validation})"
        );
    }
}

#[test]
fn fast_retry_provider_fallback_and_replacement() {
    let addr = "[::1]:4433".parse().unwrap();
    let mut config = server_config();
    let data = initial_packet(&config, ConnectionId::new(&[1; 8]), &[]);
    let reject_versions = false;
    let counts = instrument(&mut config, reject_versions);
    config.initial_filter(Policy::new(InitialDecision::Retry));
    let mut endpoint = server_endpoint(config);
    for _ in 0..3 {
        let mut out = Vec::new();
        let event = endpoint.handle(Instant::now(), addr, None, None, data.clone(), &mut out);
        assert!(
            matches!(event, Some(DatagramEvent::Response(_))),
            "expected a response datagram"
        );
        assert!(is_retry(&out), "fast path must answer with a Retry");
        assert_eq!(endpoint.open_connections(), 0, "fast Retry opened state");
    }
    assert_eq!(
        counts.values(),
        [3, 3, 3, 0],
        "default supports_version derives keys once per Retry"
    );

    let mut replacement = server_config();
    replacement.initial_filter(Policy::new(InitialDecision::Retry));
    let reject_versions = true;
    let counts = instrument(&mut replacement, reject_versions);
    endpoint.set_server_config(Some(Arc::new(replacement)));
    let event = endpoint.handle(Instant::now(), addr, None, None, data, &mut Vec::new());
    assert!(event.is_none(), "unsupported version must be dropped");
    assert_eq!(
        counts.values(),
        [1, 0, 0, 0],
        "unsupported provider must never reach retry_tag"
    );
}

#[test]
fn malformed_initial_is_budgeted_and_no_filter_retains_close() {
    let addr = "[::1]:4433".parse().unwrap();
    let mut data = BytesMut::from(hex!("c4 00000001 00 00 00 3f").as_ref());
    data.resize(MIN_INITIAL_SIZE.into(), 0);
    for allow in [false, true] {
        let mut config = server_config();
        let reject_versions = false;
        let counts = instrument(&mut config, reject_versions);
        let policy = Policy::new(InitialDecision::Retry);
        policy.allow.store(allow, Ordering::Relaxed);
        config.initial_filter(policy);
        let result = server_endpoint(config).handle(
            Instant::now(),
            addr,
            None,
            None,
            data.clone(),
            &mut Vec::new(),
        );
        assert_eq!(
            result.is_some(),
            allow,
            "malformed initial answered only when admitted (allow: {allow})"
        );
        assert_eq!(
            counts.values(),
            [usize::from(allow), 0, 0, 0],
            "malformed initial must derive keys only when admitted (allow: {allow})"
        );
    }
    let event = server_endpoint(server_config()).handle(
        Instant::now(),
        addr,
        None,
        None,
        data,
        &mut Vec::new(),
    );
    assert!(
        matches!(event, Some(DatagramEvent::Response(_))),
        "expected a response datagram"
    );
}

#[test]
fn authenticated_invalid_retry_retains_error_response() {
    let addr = "[::1]:4433".parse().unwrap();
    let mut config = server_config();
    let validation = false;
    let token = issue_token(&config, "[::1]:4434".parse().unwrap(), validation);
    let data = initial_packet(&config, ConnectionId::new(&[1; 8]), &token);
    let policy = Policy::new(InitialDecision::Retry);
    config.initial_filter(policy.clone());
    let mut out = Vec::new();
    let event = server_endpoint(config).handle(Instant::now(), addr, None, None, data, &mut out);
    assert!(
        matches!(event, Some(DatagramEvent::Response(_))),
        "expected a response datagram"
    );
    assert!(
        !is_retry(&out),
        "a Retry token bound to another address draws CONNECTION_CLOSE, not Retry"
    );
    assert!(
        policy.seen().is_empty(),
        "decide must not run for an invalid Retry token"
    );
}

/// Cheap-capability provider that panics if the fast path derives Initial keys
struct NoInitialKeys(Arc<dyn crypto::ServerConfig>);

impl crypto::ServerConfig for NoInitialKeys {
    fn supports_version(&self, version: u32) -> bool {
        self.0.supports_version(version)
    }

    fn initial_keys(&self, _: u32, _: ConnectionId) -> Result<Keys, UnsupportedVersion> {
        panic!("fast Retry derived Initial keys")
    }

    fn retry_tag(&self, version: u32, cid: ConnectionId, packet: &[u8]) -> [u8; 16] {
        self.0.retry_tag(version, cid, packet)
    }

    fn start_session(self: Arc<Self>, _: u32, _: &TransportParameters) -> Box<dyn crypto::Session> {
        panic!("fast Retry started TLS")
    }
}

#[test]
fn built_in_fast_retry_skips_initial_keys_and_retains_no_route() {
    let addr = "[::1]:4433".parse().unwrap();
    let mut config = server_config();
    let data = initial_packet(&config, ConnectionId::new(&[1; 8]), &[7; 80]);
    config.crypto = Arc::new(NoInitialKeys(config.crypto.clone()));
    config.max_incoming = 1;
    config.initial_filter(Policy::new(InitialDecision::Retry));
    let mut endpoint = server_endpoint(config);
    for _ in 0..3 {
        let mut out = Vec::new();
        let event = endpoint.handle(Instant::now(), addr, None, None, data.clone(), &mut out);
        assert!(
            matches!(event, Some(DatagramEvent::Response(_))),
            "expected a response datagram"
        );
        assert!(is_retry(&out), "fast path must answer with a Retry");
        assert_eq!(
            endpoint.known_connections(),
            0,
            "fast Retry created a connection"
        );
        assert_eq!(
            endpoint.known_cids(),
            0,
            "fast Retry registered a CID route"
        );
    }
}

#[test]
fn no_filter_validates_reserved_bits_before_consuming_token() {
    let addr = "[::1]:4433".parse().unwrap();
    let mut config = server_config();
    let validation = true;
    let token = issue_token(&config, addr, validation);
    let mut data = initial_packet(&config, ConnectionId::new(&[1; 8]), &token);
    // Flip a protected reserved bit without changing the header protection sample.
    data[0] ^= 0x04;
    let reject_versions = false;
    let counts = instrument(&mut config, reject_versions);
    let event =
        server_endpoint(config).handle(Instant::now(), addr, None, None, data, &mut Vec::new());
    assert!(event.is_none(), "reserved bits violation must be dropped");
    assert_eq!(
        counts.values(),
        [1, 0, 0, 0],
        "without a filter, the token must not be decoded before header validation"
    );
}

#[test]
fn existing_connection_bypasses_exhausted_admission() {
    let mut config = server_config();
    let policy = Policy::new(InitialDecision::Retry);
    config.initial_filter(policy.clone());
    let mut pair = Pair::new(Default::default(), config);
    let (client, _) = pair.connect();
    let admitted = policy.admitted.load(Ordering::Relaxed);
    policy.allow.store(false, Ordering::Relaxed);
    let before = pair.client_conn_mut(client).stats().frame_rx.acks;
    pair.client_conn_mut(client).ping();
    pair.drive();
    assert!(
        pair.client_conn_mut(client).stats().frame_rx.acks > before,
        "established connection must keep working with the gate closed"
    );
    assert_eq!(
        policy.admitted.load(Ordering::Relaxed),
        admitted,
        "established connection traffic must not reach the gate"
    );
}

#[test]
fn endpoint_version_list_cannot_force_unsupported_retry_crypto() {
    let addr = "[::1]:4433".parse().unwrap();
    let unknown_version: u32 = 0x12345678;
    let mut config = server_config();
    let mut data = initial_packet(&config, ConnectionId::new(&[1; 8]), &[]);
    data[1..5].copy_from_slice(&unknown_version.to_be_bytes());
    config.initial_filter(Policy::new(InitialDecision::Retry));
    let mut endpoint_config = EndpointConfig::default();
    endpoint_config.supported_versions(vec![1, unknown_version]);
    let mut endpoint = Endpoint::new(Arc::new(endpoint_config), Some(Arc::new(config)), true);
    let mut out = Vec::new();
    let event = endpoint.handle(Instant::now(), addr, None, None, data, &mut out);
    assert!(
        event.is_none(),
        "version unsupported by crypto must be dropped"
    );
    assert!(
        out.is_empty(),
        "version unsupported by crypto drew a response"
    );
}

#[test]
fn default_admission_hook_allows_simple_retry_policy() {
    struct Retry;
    impl InitialFilter for Retry {
        fn decide(&self, _: &InitialContext) -> InitialDecision {
            InitialDecision::Retry
        }
    }
    let mut config = server_config();
    config.initial_filter(Arc::new(Retry));
    Pair::new(Default::default(), config).connect();
}

#[test]
fn global_budget_bounds_new_cids_addresses_and_valid_token_replays() {
    /// Admits a fixed number of initials in total
    struct Budget(AtomicUsize);
    impl InitialFilter for Budget {
        fn allow_initial(&self, _: &InitialMetadata) -> bool {
            self.0
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_sub(1))
                .is_ok()
        }
        fn decide(&self, _: &InitialContext) -> InitialDecision {
            InitialDecision::Ignore
        }
    }
    let mut config = server_config();
    let packets: Vec<_> = (0u16..100)
        .map(|i| {
            let addr: SocketAddr = format!("[::1]:{}", 4433 + i).parse().unwrap();
            let token = match i % 3 {
                0 => vec![7; 80],
                1 => issue_token(&config, addr, false),
                _ => issue_token(&config, addr, true),
            };
            let dst_cid = ConnectionId::new(&u64::from(i).to_be_bytes());
            (addr, initial_packet(&config, dst_cid, &token))
        })
        .collect();
    let reject_versions = false;
    let counts = instrument(&mut config, reject_versions);
    let budget = 6;
    config.initial_filter(Arc::new(Budget(AtomicUsize::new(budget))));
    let mut endpoint = server_endpoint(config);
    for (addr, data) in packets.iter().cycle().take(300) {
        let event = endpoint.handle(
            Instant::now(),
            *addr,
            None,
            None,
            data.clone(),
            &mut Vec::new(),
        );
        assert!(event.is_none(), "budget policy only ever ignores");
    }
    assert_eq!(
        counts.values(),
        [0, 0, budget, 2],
        "only the {budget} admitted initials may pay token costs"
    );
}

#[test]
fn coalesced_initials_generate_one_retry() {
    let mut config = server_config();
    let mut data = initial_packet(&config, ConnectionId::new(&[1; 8]), &[]);
    data.extend_from_slice(&data.clone());
    let policy = Policy::new(InitialDecision::Retry);
    config.initial_filter(policy.clone());
    let mut out = Vec::new();
    let event = server_endpoint(config).handle(
        Instant::now(),
        "[::1]:4433".parse().unwrap(),
        None,
        None,
        data,
        &mut out,
    );
    assert!(
        matches!(event, Some(DatagramEvent::Response(_))),
        "expected a response datagram"
    );
    assert_eq!(
        policy.admitted.load(Ordering::Relaxed),
        1,
        "coalesced initials must pass the gate once"
    );
    assert_eq!(
        policy.seen().len(),
        1,
        "coalesced initials must be decided once"
    );
    assert!(is_retry(&out), "expected a single Retry");
}
