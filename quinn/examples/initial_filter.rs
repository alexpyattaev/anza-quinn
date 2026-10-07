//! Rate limiting inbound connection attempts with [`InitialFilter`].
//!
//! Checkout the `README.md` for guidance.

use std::{
    error::Error,
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use quinn::{
    Endpoint, InitialContext, InitialDecision, InitialFilter, ServerConfig,
    crypto::rustls::QuicServerConfig,
};
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};

mod common;
use common::make_client_endpoint;

#[derive(Debug)]
struct AdmissionPolicy {
    min_interval_nanos: u64,
    epoch: Instant,
    /// Nanoseconds since `epoch` at the most recently admitted attempt
    last_admit: AtomicU64,
    retried: AtomicU64,
    ignored: AtomicU64,
    admitted: AtomicU64,
}

impl AdmissionPolicy {
    fn new(max_per_second: u32) -> Self {
        assert!(max_per_second > 0, "a rate of zero would admit nothing");
        let min_interval = Duration::from_secs(1) / max_per_second;
        Self {
            min_interval_nanos: min_interval.as_nanos() as u64,
            // Start one interval in the past so the first attempt is admitted immediately.
            epoch: Instant::now() - min_interval,
            last_admit: AtomicU64::new(0),
            retried: AtomicU64::new(0),
            ignored: AtomicU64::new(0),
            admitted: AtomicU64::new(0),
        }
    }

    fn can_admit(&self) -> bool {
        let now = self.epoch.elapsed().as_nanos() as u64;
        let last = self.last_admit.load(Ordering::Relaxed);
        if now.saturating_sub(last) < self.min_interval_nanos {
            return false;
        }
        self.last_admit
            .compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
    }

    fn report(&self) {
        println!(
            "[server] admitted={} retried={} ignored={}",
            self.admitted.load(Ordering::Relaxed),
            self.retried.load(Ordering::Relaxed),
            self.ignored.load(Ordering::Relaxed),
        );
    }
}

impl InitialFilter for AdmissionPolicy {
    fn decide(&self, ctx: &InitialContext) -> InitialDecision {
        // A peer bearing a usable token has proved it receives traffic at the address it
        // claims, and was admitted once already to get that token. Rate limiting it again
        // would mean no handshake ever completes under load.
        if ctx.remote_address_validated() {
            self.admitted.fetch_add(1, Ordering::Relaxed);
            InitialDecision::Proceed
        } else if self.can_admit() {
            self.retried.fetch_add(1, Ordering::Relaxed);
            InitialDecision::Retry
        } else {
            self.ignored.fetch_add(1, Ordering::Relaxed);
            InitialDecision::Ignore
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error + Send + Sync + 'static>> {
    // ridiculously low admission rate allows to illustrate rejection path at low rates
    let admission_policy = Arc::new(AdmissionPolicy::new(1));
    let (addr, cert) = spawn_server(admission_policy.clone())?;

    println!("New client connecting to a server admitting 1 handshake/s");
    let client = make_client_endpoint("0.0.0.0:0".parse()?, &[&cert])?;
    let connection = client.connect(addr, "localhost")?.await?;
    println!("[client] connected: {}", connection.remote_address());
    drop(connection);
    client.wait_idle().await;
    admission_policy.report();

    println!("Familiar client connecting again - no problem");
    let connection = client.connect(addr, "localhost")?.await?;
    println!("[client] connected: {}", connection.remote_address());
    drop(connection);
    client.wait_idle().await;
    admission_policy.report();

    println!("Unfamiliar client connecting");
    // A second endpoint, because the first one is no longer a stranger.
    let second_client = make_client_endpoint("0.0.0.0:0".parse()?, &[&cert])?;
    let connecting = second_client.connect(addr, "localhost")?;
    match tokio::time::timeout(Duration::from_millis(500), connecting).await {
        Err(_) => println!("[client] second attempt got no response within 500ms, as expected"),
        Ok(Ok(connection)) => panic!(
            "rate limited server completed a second handshake with {}",
            connection.remote_address()
        ),
        Ok(Err(error)) => panic!("expected silence for the second attempt, got {error}"),
    }
    admission_policy.report();
    Ok(())
}

/// Bind a server endpoint on an ephemeral loopback port and accept connections until dropped
fn spawn_server(
    filter: Arc<AdmissionPolicy>,
) -> Result<(SocketAddr, CertificateDer<'static>), Box<dyn Error + Send + Sync + 'static>> {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
    let cert_der = CertificateDer::from(cert.cert);
    let key = PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der());

    let crypto = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der.clone()], key.into())?;
    let mut server_config =
        ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(crypto)?));
    server_config.initial_filter(filter);

    let endpoint = Endpoint::server(server_config, "127.0.0.1:0".parse()?)?;
    let addr = endpoint.local_addr()?;

    tokio::spawn(async move {
        while let Some(incoming) = endpoint.accept().await {
            tokio::spawn(async move {
                match incoming.await {
                    Ok(connection) => {
                        println!("[server] accepted {}", connection.remote_address())
                    }
                    Err(error) => println!("[server] handshake failed: {error}"),
                }
            });
        }
    });

    Ok((addr, cert_der))
}
