use bytes::Bytes;
use http::{Method, Request, Response, StatusCode};
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::{TokioIo, TokioTimer};
use parking_lot::RwLock;
use std::collections::HashMap;
use std::convert::Infallible;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::net::TcpListener;
use tokio::sync::broadcast;
use tracing::{info, warn};

use crate::config::node::NodeConfig;
use crate::panel::types::NodeInfo;

#[derive(Debug, Clone)]
pub struct AcmeConfig {
    pub domain: String,
    pub cert_mode: String,
    pub cert_key_length: String,
    pub acme_server: String,
    pub acme_email: Option<String>,
    pub cert_file: PathBuf,
    pub key_file: PathBuf,
}

#[derive(Debug, PartialEq, Eq)]
pub enum CertStatus {
    Valid { not_after: i64 },
    NeedRenewal { not_after: i64 },
    Missing,
    Invalid(String),
}

pub fn check_cert_validity(cert_path: &Path, renew_before_days: u64) -> CertStatus {
    if !cert_path.exists() {
        return CertStatus::Missing;
    }

    let pem_data = match std::fs::read_to_string(cert_path) {
        Ok(data) => data,
        Err(e) => return CertStatus::Invalid(format!("failed to read certificate: {e}")),
    };

    let (_, pem) = match x509_parser::pem::parse_x509_pem(pem_data.as_bytes()) {
        Ok(res) => res,
        Err(e) => return CertStatus::Invalid(format!("PEM parse error: {e}")),
    };

    let (_, cert) = match x509_parser::parse_x509_certificate(&pem.contents) {
        Ok(res) => res,
        Err(e) => return CertStatus::Invalid(format!("X.509 parse error: {e}")),
    };

    let not_after = cert.validity().not_after.timestamp();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    if cert.validity().not_before.timestamp() > now {
        return CertStatus::Invalid("certificate is not valid yet".into());
    }

    let renew_seconds = (renew_before_days as i64) * 86400;
    if not_after - now > renew_seconds {
        CertStatus::Valid { not_after }
    } else {
        CertStatus::NeedRenewal { not_after }
    }
}

struct Http01ChallengeServer {
    tokens: Arc<RwLock<HashMap<String, String>>>,
    shutdown_tx: broadcast::Sender<()>,
}

impl Http01ChallengeServer {
    pub async fn start() -> Result<Self, String> {
        // Binding is the cross-process lock: each Elise service waits its turn
        // to answer HTTP-01 on the same host. Never stop an existing web server.
        let deadline = tokio::time::Instant::now() + Duration::from_secs(120);
        let listener = loop {
            match bind_http_listener(80) {
                Ok(listener) => break listener,
                Err(e) if e.kind() == std::io::ErrorKind::AddrInUse && tokio::time::Instant::now() < deadline => {
                    tokio::time::sleep(Duration::from_secs(2)).await;
                }
                Err(e) => return Err(format!("Cannot bind TCP port 80 for HTTP-01: {e}; keep port 80 free and publicly reachable")),
            }
        };
        Ok(Self::serve(listener))
    }

    fn serve(listener: TcpListener) -> Self {
        let tokens = Arc::new(RwLock::new(HashMap::<String, String>::new()));
        info!(address = ?listener.local_addr(), "ACME HTTP-01 challenge responder listening");

        let (shutdown_tx, _) = broadcast::channel(1);
        let mut shutdown_rx = shutdown_tx.subscribe();
        let tokens_clone = tokens.clone();

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = shutdown_rx.recv() => {
                        info!("ACME HTTP-01 challenge server stopping");
                        break;
                    }
                    accept_res = listener.accept() => {
                        let (stream, remote_addr) = match accept_res {
                            Ok(res) => res,
                            Err(_) => continue,
                        };
                        let tokens = tokens_clone.clone();

                        tokio::spawn(async move {
                            let service = service_fn(move |request: Request<Incoming>| {
                                let mut response = Response::new(Full::new(Bytes::new()));
                                *response.status_mut() = StatusCode::NOT_FOUND;
                                if request.method() == Method::GET {
                                    if let Some(token) = request.uri().path().strip_prefix("/.well-known/acme-challenge/") {
                                        if let Some(key_auth) = tokens.read().get(token).cloned() {
                                            info!(
                                                remote = %remote_addr,
                                                token = %token,
                                                "ACME HTTP-01 challenge matched"
                                            );
                                            *response.status_mut() = StatusCode::OK;
                                            response.headers_mut().insert(
                                                http::header::CONTENT_TYPE,
                                                http::HeaderValue::from_static("text/plain"),
                                            );
                                            *response.body_mut() = Full::new(Bytes::from(key_auth));
                                        }
                                    }
                                }
                                async move { Ok::<_, Infallible>(response) }
                            });
                            // Parse complete headers across TCP reads, with bounded size and time.
                            let _ = hyper::server::conn::http1::Builder::new()
                                .timer(TokioTimer::new())
                                .header_read_timeout(Duration::from_secs(10))
                                .max_buf_size(8192)
                                .keep_alive(false)
                                .serve_connection(TokioIo::new(stream), service)
                                .await;
                        });
                    }
                }
            }
        });

        Self {
            tokens,
            shutdown_tx,
        }
    }

    pub fn add_token(&self, token: String, key_auth: String) {
        self.tokens.write().insert(token, key_auth);
    }

    pub fn stop(self) {
        let _ = self.shutdown_tx.send(());
    }
}

fn bind_http_listener(port: u16) -> std::io::Result<TcpListener> {
    use socket2::{Domain, Protocol, Socket, Type};
    // A dual-stack socket answers both A and AAAA records. Fall back only when
    // IPv6 is unavailable, not when another process owns the IPv6 port.
    let socket = Socket::new(Domain::IPV6, Type::STREAM, Some(Protocol::TCP))
        .and_then(|socket| {
            socket.set_only_v6(false)?;
            socket.set_reuse_address(true)?;
            socket.bind(&std::net::SocketAddr::from(([0u16; 8], port)).into())?;
            Ok(socket)
        })
        .or_else(|e| {
            if e.kind() == std::io::ErrorKind::AddrInUse
                || e.kind() == std::io::ErrorKind::PermissionDenied
            {
                return Err(e);
            }
            let socket = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))?;
            socket.set_reuse_address(true)?;
            socket.bind(&std::net::SocketAddr::from(([0, 0, 0, 0], port)).into())?;
            Ok(socket)
        })?;
    socket.listen(128)?;
    socket.set_nonblocking(true)?;
    TcpListener::from_std(socket.into())
}

pub async fn obtain_certificate(config: &AcmeConfig) -> Result<(), String> {
    tokio::time::timeout(Duration::from_secs(240), issue_certificate(config))
        .await
        .map_err(|_| "ACME issuance timed out after 240 seconds".to_string())?
}

async fn issue_certificate(config: &AcmeConfig) -> Result<(), String> {
    info!(
        domain = %config.domain,
        server = %config.acme_server,
        key_length = %config.cert_key_length,
        cert_file = %config.cert_file.display(),
        key_file = %config.key_file.display(),
        "Starting ACME certificate request via HTTP-01"
    );

    let dir_url = match config.acme_server.to_ascii_lowercase().as_str() {
        "letsencrypt" | "le" | "lets_encrypt" | "production" => {
            instant_acme::LetsEncrypt::Production.url().to_string()
        }
        "letsencrypt_staging" | "staging" => instant_acme::LetsEncrypt::Staging.url().to_string(),
        "zerossl" => instant_acme::ZeroSsl::Production.url().to_string(),
        other => {
            if other.starts_with("http://") || other.starts_with("https://") {
                other.to_string()
            } else {
                instant_acme::LetsEncrypt::Production.url().to_string()
            }
        }
    };

    let email = config
        .acme_email
        .as_deref()
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(|e| format!("mailto:{e}"))
        .unwrap_or_else(|| format!("mailto:admin@{}", config.domain));

    let contact = [email.as_str()];

    let (account, _) = instant_acme::Account::builder()
        .map_err(|e| format!("ACME builder error: {e}"))?
        .create(
            &instant_acme::NewAccount {
                contact: &contact,
                terms_of_service_agreed: true,
                only_return_existing: false,
            },
            dir_url,
            None,
        )
        .await
        .map_err(|e| format!("ACME account registration failed: {e}"))?;

    let identifier = instant_acme::Identifier::Dns(config.domain.clone());
    let mut order = account
        .new_order(&instant_acme::NewOrder::new(&[identifier]))
        .await
        .map_err(|e| format!("ACME new order failed: {e}"))?;

    let challenge_server = Http01ChallengeServer::start().await?;
    tokio::time::sleep(Duration::from_millis(300)).await;

    let mut authorizations = order.authorizations();
    while let Some(authz_res) = authorizations.next().await {
        let mut authz = authz_res.map_err(|e| format!("ACME authorization error: {e}"))?;
        if authz.status == instant_acme::AuthorizationStatus::Valid {
            continue;
        }
        let mut challenge = authz
            .challenge(instant_acme::ChallengeType::Http01)
            .ok_or_else(|| "No HTTP-01 challenge found in ACME order".to_string())?;

        let token = challenge.token.clone();
        let key_auth = challenge.key_authorization().as_str().to_string();
        challenge_server.add_token(token, key_auth);

        challenge
            .set_ready()
            .await
            .map_err(|e| format!("Failed to set ACME challenge ready: {e}"))?;
    }

    let retry_policy = instant_acme::RetryPolicy::new()
        .initial_delay(Duration::from_millis(500))
        .backoff(1.5)
        .timeout(Duration::from_secs(60));

    let status = order
        .poll_ready(&retry_policy)
        .await
        .map_err(|e| format!("ACME poll order ready failed: {e}"))?;

    challenge_server.stop();

    if status != instant_acme::OrderStatus::Ready {
        return Err(format!("ACME order ended in unexpected status: {status:?}"));
    }

    let key_pair = generate_certificate_key(&config.cert_key_length).await?;

    let mut params = rcgen::CertificateParams::new(vec![config.domain.clone()])
        .map_err(|e| format!("Failed to create certificate params: {e}"))?;
    params.distinguished_name = rcgen::DistinguishedName::new();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, config.domain.clone());
    let csr = params
        .serialize_request(&key_pair)
        .map_err(|e| format!("Failed to generate CSR: {e}"))?;

    let csr_der = csr.der();
    if csr_der
        .windows(b"rcgen self signed cert".len())
        .any(|window| window == b"rcgen self signed cert")
    {
        return Err("Generated CSR unexpectedly contains default rcgen subject name".to_string());
    }

    info!(
        domain = %config.domain,
        "ACME order finalizing with clean CSR (CN = domain, SAN = [domain])"
    );

    order
        .finalize_csr(csr_der)
        .await
        .map_err(|e| format!("ACME finalize CSR failed: {e}"))?;

    let retry_policy = instant_acme::RetryPolicy::new()
        .initial_delay(Duration::from_millis(500))
        .backoff(1.5)
        .timeout(Duration::from_secs(60));

    let cert_chain_pem = order
        .poll_certificate(&retry_policy)
        .await
        .map_err(|e| format!("ACME poll certificate failed: {e}"))?;

    let private_key_pem = key_pair.serialize_pem();

    validate_certificate_pair(&cert_chain_pem, &private_key_pem, &config.domain)?;
    save_certificate_pair(config, &cert_chain_pem, &private_key_pem)?;

    info!(
        cert_file = %config.cert_file.display(),
        key_file = %config.key_file.display(),
        "ACME certificate and private key issued and saved successfully"
    );

    Ok(())
}

async fn generate_certificate_key(cert_key_length: &str) -> Result<rcgen::KeyPair, String> {
    let cert_key_length = cert_key_length.to_ascii_lowercase();
    // RSA generation is CPU-bound; keep it off the async runtime's worker threads.
    tokio::task::spawn_blocking(move || {
        match cert_key_length.as_str() {
            "ec-384" | "p384" | "p-384" => {
                rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384)
            }
            "rsa-2048" | "2048" | "rsa" => {
                rcgen::KeyPair::generate_rsa_for(&rcgen::PKCS_RSA_SHA256, rcgen::RsaKeySize::_2048)
            }
            "rsa-4096" | "4096" => {
                rcgen::KeyPair::generate_rsa_for(&rcgen::PKCS_RSA_SHA512, rcgen::RsaKeySize::_4096)
            }
            _ => rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256),
        }
        .map_err(|e| format!("Failed to generate private key: {e}"))
    })
    .await
    .map_err(|e| format!("Private key generation task failed: {e}"))?
}

fn validate_certificate_pair(cert: &str, key: &str, domain: &str) -> Result<(), String> {
    let chain = super::tls::parse_pem_certificates(cert)?;
    let key = super::tls::parse_pem_private_key(key)?;
    let (_, leaf) = x509_parser::parse_x509_certificate(chain[0].as_ref())
        .map_err(|e| format!("invalid leaf certificate: {e}"))?;
    let san = leaf
        .subject_alternative_name()
        .map_err(|e| e.to_string())?
        .ok_or_else(|| "certificate has no subject alternative names".to_string())?;
    if !san.value.general_names.iter().any(|name| {
        matches!(name,
        x509_parser::extensions::GeneralName::DNSName(name) if name.eq_ignore_ascii_case(domain))
    }) {
        return Err(format!("certificate does not cover {domain}"));
    }
    rustls::sign::CertifiedKey::from_der(chain, key, &rustls::crypto::ring::default_provider())
        .map_err(|e| format!("invalid certificate/key pair: {e}"))?
        .keys_match()
        .map_err(|e| format!("certificate/key mismatch: {e}"))
}

fn check_acme_certificate(config: &AcmeConfig, renew_before_days: u64) -> CertStatus {
    let pair = std::fs::read_to_string(&config.cert_file)
        .and_then(|cert| std::fs::read_to_string(&config.key_file).map(|key| (cert, key)));
    match pair {
        Ok((cert, key)) => {
            if let Err(e) = validate_certificate_pair(&cert, &key, &config.domain) {
                return CertStatus::Invalid(e);
            }
            check_cert_validity(&config.cert_file, renew_before_days)
        }
        Err(e) => CertStatus::Invalid(format!("cannot read certificate/key: {e}")),
    }
}

fn save_certificate_pair(config: &AcmeConfig, cert: &str, key: &str) -> Result<(), String> {
    use std::io::Write;
    if config.cert_file == config.key_file {
        return Err("cert_file and key_file must be different paths".into());
    }
    let suffix = format!("tmp-{}", uuid::Uuid::new_v4());
    let cert_temp = config.cert_file.with_extension(&suffix);
    let key_temp = config.key_file.with_extension(format!("key-{suffix}"));
    let result = (|| -> std::io::Result<()> {
        for (path, contents) in [(&cert_temp, cert), (&key_temp, key)] {
            if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
                std::fs::create_dir_all(parent)?;
            }
            let mut options = std::fs::OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            let mut file = options.open(path)?;
            file.write_all(contents.as_bytes())?;
            file.sync_all()?;
        }
        let old_key = match std::fs::read(&config.key_file) {
            Ok(key) => Some(key),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => return Err(e),
        };
        std::fs::rename(&key_temp, &config.key_file)?;
        if let Err(e) = std::fs::rename(&cert_temp, &config.cert_file) {
            // Keep the old usable pair if the final replacement fails.
            if let Some(old_key) = old_key {
                std::fs::write(&config.key_file, old_key)?;
            } else {
                std::fs::remove_file(&config.key_file)?;
            }
            return Err(e);
        }
        Ok(())
    })();
    let _ = std::fs::remove_file(cert_temp);
    let _ = std::fs::remove_file(key_temp);
    result.map_err(|e| format!("failed to save ACME certificate/key: {e}"))
}

pub async fn ensure_acme_certificate(
    node_cfg: &mut NodeConfig,
    node_info: &NodeInfo,
) -> Result<AcmeConfig, String> {
    let domain = node_cfg
        .cert_domain
        .clone()
        .or_else(|| node_info.server_name.clone())
        .or_else(|| node_info.host.clone())
        .or_else(|| {
            node_info
                .tls_settings
                .as_ref()
                .and_then(|ts| ts.get("server_name"))
                .and_then(|v| v.as_str())
                .map(String::from)
        })
        .ok_or_else(|| {
            "ACME is enabled (cert_mode = http), but no domain specified in cert_domain or panel server_name".to_string()
        })?;

    if domain.len() > 253
        || !domain.contains('.')
        || domain.parse::<std::net::IpAddr>().is_ok()
        || !domain.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label.as_bytes()[0].is_ascii_alphanumeric()
                && label.as_bytes()[label.len() - 1].is_ascii_alphanumeric()
                && label
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || c == b'-')
        })
    {
        return Err(
            "HTTP-01 requires a DNS hostname in cert_domain (no URL, wildcard, or IP)".into(),
        );
    }

    let cert_file = match &node_cfg.cert_file {
        Some(path) => crate::config::node::normalize_cert_path(path),
        None => {
            if Path::new("/etc/elise").exists() {
                PathBuf::from(format!("/etc/elise/cert/{domain}.crt"))
            } else {
                PathBuf::from(format!("./cert/{domain}.crt"))
            }
        }
    };

    let key_file = match &node_cfg.key_file {
        Some(path) => crate::config::node::normalize_cert_path(path),
        None => {
            if Path::new("/etc/elise").exists() {
                PathBuf::from(format!("/etc/elise/cert/{domain}.key"))
            } else {
                PathBuf::from(format!("./cert/{domain}.key"))
            }
        }
    };

    let cert_key_length = node_cfg
        .cert_key_length
        .clone()
        .unwrap_or_else(|| "ec-256".to_string());

    let acme_server = node_cfg
        .acme_server
        .clone()
        .unwrap_or_else(|| "letsencrypt".to_string());

    let acme_config = AcmeConfig {
        domain,
        cert_mode: node_cfg
            .cert_mode
            .clone()
            .unwrap_or_else(|| "http".to_string()),
        cert_key_length,
        acme_server,
        acme_email: node_cfg.acme_email.clone(),
        cert_file: cert_file.clone(),
        key_file: key_file.clone(),
    };

    node_cfg.cert_file = Some(cert_file.clone());
    node_cfg.key_file = Some(key_file.clone());
    if node_cfg.cert_domain.is_none() {
        node_cfg.cert_domain = Some(acme_config.domain.clone());
    }

    match check_acme_certificate(&acme_config, 30) {
        CertStatus::Valid { not_after } => {
            info!(
                domain = %acme_config.domain,
                cert_file = %cert_file.display(),
                not_after = not_after,
                "Existing ACME certificate is valid (expires in > 30 days), skipping renewal"
            );
            Ok(acme_config)
        }
        status => {
            warn!(
                domain = %acme_config.domain,
                cert_file = %cert_file.display(),
                status = ?status,
                "Certificate missing, invalid, or expiring within 30 days; obtaining new certificate via ACME"
            );
            if let Err(e) = obtain_certificate(&acme_config).await {
                if matches!(
                    check_acme_certificate(&acme_config, 0),
                    CertStatus::Valid { .. }
                ) {
                    warn!(domain = %acme_config.domain, error = %e, "ACME renewal failed; keeping still-valid certificate and retrying at next check");
                } else {
                    return Err(e);
                }
            }
            Ok(acme_config)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{CertificateParams, KeyPair};
    use std::fs;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use x509_parser::prelude::FromDer;

    fn fixture() -> (PathBuf, AcmeConfig, String, String) {
        let dir = std::env::temp_dir().join(format!("elise-acme-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&dir).unwrap();
        let config = AcmeConfig {
            domain: "node.example.com".into(),
            cert_mode: "http".into(),
            cert_key_length: "ec-256".into(),
            acme_server: "http://127.0.0.1:1/directory".into(),
            acme_email: Some("admin@example.com".into()),
            cert_file: dir.join("fullchain.pem"),
            key_file: dir.join("privkey.pem"),
        };
        let mut params = CertificateParams::new(vec![config.domain.clone()]).unwrap();
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
        params.not_after = rcgen::date_time_ymd(1970, 1, 1) + now + Duration::from_secs(86400);
        let key = KeyPair::generate().unwrap();
        let cert = params.self_signed(&key).unwrap().pem();
        (dir, config, cert, key.serialize_pem())
    }

    #[test]
    fn certificate_pair_validation_and_private_staged_writes() {
        let (dir, config, cert, key) = fixture();
        validate_certificate_pair(&cert, &key, &config.domain).unwrap();
        assert!(validate_certificate_pair(&cert, &key, "wrong.example.com").is_err());
        assert!(validate_certificate_pair(
            &cert,
            &KeyPair::generate().unwrap().serialize_pem(),
            &config.domain
        )
        .is_err());
        save_certificate_pair(&config, &cert, &key).unwrap();
        assert!(matches!(
            check_acme_certificate(&config, 30),
            CertStatus::NeedRenewal { .. }
        ));
        assert!(matches!(
            check_acme_certificate(&config, 0),
            CertStatus::Valid { .. }
        ));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&config.key_file).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        // A final rename failure must restore the old key and remove staging files.
        let blocked_cert = dir.join("directory");
        fs::create_dir(&blocked_cert).unwrap();
        let blocked = AcmeConfig {
            cert_file: blocked_cert,
            ..config.clone()
        };
        assert!(save_certificate_pair(&blocked, &cert, "replacement").is_err());
        assert_eq!(fs::read_to_string(&config.key_file).unwrap(), key);
        assert_eq!(fs::read_dir(&dir).unwrap().count(), 3);
        fs::remove_file(&config.key_file).unwrap();
        assert!(matches!(
            check_acme_certificate(&config, 0),
            CertStatus::Invalid(_)
        ));
        fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn renewal_failure_keeps_valid_pair_but_missing_pair_fails() {
        let (dir, config, cert, key) = fixture();
        save_certificate_pair(&config, &cert, &key).unwrap();
        let mut node = NodeConfig {
            cert_domain: Some(config.domain.clone()),
            cert_file: Some(config.cert_file.clone()),
            key_file: Some(config.key_file.clone()),
            acme_server: Some(config.acme_server.clone()),
            ..Default::default()
        };
        tokio::time::timeout(
            Duration::from_secs(5),
            ensure_acme_certificate(&mut node, &NodeInfo::default()),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(fs::read_to_string(&config.cert_file).unwrap(), cert);
        assert_eq!(fs::read_to_string(&config.key_file).unwrap(), key);
        fs::remove_file(&config.key_file).unwrap();
        assert!(tokio::time::timeout(
            Duration::from_secs(5),
            ensure_acme_certificate(&mut node, &NodeInfo::default())
        )
        .await
        .unwrap()
        .is_err());
        node.cert_domain = Some("../../bad.example.com".into());
        assert!(ensure_acme_certificate(&mut node, &NodeInfo::default())
            .await
            .unwrap_err()
            .contains("DNS hostname"));
        fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn http_challenge_serves_dual_stack_and_releases_port() {
        let listener = bind_http_listener(0).unwrap();
        let address = listener.local_addr().unwrap();
        let responder = Http01ChallengeServer::serve(listener);
        responder.add_token("fixture".into(), "fixture.authorization".into());
        for host in if address.is_ipv6() {
            vec!["127.0.0.1", "::1"]
        } else {
            vec!["127.0.0.1"]
        } {
            for (method, path, expected) in [
                ("GET", "fixture", "200 OK"),
                ("GET", "unknown", "404 Not Found"),
                ("GET", "", "404 Not Found"),
                ("POST", "fixture", "404 Not Found"),
                (
                    "GET",
                    "/.well-known/acme-challenge/fixture",
                    "404 Not Found",
                ),
            ] {
                let mut stream = tokio::net::TcpStream::connect((host, address.port()))
                    .await
                    .unwrap();
                stream.write_all(format!("{method} /.well-known/acme-challenge/{path} HTTP/1.1\r\nHost: node.example.com\r\n\r\n").as_bytes()).await.unwrap();
                let mut reply = String::new();
                tokio::time::timeout(Duration::from_secs(2), stream.read_to_string(&mut reply))
                    .await
                    .unwrap()
                    .unwrap();
                assert!(reply.contains(expected));
                if expected == "200 OK" {
                    assert!(reply.ends_with("fixture.authorization"));
                }
            }
        }
        responder.stop();
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if bind_http_listener(address.port()).is_ok() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn http_challenge_waits_for_fragmented_request_line_and_headers() {
        let listener = bind_http_listener(0).unwrap();
        let port = listener.local_addr().unwrap().port();
        let responder = Http01ChallengeServer::serve(listener);
        responder.add_token("fixture".into(), "fixture.authorization".into());
        let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .unwrap();
        let headers = format!(
            "re HTTP/1.1\r\nHost: node.example.com\r\nX-Padding: {}\r\n\r",
            "x".repeat(4096)
        );
        for fragment in ["GET /.well-known/acme-challenge/", "fixtu", &headers] {
            stream.write_all(fragment.as_bytes()).await.unwrap();
            // Allow the server to consume each fragment, but require it to wait
            // for the complete request before deciding whether the token matches.
            assert!(
                tokio::time::timeout(Duration::from_millis(50), stream.read(&mut [0u8; 1]))
                    .await
                    .is_err()
            );
        }
        stream.write_all(b"\n").await.unwrap();
        let mut reply = String::new();
        tokio::time::timeout(Duration::from_secs(2), stream.read_to_string(&mut reply))
            .await
            .unwrap()
            .unwrap();
        assert!(reply.starts_with("HTTP/1.1 200 OK\r\n"), "{reply}");
        assert!(reply.ends_with("\r\n\r\nfixture.authorization"), "{reply}");
        responder.stop();
    }

    #[tokio::test]
    async fn http_challenge_rejects_oversized_headers() {
        let listener = bind_http_listener(0).unwrap();
        let port = listener.local_addr().unwrap().port();
        let responder = Http01ChallengeServer::serve(listener);
        responder.add_token("fixture".into(), "fixture.authorization".into());
        let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .unwrap();
        let mut request = b"GET /.well-known/acme-challenge/fixture HTTP/1.1\r\nHost: node.example.com\r\nX-Padding: ".to_vec();
        request.resize(8192, b'x');
        stream.write_all(&request).await.unwrap();
        let mut reply = String::new();
        tokio::time::timeout(Duration::from_secs(2), stream.read_to_string(&mut reply))
            .await
            .unwrap()
            .unwrap();
        assert!(reply.starts_with("HTTP/1.1 431 "), "{reply}");
        responder.stop();
    }

    #[tokio::test]
    async fn http_challenge_incomplete_headers_time_out() {
        let listener = bind_http_listener(0).unwrap();
        let port = listener.local_addr().unwrap().port();
        let responder = Http01ChallengeServer::serve(listener);
        responder.add_token("fixture".into(), "fixture.authorization".into());
        let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .unwrap();
        stream
            .write_all(b"GET /.well-known/acme-challenge/fixture HTTP/1.1\r\nHost: ")
            .await
            .unwrap();
        let mut reply = String::new();
        tokio::time::timeout(Duration::from_secs(15), stream.read_to_string(&mut reply))
            .await
            .unwrap()
            .unwrap();
        // Hyper closes timed-out connections without sending an HTTP response.
        assert!(reply.is_empty(), "{reply}");
        responder.stop();
    }

    #[tokio::test]
    async fn certificate_keys_have_requested_size_and_valid_csrs() {
        use ring::signature;
        use x509_parser::certification_request::X509CertificationRequest;

        for (setting, bits, verifier) in [
            (
                "ec-256",
                256,
                &signature::ECDSA_P256_SHA256_ASN1 as &dyn signature::VerificationAlgorithm,
            ),
            ("ec-384", 384, &signature::ECDSA_P384_SHA384_ASN1),
            ("p384", 384, &signature::ECDSA_P384_SHA384_ASN1),
            ("p-384", 384, &signature::ECDSA_P384_SHA384_ASN1),
            ("rsa-2048", 2048, &signature::RSA_PKCS1_2048_8192_SHA256),
            ("2048", 2048, &signature::RSA_PKCS1_2048_8192_SHA256),
            ("rsa", 2048, &signature::RSA_PKCS1_2048_8192_SHA256),
            ("rsa-4096", 4096, &signature::RSA_PKCS1_2048_8192_SHA512),
            ("4096", 4096, &signature::RSA_PKCS1_2048_8192_SHA512),
            ("RSA-4096", 4096, &signature::RSA_PKCS1_2048_8192_SHA512),
        ] {
            let key = generate_certificate_key(setting).await.unwrap();
            let params = CertificateParams::new(vec!["node.example.com".into()]).unwrap();
            let csr = params.serialize_request(&key).unwrap();
            let (_, parsed) = X509CertificationRequest::from_der(csr.der()).unwrap();
            let info = &parsed.certification_request_info;
            assert_eq!(
                info.subject_pki.parsed().unwrap().key_size(),
                bits,
                "{setting}"
            );
            signature::UnparsedPublicKey::new(verifier, &info.subject_pki.subject_public_key.data)
                .verify(info.raw, &parsed.signature_value.data)
                .unwrap_or_else(|e| panic!("{setting} CSR signature failed: {e:?}"));

            // The generated PEM pair must also load in the ring-backed TLS server.
            let cert = params.self_signed(&key).unwrap();
            validate_certificate_pair(&cert.pem(), &key.serialize_pem(), "node.example.com")
                .unwrap_or_else(|e| panic!("{setting} certificate/key pair failed: {e}"));
        }
    }

    #[test]
    fn test_check_cert_validity_missing() {
        let p = Path::new("non_existent_cert_path_99999.crt");
        assert_eq!(check_cert_validity(p, 30), CertStatus::Missing);
    }

    #[test]
    fn test_check_cert_validity_invalid_content() {
        let dir = std::env::temp_dir().join(format!("elise-acme-test-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&dir).unwrap();
        let cert_path = dir.join("invalid.crt");
        fs::write(&cert_path, "not a pem certificate").unwrap();

        match check_cert_validity(&cert_path, 30) {
            CertStatus::Invalid(_) => {}
            other => panic!("Expected CertStatus::Invalid, got {:?}", other),
        }

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn test_check_cert_validity_valid_cert() {
        let dir = std::env::temp_dir().join(format!("elise-acme-test-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&dir).unwrap();
        let cert_path = dir.join("valid.crt");

        let params = CertificateParams::new(vec!["test.example.com".to_string()]).unwrap();
        let key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let cert = params.self_signed(&key_pair).unwrap();

        fs::write(&cert_path, cert.pem()).unwrap();

        match check_cert_validity(&cert_path, 30) {
            CertStatus::Valid { not_after } => {
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs() as i64;
                assert!(not_after > now + 30 * 86400);
            }
            other => panic!("Expected CertStatus::Valid, got {:?}", other),
        }

        match check_cert_validity(&cert_path, 1_000_000) {
            CertStatus::NeedRenewal { not_after } => {
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs() as i64;
                assert!(not_after > now);
            }
            other => panic!("Expected CertStatus::NeedRenewal, got {:?}", other),
        }

        let _ = fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn test_ensure_acme_certificate_skips_when_valid() {
        let dir = std::env::temp_dir().join(format!("elise-acme-test-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&dir).unwrap();
        let cert_path = dir.join("my_cert.crt");
        let key_path = dir.join("my_cert.key");

        let params = CertificateParams::new(vec!["example.com".to_string()]).unwrap();
        let key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let cert = params.self_signed(&key_pair).unwrap();

        fs::write(&cert_path, cert.pem()).unwrap();
        fs::write(&key_path, key_pair.serialize_pem()).unwrap();

        let mut node_cfg = NodeConfig {
            node_id: 32,
            cert_domain: Some("example.com".to_string()),
            cert_mode: Some("http".to_string()),
            cert_file: Some(cert_path.clone()),
            key_file: Some(key_path.clone()),
            ..Default::default()
        };

        let node_info = NodeInfo {
            id: 32,
            node_type: "anytls".to_string(),
            server_port: 8000,
            server_name: Some("example.com".to_string()),
            tls: Some(1),
            ..Default::default()
        };

        let result = ensure_acme_certificate(&mut node_cfg, &node_info).await;
        assert!(
            result.is_ok(),
            "ensure_acme_certificate failed: {:?}",
            result.err()
        );
        let acme_cfg = result.unwrap();
        assert_eq!(acme_cfg.domain, "example.com");
        assert_eq!(acme_cfg.cert_file, cert_path);
        assert_eq!(acme_cfg.key_file, key_path);

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn test_acme_csr_does_not_contain_rcgen_default_cn() {
        let domain = "example.com";
        let key_pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let mut params = rcgen::CertificateParams::new(vec![domain.to_string()]).unwrap();
        params.distinguished_name = rcgen::DistinguishedName::new();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, domain.to_string());
        let csr = params.serialize_request(&key_pair).unwrap();
        let pem = csr.pem().unwrap();
        assert!(
            !pem.contains("rcgen self signed cert"),
            "CSR PEM must not contain rcgen self signed cert"
        );

        let csr_der = csr.der();
        assert!(
            !csr_der
                .windows(b"rcgen self signed cert".len())
                .any(|w| w == b"rcgen self signed cert"),
            "CSR DER must not contain rcgen default CN"
        );

        let (_, parsed_csr) =
            x509_parser::certification_request::X509CertificationRequest::from_der(
                csr_der.as_ref(),
            )
            .expect("Failed to parse generated CSR DER");
        let subject = parsed_csr.certification_request_info.subject.to_string();
        assert!(
            subject.contains("example.com"),
            "Subject should contain domain example.com: {}",
            subject
        );
        assert!(
            !subject.contains("rcgen self signed cert"),
            "Subject must not contain rcgen self signed cert: {}",
            subject
        );
    }

    #[tokio::test]
    async fn test_ensure_acme_certificate_normalizes_typo_path() {
        let mut node_cfg = NodeConfig {
            node_id: 32,
            cert_domain: Some("example.com".to_string()),
            cert_mode: Some("http".to_string()),

            cert_file: Some(PathBuf::from("/etc/eslise/my_cert.crt")),
            key_file: Some(PathBuf::from("/etc/eslise/my_cert.key")),
            ..Default::default()
        };

        let node_info = NodeInfo {
            id: 32,
            node_type: "anytls".to_string(),
            server_port: 8000,
            server_name: Some("example.com".to_string()),
            tls: Some(1),
            ..Default::default()
        };

        let _ = ensure_acme_certificate(&mut node_cfg, &node_info).await;
        assert_eq!(
            node_cfg.cert_file,
            Some(PathBuf::from("/etc/elise/my_cert.crt"))
        );
        assert_eq!(
            node_cfg.key_file,
            Some(PathBuf::from("/etc/elise/my_cert.key"))
        );
    }
}
