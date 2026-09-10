use crate::{
    address::{Resolution, UnknownAction, format_replacements},
    config::Config,
    dns::{MxVerification, MxVerificationError, MxVerifier},
    logging,
};
use anyhow::{Context, Result};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde_json::json;
use signal_hook::{
    consts::{SIGHUP, SIGINT, SIGTERM},
    flag,
};
use std::{
    collections::HashMap,
    fs,
    io::{BufRead, BufReader, Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex, RwLock,
        atomic::{AtomicUsize, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

const IDLE_PEER_QUARANTINE: Duration = Duration::from_secs(60 * 60);
const MAX_IDLE_PEER_QUARANTINE_ENTRIES: usize = 10_000;

#[derive(Clone, Default)]
struct IdlePeerQuarantine {
    entries: Arc<Mutex<HashMap<std::net::IpAddr, Instant>>>,
}

impl IdlePeerQuarantine {
    fn contains(&self, address: std::net::IpAddr) -> bool {
        let now = Instant::now();
        let Ok(mut entries) = self.entries.lock() else {
            return false;
        };
        entries.retain(|_, expires_at| *expires_at > now);
        entries.contains_key(&address)
    }

    fn insert(&self, address: std::net::IpAddr) {
        let now = Instant::now();
        let Ok(mut entries) = self.entries.lock() else {
            return;
        };
        entries.retain(|_, expires_at| *expires_at > now);
        if entries.len() >= MAX_IDLE_PEER_QUARANTINE_ENTRIES
            && let Some((oldest_address, _)) = entries
                .iter()
                .min_by_key(|(_, expires_at)| **expires_at)
                .map(|(address, expires_at)| (*address, *expires_at))
        {
            entries.remove(&oldest_address);
        }
        entries.insert(address, now + IDLE_PEER_QUARANTINE);
    }
}

pub fn serve(
    config: Config,
    bind: SocketAddr,
    config_path: PathBuf,
    event_log: Option<PathBuf>,
) -> Result<()> {
    if let Some(event_log) = event_log {
        logging::init_event_log(&event_log)
            .with_context(|| format!("opening event log {}", event_log.display()))?;
        logging::event(
            "event_log_initialized",
            [("path", json!(event_log.display().to_string()))],
        );
    }
    let listener =
        TcpListener::bind(bind).with_context(|| format!("binding SMTP listener to {bind}"))?;
    listener
        .set_nonblocking(true)
        .context("enabling non-blocking SMTP listener")?;
    let config = Arc::new(RwLock::new(config));
    let reload_requested = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let reload_requested = match flag::register(SIGHUP, Arc::clone(&reload_requested)) {
        Ok(_) => Some(reload_requested),
        Err(error) => {
            eprintln!("SIGHUP configuration reload unavailable: {error}");
            None
        }
    };
    let shutdown_requested = Arc::new(std::sync::atomic::AtomicBool::new(false));
    for signal in [SIGTERM, SIGINT] {
        if let Err(error) = flag::register(signal, Arc::clone(&shutdown_requested)) {
            eprintln!("graceful shutdown signal unavailable: {error}");
        }
    }
    let verifier: Arc<dyn MxVerification> = Arc::new(MxVerifier::new()?);
    let active_connections = Arc::new(AtomicUsize::new(0));
    let idle_peer_quarantine = IdlePeerQuarantine::default();
    let mut observed_config_stamp = config_file_stamp(&config_path);
    eprintln!("SMTP listening on {bind}");
    loop {
        if shutdown_requested.load(Ordering::Acquire) {
            eprintln!("SMTP shutdown requested");
            break;
        }
        let file_changed = config_file_stamp(&config_path) != observed_config_stamp;
        let signal_reload = reload_requested
            .as_ref()
            .is_some_and(|requested| requested.swap(false, Ordering::AcqRel));
        if file_changed || signal_reload {
            observed_config_stamp = config_file_stamp(&config_path);
            match reload_configuration(&config, &config_path) {
                Ok(()) => {
                    logging::event(
                        "configuration_reloaded",
                        [("path", json!(config_path.display().to_string()))],
                    );
                    eprintln!("reloaded configuration from {}", config_path.display());
                }
                Err(error) => {
                    logging::event(
                        "configuration_reload_failed",
                        [
                            ("path", json!(config_path.display().to_string())),
                            ("error", json!(error.to_string())),
                        ],
                    );
                    eprintln!("configuration reload rejected: {error:#}");
                }
            }
        }
        match listener.accept() {
            Ok((mut stream, peer)) => {
                let remote_addr = peer.ip();
                if idle_peer_quarantine.contains(remote_addr) {
                    logging::event(
                        "connection_rejected_quarantined",
                        [
                            ("remote_ip", json!(remote_addr.to_string())),
                            ("reason", json!("previous_idle_timeout")),
                            ("retry_after_seconds", json!(IDLE_PEER_QUARANTINE.as_secs())),
                        ],
                    );
                    let _ = stream.write_all(b"421 4.7.0 Temporarily unavailable\r\n");
                    continue;
                }
                let max_connections = config
                    .read()
                    .expect("configuration lock poisoned")
                    .limits
                    .max_connections;
                if active_connections.fetch_add(1, Ordering::AcqRel) >= max_connections {
                    active_connections.fetch_sub(1, Ordering::AcqRel);
                    let mut stream = stream;
                    let _ = stream.write_all(b"421 4.3.2 Too many connections\r\n");
                    continue;
                }
                let config = Arc::new(config.read().expect("configuration lock poisoned").clone());
                let verifier = Arc::clone(&verifier);
                let active_connections = Arc::clone(&active_connections);
                let idle_peer_quarantine = idle_peer_quarantine.clone();
                thread::spawn(move || {
                    if let Err(error) = Session::new(
                        stream,
                        config,
                        verifier,
                        active_connections,
                        idle_peer_quarantine,
                    )
                    .and_then(Session::run)
                    {
                        eprintln!("SMTP session error: {error:#}");
                    }
                });
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(100));
            }
            Err(error) => eprintln!("SMTP connection error: {error}"),
        }
    }
    let deadline = Instant::now() + Duration::from_secs(30);
    while active_connections.load(Ordering::Acquire) != 0 && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(100));
    }
    if active_connections.load(Ordering::Acquire) != 0 {
        eprintln!("SMTP shutdown grace period expired with active sessions");
    }
    Ok(())
}

fn reload_configuration(config: &RwLock<Config>, path: &Path) -> Result<()> {
    let source = fs::read_to_string(path)
        .with_context(|| format!("reading configuration {}", path.display()))?;
    let new_config = Config::from_markdown(&source).context("loading configuration")?;
    *config.write().expect("configuration lock poisoned") = new_config;
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ConfigFileStamp {
    modified: Option<std::time::SystemTime>,
    length: u64,
    #[cfg(unix)]
    inode: u64,
}

fn config_file_stamp(path: &Path) -> Option<ConfigFileStamp> {
    let metadata = fs::metadata(path).ok()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        Some(ConfigFileStamp {
            modified: metadata.modified().ok(),
            length: metadata.len(),
            inode: metadata.ino(),
        })
    }
    #[cfg(not(unix))]
    {
        Some(ConfigFileStamp {
            modified: metadata.modified().ok(),
            length: metadata.len(),
        })
    }
}

struct Session {
    reader: BufReader<TcpStream>,
    writer: TcpStream,
    config: Arc<Config>,
    verifier: Arc<dyn MxVerification>,
    pass_through_sender: bool,
    verification_failure: Option<(String, String)>,
    verification_mx_mismatch: bool,
    session_id: u64,
    remote_ip: String,
    remote_addr: std::net::IpAddr,
    active_connections: Arc<AtomicUsize>,
    idle_peer_quarantine: IdlePeerQuarantine,
    greeted: bool,
    helo: Option<String>,
    mail_from: Option<String>,
    pass_through_recipients: Vec<String>,
}

impl Session {
    fn new(
        stream: TcpStream,
        config: Arc<Config>,
        verifier: Arc<dyn MxVerification>,
        active_connections: Arc<AtomicUsize>,
        idle_peer_quarantine: IdlePeerQuarantine,
    ) -> Result<Self> {
        stream.set_read_timeout(Some(Duration::from_secs(
            config.limits.idle_timeout_seconds as u64,
        )))?;
        stream.set_write_timeout(Some(Duration::from_secs(30)))?;
        let writer = stream.try_clone()?;
        let remote_addr = stream
            .peer_addr()
            .map(|address| address.ip())
            .unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED));
        let remote_ip = remote_addr.to_string();
        let session_id = logging::next_session_id();
        logging::event(
            "connection_opened",
            [
                ("session_id", json!(session_id)),
                ("remote_ip", json!(remote_ip.clone())),
            ],
        );
        Ok(Self {
            reader: BufReader::new(stream),
            writer,
            config,
            verifier,
            pass_through_sender: false,
            verification_failure: None,
            verification_mx_mismatch: false,
            session_id,
            remote_ip,
            remote_addr,
            active_connections,
            idle_peer_quarantine,
            greeted: false,
            helo: None,
            mail_from: None,
            pass_through_recipients: Vec::new(),
        })
    }

    fn run(mut self) -> Result<()> {
        self.reply(&format!("220 {} ESMTP\r\n", self.config.hostname))?;
        loop {
            let line = match read_line_limited(&mut self.reader, self.config.limits.max_line_bytes)
            {
                Ok(Some(line)) => line,
                Ok(None) => return Ok(()),
                Err(error)
                    if error
                        .downcast_ref::<std::io::Error>()
                        .is_some_and(|error| error.kind() == std::io::ErrorKind::TimedOut) =>
                {
                    self.idle_peer_quarantine.insert(self.remote_addr);
                    logging::event(
                        "connection_idle_timeout",
                        [
                            ("session_id", json!(self.session_id)),
                            ("remote_ip", json!(self.remote_ip.clone())),
                            (
                                "timeout_seconds",
                                json!(self.config.limits.idle_timeout_seconds),
                            ),
                        ],
                    );
                    return Ok(());
                }
                Err(error) => return Err(error),
            };
            let command = line.trim_end_matches(['\r', '\n']);
            let verb = command
                .split_ascii_whitespace()
                .next()
                .unwrap_or("")
                .to_ascii_uppercase();
            match verb.as_str() {
                "EHLO" | "HELO" => {
                    self.greeted = true;
                    self.helo = command.split_ascii_whitespace().nth(1).map(str::to_owned);
                    self.reply(&format!(
                        "250-{}\r\n250-SIZE {}\r\n250 PIPELINING\r\n",
                        self.config.hostname, self.config.limits.max_data_bytes
                    ))?;
                }
                "NOOP" => self.reply("250 2.0.0 OK\r\n")?,
                "RSET" => {
                    self.reset_transaction();
                    self.reply("250 2.0.0 Reset\r\n")?;
                }
                "QUIT" => {
                    self.reply("221 2.0.0 Bye\r\n")?;
                    return Ok(());
                }
                "MAIL" => self.mail(command)?,
                "RCPT" => self.rcpt(command)?,
                "DATA" => self.data()?,
                _ => self.reply("502 5.5.1 Command not implemented\r\n")?,
            }
        }
    }

    fn mail(&mut self, command: &str) -> Result<()> {
        if !self.greeted {
            return self.reply("503 5.5.1 Send HELO or EHLO first\r\n");
        }
        let Some((address, parameters)) = smtp_path_parts(command, "MAIL FROM:") else {
            return self.reply("501 5.1.7 Invalid sender\r\n");
        };
        for parameter in parameters.split_ascii_whitespace() {
            let Some((name, value)) = parameter.split_once('=') else {
                continue;
            };
            if name.eq_ignore_ascii_case("size") {
                let Ok(size) = value.parse::<usize>() else {
                    return self.reply("501 5.5.4 Invalid SIZE parameter\r\n");
                };
                if size > self.config.limits.max_data_bytes {
                    return self.reply("552 5.3.4 Message exceeds fixed maximum message size\r\n");
                }
            }
        }
        self.reset_transaction();
        logging::event(
            "sender_received",
            [
                ("session_id", json!(self.session_id)),
                ("remote_ip", json!(self.remote_ip.clone())),
                ("mail_from", json!(address.clone())),
            ],
        );
        if address.is_empty() && self.config.reject_null_sender {
            logging::event(
                "sender_rejected_null",
                [
                    ("session_id", json!(self.session_id)),
                    ("remote_ip", json!(self.remote_ip.clone())),
                    ("mail_from", json!("<>")),
                    ("smtp_code", json!(550)),
                    ("enhanced_code", json!("5.7.1")),
                ],
            );
            return self.reply("550 5.7.1 Null sender rejected\r\n");
        }
        if let Some(rule) = self.config.sender_policy.blocked_sender(&address) {
            logging::event(
                "sender_blocked",
                [
                    ("session_id", json!(self.session_id)),
                    ("remote_ip", json!(self.remote_ip.clone())),
                    ("mail_from", json!(address.clone())),
                    ("matched_rule", json!(rule.pattern.clone())),
                    ("smtp_code", json!(550)),
                    ("enhanced_code", json!("5.7.1")),
                ],
            );
            return self.reply("550 5.7.1 Sender blocked\r\n");
        }
        if self.config.reject_managed_sender_spoofing && !address.is_empty() {
            let domain = address
                .split_once('@')
                .map(|(_, domain)| domain)
                .unwrap_or_default();
            if self.config.is_managed_domain(domain) && !self.remote_addr.is_loopback() {
                match self.verifier.verify(domain, self.remote_addr) {
                    Ok(mx_hosts) => {
                        logging::event(
                            "managed_sender_mx_authorized",
                            [
                                ("session_id", json!(self.session_id)),
                                ("remote_ip", json!(self.remote_ip.clone())),
                                ("mail_from", json!(address.clone())),
                                ("sender_domain", json!(domain)),
                                ("mx_hosts", json!(mx_hosts)),
                            ],
                        );
                    }
                    Err(error) => {
                        logging::event(
                            "managed_sender_spoof_rejected",
                            [
                                ("session_id", json!(self.session_id)),
                                ("remote_ip", json!(self.remote_ip.clone())),
                                ("mail_from", json!(address.clone())),
                                ("sender_domain", json!(domain)),
                                ("reason", json!(error.to_string())),
                                ("smtp_code", json!(550)),
                                ("enhanced_code", json!("5.7.1")),
                            ],
                        );
                        return self
                            .reply("550 5.7.1 Sender domain is not permitted from this host\r\n");
                    }
                }
            }
        }
        if self.config.reject_sender_without_mx && !address.is_empty() {
            let domain = address
                .split_once('@')
                .map(|(_, domain)| domain)
                .unwrap_or_default();
            match self.verifier.lookup_mx(domain) {
                Ok(mx_hosts) if mx_hosts.is_empty() => {
                    logging::event(
                        "sender_rejected_no_mx",
                        [
                            ("session_id", json!(self.session_id)),
                            ("remote_ip", json!(self.remote_ip.clone())),
                            ("mail_from", json!(address.clone())),
                            ("sender_domain", json!(domain)),
                            ("smtp_code", json!(550)),
                            ("enhanced_code", json!("5.1.8")),
                        ],
                    );
                    return self.reply("550 5.1.8 Sender domain has no MX record\r\n");
                }
                Ok(_) => {}
                Err(error) => {
                    logging::event(
                        "sender_mx_lookup_failed",
                        [
                            ("session_id", json!(self.session_id)),
                            ("remote_ip", json!(self.remote_ip.clone())),
                            ("mail_from", json!(address.clone())),
                            ("sender_domain", json!(domain)),
                            ("error", json!(error.to_string())),
                            ("fallback", json!("continue")),
                        ],
                    );
                }
            }
        }
        if let Some(rule) = self.config.sender_policy.match_sender(&address).cloned() {
            let verified = match rule.verification {
                crate::policy::SenderVerification::None => true,
                crate::policy::SenderVerification::Mx => {
                    let domain = address
                        .split_once('@')
                        .map(|(_, domain)| domain)
                        .unwrap_or_default();
                    match self.verifier.verify(domain, self.remote_addr) {
                        Ok(mx_hosts) => {
                            logging::event(
                                "sender_verification_succeeded",
                                [
                                    ("session_id", json!(self.session_id)),
                                    ("remote_ip", json!(self.remote_ip.clone())),
                                    ("mail_from", json!(address.clone())),
                                    ("verification", json!("mx")),
                                    ("mx_hosts", json!(mx_hosts)),
                                ],
                            );
                            true
                        }
                        Err(error) => {
                            let mx_mismatch = error
                                .downcast_ref::<MxVerificationError>()
                                .is_some_and(|error| {
                                    matches!(
                                        error,
                                        MxVerificationError::NoMatch { mx_hosts }
                                            if !mx_hosts.is_empty()
                                    )
                                });
                            if rule.action == crate::policy::SenderAction::PassThrough {
                                self.verification_failure =
                                    Some((rule.pattern.clone(), error.to_string()));
                            }
                            if mx_mismatch
                                && rule.action == crate::policy::SenderAction::PassThrough
                            {
                                self.verification_mx_mismatch = true;
                            }
                            let mx_hosts = error
                                .downcast_ref::<MxVerificationError>()
                                .map(|error| match error {
                                    MxVerificationError::NoMatch { mx_hosts } => {
                                        json!(mx_hosts.clone())
                                    }
                                })
                                .unwrap_or_else(|| json!([]));
                            logging::event(
                                "sender_verification_failed",
                                [
                                    ("session_id", json!(self.session_id)),
                                    ("remote_ip", json!(self.remote_ip.clone())),
                                    ("mail_from", json!(address.clone())),
                                    ("verification", json!("mx")),
                                    ("reason", json!(error.to_string())),
                                    ("mx_hosts", mx_hosts),
                                    (
                                        "fallback",
                                        json!(if self.verification_mx_mismatch {
                                            "pass-through"
                                        } else {
                                            "migration_rules"
                                        }),
                                    ),
                                ],
                            );
                            if self.verification_mx_mismatch {
                                logging::event(
                                    "sender_verification_warning",
                                    [
                                        ("session_id", json!(self.session_id)),
                                        ("remote_ip", json!(self.remote_ip.clone())),
                                        ("mail_from", json!(address.clone())),
                                        ("policy_rule", json!(rule.pattern.clone())),
                                        ("verification", json!("mx")),
                                        ("reason", json!("remote IP does not match sender MX")),
                                        ("action", json!("pass-through")),
                                    ],
                                );
                            }
                            false
                        }
                    }
                }
            };
            self.pass_through_sender = rule.action == crate::policy::SenderAction::PassThrough
                && (verified || self.verification_mx_mismatch);
            if self.pass_through_sender {
                logging::event(
                    "sender_policy_matched",
                    [
                        ("session_id", json!(self.session_id)),
                        ("remote_ip", json!(self.remote_ip.clone())),
                        ("mail_from", json!(address.clone())),
                        ("policy_rule", json!(rule.pattern.clone())),
                        ("action", json!("pass-through")),
                    ],
                );
            }
        }
        self.mail_from = Some(address);
        self.reply("250 2.1.0 Sender OK\r\n")
    }

    fn rcpt(&mut self, command: &str) -> Result<()> {
        if self.mail_from.is_none() {
            return self.reply("503 5.5.1 Need MAIL FROM first\r\n");
        }
        let Some(address) = smtp_path(command, "RCPT TO:") else {
            return self.reply("501 5.1.3 Invalid recipient\r\n");
        };
        if !self.config.is_managed_recipient(&address) {
            logging::event(
                "relay_rejected",
                [
                    ("session_id", json!(self.session_id)),
                    ("remote_ip", json!(self.remote_ip.clone())),
                    (
                        "mail_from",
                        json!(self.mail_from.clone().unwrap_or_default()),
                    ),
                    ("recipient", json!(address)),
                    ("decision", json!("non-local")),
                    ("smtp_code", json!(550)),
                    ("enhanced_code", json!("5.7.1")),
                ],
            );
            return self.reply("550 5.7.1 Relay access denied\r\n");
        }
        if self.pass_through_recipients.len() >= self.config.limits.max_recipients {
            return self.reply("452 4.5.3 Too many recipients\r\n");
        }
        if self.pass_through_sender {
            self.log_recipient_decision(&address, "pass-through", None);
            self.pass_through_recipients.push(address);
            return self.reply("250 2.1.5 Recipient accepted for pass-through\r\n");
        }
        match self.config.resolver.resolve(&address) {
            Resolution::Retired {
                replacements,
                message,
                pass_through,
                ..
            } => {
                let destinations = format_replacements(&replacements);
                logging::event(
                    "recipient_resolved",
                    [
                        ("session_id", json!(self.session_id)),
                        ("remote_ip", json!(self.remote_ip.clone())),
                        ("recipient", json!(address.clone())),
                        ("decision", json!("retired")),
                        ("pass_through", json!(pass_through)),
                        ("replacement", json!(destinations.clone())),
                    ],
                );
                if pass_through {
                    self.log_recipient_decision(&address, "pass-through", Some(&destinations));
                    logging::event(
                        "recipient_would_be_rejected",
                        [
                            ("session_id", json!(self.session_id)),
                            ("remote_ip", json!(self.remote_ip.clone())),
                            (
                                "mail_from",
                                json!(self.mail_from.clone().unwrap_or_default()),
                            ),
                            ("recipient", json!(address.clone())),
                            ("decision", json!("pass-through")),
                            ("replacement", json!(destinations)),
                            ("smtp_code", json!(550)),
                        ],
                    );
                    self.pass_through_recipients.push(address);
                    return self.reply("250 2.1.5 Recipient accepted for pass-through\r\n");
                }
                self.log_recipient_decision(&address, "replacement", Some(&destinations));
                self.log_pass_through_denied(&address);
                logging::event(
                    "recipient_rejected",
                    [
                        ("session_id", json!(self.session_id)),
                        ("remote_ip", json!(self.remote_ip.clone())),
                        (
                            "mail_from",
                            json!(self.mail_from.clone().unwrap_or_default()),
                        ),
                        ("recipient", json!(address.clone())),
                        ("decision", json!("retired")),
                        ("replacement", json!(destinations.clone())),
                        ("smtp_code", json!(550)),
                    ],
                );
                self.reply(&format!(
                    "550 5.1.1 {}; please send to {destinations}\r\n",
                    message
                ))
            }
            Resolution::Unknown {
                message, action, ..
            } => {
                logging::event(
                    "recipient_resolved",
                    [
                        ("session_id", json!(self.session_id)),
                        ("remote_ip", json!(self.remote_ip.clone())),
                        ("recipient", json!(address.clone())),
                        ("decision", json!("unknown")),
                        ("action", json!(action)),
                    ],
                );
                match action {
                    UnknownAction::Reject => {
                        self.log_recipient_decision(&address, "rejected", None);
                        self.log_pass_through_denied(&address);
                        logging::event(
                            "recipient_rejected",
                            [
                                ("session_id", json!(self.session_id)),
                                ("remote_ip", json!(self.remote_ip.clone())),
                                (
                                    "mail_from",
                                    json!(self.mail_from.clone().unwrap_or_default()),
                                ),
                                ("recipient", json!(address.clone())),
                                ("decision", json!("unknown")),
                                ("smtp_code", json!(550)),
                            ],
                        );
                        self.reply(&format!("550 5.1.1 {message}\r\n"))
                    }
                    UnknownAction::PassThrough => {
                        self.log_recipient_decision(&address, "pass-through", None);
                        self.pass_through_recipients.push(address.clone());
                        logging::event(
                            "pass_through_selected",
                            [
                                ("session_id", json!(self.session_id)),
                                ("remote_ip", json!(self.remote_ip.clone())),
                                (
                                    "mail_from",
                                    json!(self.mail_from.clone().unwrap_or_default()),
                                ),
                                ("recipient", json!(address.clone())),
                            ],
                        );
                        self.reply("250 2.1.5 Recipient accepted for pass-through\r\n")
                    }
                }
            }
        }
    }

    fn data(&mut self) -> Result<()> {
        if self.mail_from.is_none() || self.pass_through_recipients.is_empty() {
            return self.reply("503 5.5.1 Need a valid recipient first\r\n");
        }
        let Some(mail_from) = self.mail_from.clone() else {
            return self.reply("503 5.5.1 Need MAIL FROM first\r\n");
        };
        let mut upstream =
            match TcpStream::connect_timeout(&self.config.postfix_addr, Duration::from_secs(10)) {
                Ok(stream) => {
                    logging::event(
                        "postfix_connected",
                        [
                            ("session_id", json!(self.session_id)),
                            ("remote_ip", json!(self.remote_ip.clone())),
                            ("postfix_addr", json!(self.config.postfix_addr.to_string())),
                        ],
                    );
                    stream
                }
                Err(error) => {
                    logging::event(
                        "postfix_temporary_failure",
                        [
                            ("session_id", json!(self.session_id)),
                            ("remote_ip", json!(self.remote_ip.clone())),
                            ("postfix_addr", json!(self.config.postfix_addr.to_string())),
                            ("stage", json!("connect")),
                            ("error", json!(error.to_string())),
                        ],
                    );
                    return self.reply(&format!("451 4.3.0 Postfix unavailable: {error}\r\n"));
                }
            };
        upstream.set_read_timeout(Some(Duration::from_secs(300)))?;
        upstream.set_write_timeout(Some(Duration::from_secs(30)))?;
        let mut upstream_reader = BufReader::new(upstream.try_clone()?);
        let greeting = read_response(&mut upstream_reader)?;
        if !greeting.starts_with('2') {
            self.log_postfix_failure("greeting", &greeting);
            return self.reply(&greeting);
        }
        send_upstream(&mut upstream, "EHLO retiremx\r\n")?;
        let ehlo = read_response(&mut upstream_reader)?;
        if !ehlo.starts_with('2') {
            self.log_postfix_failure("ehlo", &ehlo);
            return self.reply(&ehlo);
        }
        send_upstream(&mut upstream, &format!("MAIL FROM:<{mail_from}>\r\n"))?;
        let mail_response = read_response(&mut upstream_reader)?;
        if !mail_response.starts_with('2') {
            self.log_postfix_failure("mail", &mail_response);
            return self.reply(&mail_response);
        }
        for recipient in &self.pass_through_recipients {
            send_upstream(&mut upstream, &format!("RCPT TO:<{recipient}>\r\n"))?;
            let response = read_response(&mut upstream_reader)?;
            if !response.starts_with('2') {
                self.log_postfix_failure("rcpt", &response);
                return self.reply(&response);
            }
        }
        send_upstream(&mut upstream, "DATA\r\n")?;
        let data_response = read_response(&mut upstream_reader)?;
        if !data_response.starts_with('3') {
            self.log_postfix_failure("data", &data_response);
            return self.reply(&data_response);
        }
        self.reply(&data_response)?;
        let mut data_bytes = 0usize;
        let mut too_large = false;
        let mut headers = HeaderCapture {
            in_headers: true,
            ..HeaderCapture::default()
        };
        loop {
            let Some(line) =
                read_line_limited(&mut self.reader, self.config.limits.max_line_bytes)?
            else {
                return Ok(());
            };
            if line.trim_end_matches(['\r', '\n']) == "." {
                break;
            }
            let upstream_line = line.strip_prefix(".").filter(|_| line.starts_with(".."));
            let upstream_line = upstream_line.unwrap_or(&line);
            headers.observe(upstream_line);
            data_bytes = data_bytes.saturating_add(upstream_line.len());
            if data_bytes > self.config.limits.max_data_bytes {
                too_large = true;
            } else if !too_large {
                upstream.write_all(upstream_line.as_bytes())?;
            }
        }
        if too_large {
            send_upstream(&mut upstream, "RSET\r\n")?;
            let _ = read_response(&mut upstream_reader);
            self.reply("552 5.3.4 Message too large\r\n")?;
            self.reset_transaction();
            return Ok(());
        }
        upstream.write_all(b".\r\n")?;
        upstream.flush()?;
        let final_response = read_response(&mut upstream_reader)?;
        if final_response.starts_with('2') {
            logging::event(
                "postfix_accepted",
                [
                    ("session_id", json!(self.session_id)),
                    ("remote_ip", json!(self.remote_ip.clone())),
                    ("postfix_addr", json!(self.config.postfix_addr.to_string())),
                    ("mail_from", json!(mail_from)),
                    ("recipients", json!(self.pass_through_recipients.clone())),
                    ("postfix_response", json!(final_response.trim_end())),
                ],
            );
            let (subject, message_id) = headers.finish();
            let mut fields = vec![
                ("session_id", json!(self.session_id)),
                ("remote_ip", json!(self.remote_ip.clone())),
                ("helo", json!(self.helo.clone().unwrap_or_default())),
                ("mail_from", json!(mail_from)),
                ("rcpt_to", json!(self.pass_through_recipients.clone())),
                ("action", json!("pass-through")),
                ("status", json!("accepted")),
            ];
            fields.push(("message_id", json!(message_id)));
            fields.push(("subject", json!(subject)));
            logging::event("message_received", fields);
        } else {
            self.log_postfix_failure("message", &final_response);
        }
        self.reply(&final_response)?;
        self.reset_transaction();
        Ok(())
    }

    fn reset_transaction(&mut self) {
        self.mail_from = None;
        self.pass_through_sender = false;
        self.verification_failure = None;
        self.verification_mx_mismatch = false;
        self.pass_through_recipients.clear();
    }

    fn log_pass_through_denied(&self, recipient: &str) {
        let Some((rule, reason)) = &self.verification_failure else {
            return;
        };
        logging::event(
            "pass_through_denied",
            [
                ("session_id", json!(self.session_id)),
                ("remote_ip", json!(self.remote_ip.clone())),
                (
                    "mail_from",
                    json!(self.mail_from.clone().unwrap_or_default()),
                ),
                ("recipient", json!(recipient)),
                ("matched_rule", json!(rule)),
                ("reason", json!(reason)),
                ("fallback", json!("migration_rules")),
                ("smtp_code", json!(550)),
            ],
        );
    }

    fn log_recipient_decision(&self, recipient: &str, decision: &str, replacement: Option<&str>) {
        let mut fields = vec![
            ("session_id", json!(self.session_id)),
            ("remote_ip", json!(self.remote_ip.clone())),
            (
                "mail_from",
                json!(self.mail_from.clone().unwrap_or_default()),
            ),
            ("recipient", json!(recipient)),
            ("decision", json!(decision)),
        ];
        if let Some(replacement) = replacement {
            fields.push(("replacement", json!(replacement)));
        }
        logging::event("recipient_decision", fields);
    }

    fn log_postfix_failure(&self, stage: &str, response: &str) {
        let event = if response.starts_with('4') {
            "postfix_temporary_failure"
        } else {
            "postfix_rejected"
        };
        logging::event(
            event,
            [
                ("session_id", json!(self.session_id)),
                ("remote_ip", json!(self.remote_ip.clone())),
                ("postfix_addr", json!(self.config.postfix_addr.to_string())),
                ("stage", json!(stage)),
                ("postfix_response", json!(response.trim_end())),
            ],
        );
    }

    fn reply(&mut self, response: &str) -> Result<()> {
        self.writer.write_all(response.as_bytes())?;
        self.writer.flush().context("flushing SMTP response")
    }
}

#[derive(Default)]
struct HeaderCapture {
    in_headers: bool,
    current_name: Option<String>,
    current_value: String,
    subject: Option<String>,
    message_id: Option<String>,
}

impl HeaderCapture {
    fn observe(&mut self, line: &str) {
        if !self.in_headers {
            return;
        }
        let text = line.trim_end_matches(['\r', '\n']);
        if text.is_empty() {
            self.finish_current();
            self.in_headers = false;
        } else if text.starts_with([' ', '\t']) {
            if !self.current_value.is_empty() {
                self.current_value.push(' ');
            }
            self.current_value.push_str(text.trim());
        } else if let Some((name, value)) = text.split_once(':') {
            self.finish_current();
            self.current_name = Some(name.trim().to_ascii_lowercase());
            self.current_value = value.trim().to_owned();
        } else {
            self.finish_current();
            self.in_headers = false;
        }
    }

    fn finish_current(&mut self) {
        let Some(name) = self.current_name.take() else {
            self.current_value.clear();
            return;
        };
        let value = decode_mime_header(&self.current_value);
        match name.as_str() {
            "subject" => self.subject = Some(sanitize_header_value(&value)),
            "message-id" => self.message_id = Some(sanitize_header_value(&value)),
            _ => {}
        }
        self.current_value.clear();
    }

    fn finish(mut self) -> (Option<String>, Option<String>) {
        self.finish_current();
        (self.subject, self.message_id)
    }
}

fn sanitize_header_value(value: &str) -> String {
    value
        .chars()
        .map(|character| {
            if character == '\t' || !character.is_control() {
                character
            } else {
                ' '
            }
        })
        .collect::<String>()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .chars()
        .take(512)
        .collect()
}

fn decode_mime_header(value: &str) -> String {
    let mut output = String::new();
    let mut remaining = value;
    while let Some(start) = remaining.find("=?") {
        output.push_str(&remaining[..start]);
        let Some(end) = find_mime_word_end(remaining, start + 2) else {
            output.push_str(&remaining[start..]);
            break;
        };
        let encoded = &remaining[start + 2..end];
        let Some((charset, encoded)) = encoded.split_once('?') else {
            output.push_str(&remaining[start..end + 2]);
            remaining = &remaining[end + 2..];
            continue;
        };
        let Some((encoding, data)) = encoded.split_once('?') else {
            output.push_str(&remaining[start..end + 2]);
            remaining = &remaining[end + 2..];
            continue;
        };
        let bytes = if encoding.eq_ignore_ascii_case("b") {
            STANDARD.decode(data).ok()
        } else if encoding.eq_ignore_ascii_case("q") {
            decode_quoted_printable_word(data)
        } else {
            None
        };
        if let Some(bytes) = bytes {
            let _ = charset;
            output.push_str(&String::from_utf8_lossy(&bytes));
        } else {
            output.push_str(&remaining[start..end + 2]);
        }
        remaining = &remaining[end + 2..];
    }
    if !remaining.is_empty() {
        output.push_str(remaining);
    }
    output
}

fn find_mime_word_end(value: &str, from: usize) -> Option<usize> {
    let mut offset = from;
    while let Some(relative) = value[offset..].find("?=") {
        let end = offset + relative;
        let after = end + 2;
        let looks_like_qp_prefix = value
            .as_bytes()
            .get(after)
            .is_some_and(|byte| byte.is_ascii_hexdigit());
        if !looks_like_qp_prefix {
            return Some(end);
        }
        offset = after;
    }
    None
}

fn decode_quoted_printable_word(value: &str) -> Option<Vec<u8>> {
    let bytes = value.as_bytes();
    let mut output = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'_' {
            output.push(b' ');
            index += 1;
        } else if bytes[index] == b'=' && index + 2 < bytes.len() {
            if let (Some(high), Some(low)) = (
                (bytes[index + 1] as char).to_digit(16),
                (bytes[index + 2] as char).to_digit(16),
            ) {
                output.push(((high << 4) | low) as u8);
                index += 3;
            } else {
                output.push(b'=');
                index += 1;
            }
        } else {
            output.push(bytes[index]);
            index += 1;
        }
    }
    Some(output)
}

impl Drop for Session {
    fn drop(&mut self) {
        self.active_connections.fetch_sub(1, Ordering::AcqRel);
        logging::event(
            "connection_closed",
            [
                ("session_id", json!(self.session_id)),
                ("remote_ip", json!(self.remote_ip.clone())),
            ],
        );
    }
}

fn smtp_path(command: &str, prefix: &str) -> Option<String> {
    smtp_path_parts(command, prefix).map(|(address, _)| address)
}

fn smtp_path_parts(command: &str, prefix: &str) -> Option<(String, String)> {
    let command_prefix = command.get(..prefix.len())?;
    if !command_prefix.eq_ignore_ascii_case(prefix) {
        return None;
    }
    let value = command[prefix.len()..].trim();
    let value = value.strip_prefix('<')?;
    let (address, trailing) = value.split_once('>')?;
    if (!trailing.is_empty() && !trailing.chars().next().is_some_and(char::is_whitespace))
        || !valid_esmtp_parameters(trailing)
    {
        return None;
    }
    Some((address.to_ascii_lowercase(), trailing.trim().to_string()))
}

fn valid_esmtp_parameters(trailing: &str) -> bool {
    trailing.split_ascii_whitespace().all(|parameter| {
        let (name, value) = parameter.split_once('=').unwrap_or((parameter, ""));
        !name.is_empty()
            && name
                .chars()
                .all(|character| character.is_ascii_alphanumeric() || character == '-')
            && (value.is_empty()
                || value
                    .chars()
                    .all(|character| !character.is_ascii_control() && character != ' '))
    })
}

fn read_line_limited<R: Read>(reader: &mut R, limit: usize) -> Result<Option<String>> {
    let mut bytes = Vec::with_capacity(limit.min(128));
    let mut byte = [0u8; 1];
    loop {
        match reader.read(&mut byte)? {
            0 => {
                return if bytes.is_empty() {
                    Ok(None)
                } else {
                    anyhow::bail!("connection closed mid-line")
                };
            }
            _ => {
                bytes.push(byte[0]);
                if bytes.len() > limit + 2 {
                    anyhow::bail!("SMTP line exceeds {} bytes", limit);
                }
                if byte[0] == b'\n' {
                    return Ok(Some(String::from_utf8_lossy(&bytes).into_owned()));
                }
            }
        }
    }
}

fn send_upstream(stream: &mut TcpStream, command: &str) -> Result<()> {
    stream.write_all(command.as_bytes())?;
    stream.flush().context("flushing Postfix command")
}

fn read_response(reader: &mut BufReader<TcpStream>) -> Result<String> {
    let mut response = String::new();
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line)? == 0 {
            anyhow::bail!("Postfix closed the connection");
        }
        let complete = line.as_bytes().get(3) == Some(&b' ');
        response.push_str(&line);
        if complete || line.len() < 4 {
            return Ok(response);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        HeaderCapture, decode_mime_header, reload_configuration, sanitize_header_value, smtp_path,
        smtp_path_parts,
    };
    use crate::config::Config;
    use std::{fs, sync::RwLock};

    #[test]
    fn smtp_paths_accept_mixed_case_commands() {
        assert_eq!(
            smtp_path("mAiL fRoM:<Sender@Example.org>", "MAIL FROM:"),
            Some("sender@example.org".to_string())
        );
    }

    #[test]
    fn captures_and_decodes_message_headers_without_body() {
        let mut headers = HeaderCapture {
            in_headers: true,
            ..HeaderCapture::default()
        };
        headers.observe("Subject: =?UTF-8?Q?Policy_renewal?=\r\n");
        headers.observe("Message-ID: <message@example.net>\r\n");
        headers.observe("\r\n");
        headers.observe("secret body content\r\n");
        assert_eq!(
            headers.finish(),
            (
                Some("Policy renewal".to_string()),
                Some("<message@example.net>".to_string())
            )
        );
    }

    #[test]
    fn header_values_are_sanitized_and_bounded() {
        let value = sanitize_header_value("hello\r\nworld\u{0000}");
        assert_eq!(value, "hello world");
        assert_eq!(decode_mime_header("=?UTF-8?B?SGVsbG8=?="), "Hello");
        assert_eq!(
            sanitize_header_value(&decode_mime_header(
                "=?UTF-8?Q?=E2=8F=B0=5B=31=32Hrs=20Left=20for=20Anniv=2E=20Sale=5D=20Total?= =?UTF-8?Q?=20=24=33=31=20OFF=20Allowances=20+=20=24=33=35=20Payment=20Dis?= count, Last Chance To Save Big >>"
            )),
            "⏰[12Hrs Left for Anniv. Sale] Total $31 OFF Allowances + $35 Payment Dis count, Last Chance To Save Big >>"
        );
    }

    #[test]
    fn smtp_paths_reject_trailing_data() {
        assert_eq!(
            smtp_path("RCPT TO:<user@example.org>junk", "RCPT TO:"),
            None
        );
        assert_eq!(
            smtp_path("RCPT TO:<user@example.org> BAD@PARAM", "RCPT TO:"),
            None
        );
    }

    #[test]
    fn smtp_paths_accept_esmtp_parameters() {
        assert_eq!(
            smtp_path("MAIL FROM:<sender@example.org> SIZE=1024", "MAIL FROM:"),
            Some("sender@example.org".to_string())
        );
    }

    #[test]
    fn smtp_paths_return_esmtp_parameters() {
        assert_eq!(
            smtp_path_parts("MAIL FROM:<sender@example.org> SIZE=1024", "MAIL FROM:"),
            Some(("sender@example.org".to_string(), "SIZE=1024".to_string()))
        );
    }

    #[test]
    fn invalid_reload_preserves_active_configuration() {
        let path = std::env::temp_dir().join(format!("retiremx-reload-{}.md", std::process::id()));
        let active =
            RwLock::new(Config::from_markdown("# Server\n\nHostname: active.example\n").unwrap());
        fs::write(&path, "# Addresses\n\n## broken@@example.com\n").unwrap();
        assert!(reload_configuration(&active, &path).is_err());
        assert_eq!(active.read().unwrap().hostname, "active.example");
        fs::write(&path, "# Server\n\nHostname: reloaded.example\n").unwrap();
        reload_configuration(&active, &path).unwrap();
        assert_eq!(active.read().unwrap().hostname, "reloaded.example");
        let _ = fs::remove_file(path);
    }
}
