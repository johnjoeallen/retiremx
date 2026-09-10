use anyhow::{Context, Result};
use hickory_resolver::{Resolver, TokioResolver, proto::rr::RData};
use std::time::{Duration, Instant};
use std::{
    collections::HashMap,
    net::IpAddr,
    sync::{Arc, Mutex},
};
use thiserror::Error;
use tokio::runtime::Runtime;

pub struct MxVerifier {
    runtime: Arc<Runtime>,
    resolver: TokioResolver,
    no_mx_until: Mutex<HashMap<String, Instant>>,
}

const NO_MX_CACHE_TTL: Duration = Duration::from_secs(60 * 60);

pub trait MxVerification: Send + Sync {
    fn lookup_mx(&self, domain: &str) -> Result<Vec<String>>;
    fn verify(&self, domain: &str, remote_ip: IpAddr) -> Result<Vec<String>>;
}

#[derive(Debug, Error)]
pub enum MxVerificationError {
    #[error("remote IP is not listed by sender MX records")]
    NoMatch { mx_hosts: Vec<String> },
}

impl MxVerifier {
    pub fn new() -> Result<Self> {
        let runtime = Runtime::new().context("creating DNS runtime")?;
        let mut builder = Resolver::builder_tokio().context("creating DNS resolver")?;
        builder.options_mut().timeout = Duration::from_secs(5);
        builder.options_mut().attempts = 1;
        let resolver = builder.build()?;
        Ok(Self {
            runtime: Arc::new(runtime),
            resolver,
            no_mx_until: Mutex::new(HashMap::new()),
        })
    }

    async fn lookup_mx_cached(&self, domain: &str) -> Result<Vec<String>> {
        let now = Instant::now();
        if let Ok(mut cache) = self.no_mx_until.lock() {
            cache.retain(|_, expires_at| *expires_at > now);
            if cache.contains_key(domain) {
                return Ok(Vec::new());
            }
        }
        let hosts = lookup_mx_hosts(&self.resolver, domain.to_string()).await?;
        if hosts.is_empty()
            && let Ok(mut cache) = self.no_mx_until.lock()
        {
            cache.insert(domain.to_string(), now + NO_MX_CACHE_TTL);
        }
        Ok(hosts)
    }
}

impl MxVerification for MxVerifier {
    fn lookup_mx(&self, domain: &str) -> Result<Vec<String>> {
        self.runtime.block_on(self.lookup_mx_cached(domain))
    }

    fn verify(&self, domain: &str, remote_ip: IpAddr) -> Result<Vec<String>> {
        self.runtime.block_on(async {
            let hosts = self.lookup_mx_cached(domain).await?;
            let mut matched = false;
            for host in &hosts {
                let ips = self
                    .resolver
                    .lookup_ip(host.clone())
                    .await
                    .with_context(|| format!("looking up addresses for {host}"))?;
                if ips.iter().any(|ip| ip == remote_ip) {
                    matched = true;
                }
            }
            if !matched {
                return Err(MxVerificationError::NoMatch { mx_hosts: hosts }.into());
            }
            Ok(hosts)
        })
    }
}

async fn lookup_mx_hosts(resolver: &TokioResolver, domain: String) -> Result<Vec<String>> {
    let mx = match resolver.mx_lookup(domain.clone()).await {
        Ok(mx) => mx,
        Err(error) if error.is_no_records_found() => return Ok(Vec::new()),
        Err(error) => {
            return Err(error).with_context(|| format!("looking up MX for {domain}"));
        }
    };
    Ok(mx
        .answers()
        .iter()
        .filter_map(|record| match &record.data {
            RData::MX(exchange) => Some(exchange.exchange.to_utf8()),
            _ => None,
        })
        .collect())
}
