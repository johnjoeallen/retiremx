use crate::address::{AddressDefinition, Resolver, UnknownAction, normalize};
use crate::policy::{
    BlockedSenderRule, SenderAction, SenderPolicy, SenderRule, SenderVerification,
};
use anyhow::{Context, Result, bail};
use pulldown_cmark::{Event, HeadingLevel, Parser, Tag, TagEnd};
use std::{
    collections::{HashMap, HashSet},
    net::{IpAddr, SocketAddr},
};

#[derive(Clone)]
pub struct Config {
    pub resolver: Resolver,
    pub sender_policy: SenderPolicy,
    pub postfix_addr: SocketAddr,
    pub bind: SocketAddr,
    pub hostname: String,
    pub limits: Limits,
    pub reject_sender_without_mx: bool,
    pub reject_null_sender: bool,
    pub reject_managed_sender_spoofing: bool,
    pub managed_domains: Vec<String>,
}

#[derive(Clone)]
pub struct Limits {
    pub max_connections: usize,
    pub max_line_bytes: usize,
    pub max_recipients: usize,
    pub max_data_bytes: usize,
    pub idle_timeout_seconds: usize,
}

impl Config {
    pub fn from_markdown(source: &str) -> Result<Self> {
        let mut sections: Vec<(usize, String, Vec<String>)> = Vec::new();
        let mut current: Option<usize> = None;
        let mut buffer = String::new();
        let flush = |sections: &mut Vec<(usize, String, Vec<String>)>,
                     current: &mut Option<usize>,
                     buffer: &mut String| {
            if let Some(index) = *current
                && !buffer.trim().is_empty()
            {
                sections[index].2.push(buffer.trim().to_string());
            }
            buffer.clear();
        };
        for event in Parser::new(source) {
            match event {
                Event::Start(Tag::Heading { level, .. }) => {
                    flush(&mut sections, &mut current, &mut buffer);
                    let depth = match level {
                        HeadingLevel::H1 => 1,
                        HeadingLevel::H2 => 2,
                        HeadingLevel::H3 => 3,
                        HeadingLevel::H4 => 4,
                        HeadingLevel::H5 => 5,
                        HeadingLevel::H6 => 6,
                    };
                    sections.push((depth, String::new(), Vec::new()));
                    current = Some(sections.len() - 1);
                }
                Event::End(TagEnd::Heading(_)) => {
                    if let Some(index) = current {
                        sections[index].1 = buffer.trim().to_string();
                        buffer.clear();
                    }
                }
                Event::Start(Tag::Paragraph) => {}
                Event::End(TagEnd::Paragraph) => {
                    flush(&mut sections, &mut current, &mut buffer);
                }
                Event::Start(Tag::Item) => {}
                Event::End(TagEnd::Item) => {
                    flush(&mut sections, &mut current, &mut buffer);
                }
                Event::Text(text) | Event::Code(text) => {
                    buffer.push_str(&text);
                }
                Event::SoftBreak | Event::HardBreak => buffer.push(' '),
                Event::Start(Tag::List(_)) | Event::End(TagEnd::List(_)) => {}
                _ => {}
            }
        }
        let mut shared_sections = sections.clone();
        for index in 0..sections.len() {
            let (depth, heading, blocks) = &sections[index];
            if *depth != 2 || !blocks.is_empty() || !heading.contains('@') {
                continue;
            }
            let mut next = index + 1;
            while next < sections.len() && sections[next].0 == 2 && sections[next].1.contains('@') {
                if !sections[next].2.is_empty() {
                    shared_sections[index].2 = sections[next].2.clone();
                    break;
                }
                next += 1;
            }
        }
        let mut definitions = HashMap::new();
        let mut unknown = "No such address".into();
        let mut retired = "This address is no longer in use".into();
        let mut unknown_action = UnknownAction::Reject;
        let mut known_pass_through = false;
        let mut reject_sender_without_mx = true;
        let mut reject_null_sender = true;
        let mut reject_managed_sender_spoofing = true;
        let mut configured_managed_domains = None;
        let mut sender_rules = Vec::new();
        let mut sender_patterns = HashSet::new();
        let mut blocked_sender_rules = Vec::new();
        let mut blocked_sender_patterns = HashSet::new();
        let mut postfix_host = IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);
        let mut postfix_port = 2525;
        let mut bind = SocketAddr::from(([0, 0, 0, 0], 25));
        let mut hostname = "localhost".to_string();
        let mut limits = Limits {
            max_connections: 100,
            max_line_bytes: 1000,
            max_recipients: 100,
            max_data_bytes: 10 * 1024 * 1024,
            idle_timeout_seconds: 60,
        };
        for (depth, heading, blocks) in shared_sections.iter().cloned() {
            if depth == 1 && heading.eq_ignore_ascii_case("defaults") {
                let values = fields(&blocks);
                limits.max_connections =
                    positive_limit(&values, "max connections", limits.max_connections)?;
                limits.max_line_bytes =
                    positive_limit(&values, "max line bytes", limits.max_line_bytes)?;
                limits.max_recipients =
                    positive_limit(&values, "max recipients", limits.max_recipients)?;
                limits.max_data_bytes =
                    positive_limit(&values, "max data bytes", limits.max_data_bytes)?;
                limits.idle_timeout_seconds =
                    positive_limit(&values, "idle timeout seconds", limits.idle_timeout_seconds)?;
                if let Some(action) = values
                    .get("known action")
                    .or_else(|| values.get("default action"))
                {
                    known_pass_through = match action.to_ascii_lowercase().as_str() {
                        "reject" | "migration-rules" | "migration" => false,
                        "pass-through" | "passthrough" => true,
                        other => bail!("Defaults: invalid known-address action {other}"),
                    };
                }
                if let Some(value) = values.get("reject sender without mx") {
                    reject_sender_without_mx = parse_bool(value)
                        .with_context(|| "Defaults: invalid Reject Sender Without MX value")?;
                }
                if let Some(value) = values.get("reject null sender") {
                    reject_null_sender = parse_bool(value)
                        .with_context(|| "Defaults: invalid Reject Null Sender value")?;
                }
                if let Some(value) = values.get("reject managed sender spoofing") {
                    reject_managed_sender_spoofing = parse_bool(value).with_context(
                        || "Defaults: invalid Reject Managed Sender Spoofing value",
                    )?;
                }
            }
        }
        for (index, (depth, heading, blocks)) in shared_sections.iter().enumerate() {
            if *depth != 2 {
                continue;
            }
            if section_heading(&shared_sections, index).is_some_and(|section| {
                section.eq_ignore_ascii_case("trusted senders")
                    || section.eq_ignore_ascii_case("blocked senders")
            }) {
                continue;
            }
            let key = normalize(heading);
            if !key.contains('@') {
                continue;
            }
            validate_address(&key).with_context(|| format!("invalid source address {heading}"))?;
            let fields = fields(blocks);
            let configured_members = list(&fields, "replaced by");
            let mut members = Vec::new();
            for member in configured_members {
                if let Err(error) = validate_replacement_address(&member) {
                    eprintln!("warning: {heading}: ignoring replacement {member}: {error}");
                } else {
                    members.push(member);
                }
            }
            if members.is_empty() {
                continue;
            }
            let pass_through = match fields.get("pass through") {
                None => known_pass_through,
                Some(value) => match value.trim().to_ascii_lowercase().as_str() {
                    "true" | "yes" | "on" => true,
                    "false" | "no" | "off" => false,
                    other => bail!("{heading}: invalid Pass Through value {other}"),
                },
            };
            let definition = AddressDefinition::Group {
                members,
                pass_through,
                message: fields.get("message").cloned(),
            };
            if definitions.insert(key.clone(), definition).is_some() {
                bail!("duplicate address definition: {key}");
            }
        }
        for (depth, heading, blocks) in shared_sections.iter().cloned() {
            if depth == 1 && heading.eq_ignore_ascii_case("defaults") {
                let f = fields(&blocks);
                if let Some(m) = f.get("unknown message") {
                    unknown = m.clone();
                }
                if let Some(m) = f.get("retired message") {
                    retired = m.clone();
                }
                if let Some(action) = f.get("unknown action").or_else(|| f.get("unknown")) {
                    unknown_action = match action.to_ascii_lowercase().as_str() {
                        "reject" => UnknownAction::Reject,
                        "pass-through" | "passthrough" => UnknownAction::PassThrough,
                        other => bail!("Defaults: invalid unknown-address action {other}"),
                    };
                }
            }
        }
        for (depth, heading, blocks) in shared_sections.iter().cloned() {
            if depth == 1 && heading.eq_ignore_ascii_case("server") {
                let values = fields(&blocks);
                if let Some(value) = values.get("hostname") {
                    hostname = value.clone();
                }
                if let Some(value) = values.get("bind") {
                    bind = if let Ok(address) = value.parse() {
                        address
                    } else if let Ok(address) = value.parse::<IpAddr>() {
                        SocketAddr::new(address, bind.port())
                    } else {
                        bail!("Server: invalid bind {value}");
                    };
                }
                if let Some(value) = values.get("port") {
                    bind.set_port(
                        value
                            .parse()
                            .with_context(|| format!("Server: invalid port {value}"))?,
                    );
                }
            }
            if depth == 1 && heading.eq_ignore_ascii_case("postfix") {
                let values = fields(&blocks);
                if let Some(host) = values.get("host") {
                    postfix_host = host
                        .parse()
                        .with_context(|| format!("Postfix: invalid host {host}"))?;
                }
                if let Some(port) = values.get("port") {
                    postfix_port = port
                        .parse()
                        .with_context(|| format!("Postfix: invalid port {port}"))?;
                }
            }
            if depth == 1 && heading.eq_ignore_ascii_case("server") {
                let values = fields(&blocks);
                if let Some(domains) = values.get("managed domains") {
                    let domains = domains
                        .split('|')
                        .map(str::trim)
                        .filter(|domain| !domain.is_empty())
                        .map(str::to_ascii_lowercase)
                        .collect::<Vec<_>>();
                    for domain in &domains {
                        validate_managed_domain(domain)
                            .with_context(|| format!("Server: invalid managed domain {domain}"))?;
                    }
                    configured_managed_domains = Some(domains);
                }
            }
        }
        let managed_domains = configured_managed_domains.unwrap_or_else(|| {
            definitions
                .keys()
                .filter_map(|address| address.split_once('@').map(|(_, domain)| domain))
                .filter(|domain| !domain.is_empty())
                .map(str::to_string)
                .collect()
        });
        for index in 0..shared_sections.len() {
            if shared_sections[index].0 != 1
                || !shared_sections[index]
                    .1
                    .eq_ignore_ascii_case("trusted senders")
            {
                continue;
            }
            let mut next = index + 1;
            while next < shared_sections.len() && shared_sections[next].0 > 1 {
                if shared_sections[next].0 == 2 {
                    let pattern = normalize(&shared_sections[next].1);
                    validate_sender_pattern(&pattern)
                        .with_context(|| format!("invalid trusted sender pattern {pattern}"))?;
                    if !sender_patterns.insert(pattern.clone()) {
                        bail!("duplicate trusted sender rule: {pattern}");
                    }
                    let values = fields(&shared_sections[next].2);
                    let action = match values
                        .get("action")
                        .map(String::as_str)
                        .unwrap_or("migration-rules")
                        .to_ascii_lowercase()
                        .as_str()
                    {
                        "migration-rules" | "migration" => SenderAction::MigrationRules,
                        "pass-through" | "passthrough" => SenderAction::PassThrough,
                        other => bail!("{pattern}: invalid sender action {other}"),
                    };
                    let verification = match values
                        .get("verify")
                        .map(String::as_str)
                        .unwrap_or("none")
                        .to_ascii_lowercase()
                        .as_str()
                    {
                        "none" => SenderVerification::None,
                        "mx" => SenderVerification::Mx,
                        other => bail!("{pattern}: unknown verification method {other}"),
                    };
                    sender_rules.push(SenderRule {
                        pattern,
                        action,
                        verification,
                    });
                }
                next += 1;
            }
        }
        for index in 0..shared_sections.len() {
            if shared_sections[index].0 != 1
                || !shared_sections[index]
                    .1
                    .eq_ignore_ascii_case("blocked senders")
            {
                continue;
            }
            let mut next = index + 1;
            while next < shared_sections.len() && shared_sections[next].0 > 1 {
                if shared_sections[next].0 == 2 {
                    let pattern = shared_sections[next].1.trim().to_ascii_lowercase();
                    if !blocked_sender_patterns.insert(pattern.clone()) {
                        bail!("duplicate blocked sender rule: {pattern}");
                    }
                    let rule = BlockedSenderRule::new(&pattern)
                        .with_context(|| format!("invalid blocked sender pattern {pattern}"))?;
                    if !pattern.starts_with('/') {
                        validate_blocked_sender_pattern(&pattern)
                            .with_context(|| format!("invalid blocked sender pattern {pattern}"))?;
                    }
                    blocked_sender_rules.push(rule);
                }
                next += 1;
            }
        }
        Ok(Self {
            resolver: Resolver::new(definitions, unknown, retired, unknown_action)
                .context("validating address graph")?,
            sender_policy: SenderPolicy::new(sender_rules, blocked_sender_rules),
            postfix_addr: SocketAddr::new(postfix_host, postfix_port),
            bind,
            hostname,
            limits,
            reject_sender_without_mx,
            reject_null_sender,
            reject_managed_sender_spoofing,
            managed_domains,
        })
    }

    pub fn is_managed_recipient(&self, address: &str) -> bool {
        let Some((_, domain)) = address.split_once('@') else {
            return false;
        };
        self.is_managed_domain(domain)
    }

    pub fn is_managed_domain(&self, domain: &str) -> bool {
        let domain = domain.to_ascii_lowercase();
        self.managed_domains.iter().any(|pattern| {
            pattern == &domain
                || (pattern.ends_with(".*")
                    && domain
                        .strip_prefix(pattern.trim_end_matches(".*"))
                        .is_some_and(|suffix| suffix.starts_with('.')))
        })
    }
}

fn positive_limit(values: &HashMap<String, String>, key: &str, default: usize) -> Result<usize> {
    let Some(value) = values.get(key) else {
        return Ok(default);
    };
    let parsed = value
        .parse::<usize>()
        .with_context(|| format!("Defaults: invalid {key} {value}"))?;
    if parsed == 0 {
        bail!("Defaults: {key} must be greater than zero");
    }
    Ok(parsed)
}

fn parse_bool(value: &str) -> Result<bool> {
    match value.trim().to_ascii_lowercase().as_str() {
        "true" | "yes" | "on" => Ok(true),
        "false" | "no" | "off" => Ok(false),
        other => bail!("{other}"),
    }
}

fn fields(blocks: &[String]) -> HashMap<String, String> {
    let mut result = HashMap::new();
    let mut active_list: Option<String> = None;
    for block in blocks {
        if let Some((key, value)) = block.split_once(':') {
            let key = key.trim().to_ascii_lowercase();
            result.insert(key.clone(), value.trim().to_string());
            active_list = if value.trim().is_empty() {
                Some(key)
            } else {
                None
            };
        } else if let Some(key) = &active_list {
            let value = result.entry(key.clone()).or_default();
            if !value.is_empty() {
                value.push('|');
            }
            value.push_str(block.trim().trim_start_matches("- "));
        }
    }
    result
}
fn list(fields: &HashMap<String, String>, key: &str) -> Vec<String> {
    fields
        .get(key)
        .map(|v| {
            v.split('|')
                .map(normalize)
                .filter(|x| !x.is_empty())
                .collect()
        })
        .unwrap_or_default()
}

fn validate_address(address: &str) -> Result<()> {
    let (local, domain) = address
        .split_once('@')
        .filter(|(_, domain)| !domain.contains('@'))
        .ok_or_else(|| anyhow::anyhow!("expected local@domain"))?;
    if local.is_empty() {
        bail!("local part is empty");
    }
    if local.chars().any(|character| {
        !(character.is_ascii_alphanumeric() || ".!#$%&'*+-/=?^_`{|}~".contains(character))
    }) {
        bail!("local part contains invalid characters");
    }
    if domain.is_empty() {
        return Ok(());
    }
    let domain = domain.strip_suffix(".*").unwrap_or(domain);
    if domain.is_empty() || domain.starts_with('.') || domain.ends_with('.') {
        bail!("domain is malformed");
    }
    for label in domain.split('.') {
        if label.is_empty()
            || label.starts_with('-')
            || label.ends_with('-')
            || label
                .chars()
                .any(|character| !(character.is_ascii_alphanumeric() || character == '-'))
        {
            bail!("domain is malformed");
        }
    }
    Ok(())
}

fn validate_replacement_address(address: &str) -> Result<()> {
    validate_address(address)?;
    let domain = address
        .split_once('@')
        .map(|(_, domain)| domain)
        .unwrap_or_default();
    if domain.is_empty() || domain.ends_with(".*") {
        bail!("replacement must use a fully qualified domain");
    }
    Ok(())
}

fn validate_sender_pattern(pattern: &str) -> Result<()> {
    if pattern.starts_with('@') {
        validate_address(&format!("sender{pattern}"))
    } else if pattern.contains('@') {
        validate_address(pattern)
    } else {
        validate_address(&format!("sender@{pattern}"))
    }
}

fn validate_managed_domain(domain: &str) -> Result<()> {
    let candidate = domain.strip_suffix(".*").unwrap_or(domain);
    if candidate.is_empty() {
        bail!("domain is empty");
    }
    for label in candidate.split('.') {
        if label.is_empty()
            || label.starts_with('-')
            || label.ends_with('-')
            || label
                .chars()
                .any(|character| !(character.is_ascii_alphanumeric() || character == '-'))
        {
            bail!("domain is malformed");
        }
    }
    Ok(())
}

fn section_heading(sections: &[(usize, String, Vec<String>)], index: usize) -> Option<String> {
    sections
        .iter()
        .take(index)
        .rev()
        .find(|(depth, _, _)| *depth == 1)
        .map(|(_, section, _)| section.clone())
}

fn validate_blocked_sender_pattern(pattern: &str) -> Result<()> {
    if pattern.starts_with('@') {
        let domain = pattern.trim_start_matches('@');
        if domain.is_empty() {
            bail!("blocked sender domain is empty");
        }
        let domain = domain.replace(['*', '?'], "x");
        return validate_sender_pattern(&domain);
    }
    if pattern.contains('*') || pattern.contains('?') {
        let candidate = pattern.replace('*', "sender").replace('?', "x");
        return validate_sender_pattern(&candidate);
    }
    validate_sender_pattern(pattern)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loads_shared_sources_and_wildcards() {
        let config = Config::from_markdown(
            "# Addresses\n\n## john.allen@example.com\n\n## johnallen@example.com\n\nReplaced By:\n\n- john@example.net\n\n## jane@classesarecode.*\n\nReplaced By:\n\n- jane@example.net\n",
        )
        .unwrap();
        assert!(matches!(
            config.resolver.resolve("johnallen@example.com"),
            crate::address::Resolution::Retired { .. }
        ));
        assert!(matches!(
            config.resolver.resolve("jane@classesarecode.org"),
            crate::address::Resolution::Retired { .. }
        ));
    }

    #[test]
    fn rejects_malformed_addresses() {
        let result = Config::from_markdown(
            "# Addresses\n\n## broken@@example.com\n\nReplaced By:\n\n- target@example.net\n",
        );
        assert!(result.is_err());
    }

    #[test]
    fn configures_unknown_addresses_for_pass_through() {
        let config = Config::from_markdown(
            "# Defaults\n\nUnknown Action: pass-through\n\n# Addresses\n\n## known@example.com\n\nReplaced By:\n\n- replacement@example.net\n",
        )
        .unwrap();
        assert!(matches!(
            config.resolver.resolve("unknown@example.com"),
            crate::address::Resolution::Unknown {
                action: UnknownAction::PassThrough,
                ..
            }
        ));
    }

    #[test]
    fn loads_custom_rejection_message() {
        let config = Config::from_markdown(
            "# Addresses\n\n## old@example.com\n\nReplaced By:\n\n- new@example.net\n\nMessage: This mailbox moved to the new address.\n",
        )
        .unwrap();
        match config.resolver.resolve("old@example.com") {
            crate::address::Resolution::Retired { message, .. } => {
                assert_eq!(message, "This mailbox moved to the new address.");
            }
            other => panic!("expected retired resolution, got {other:?}"),
        }
    }

    #[test]
    fn invalid_replacements_leave_source_unconfigured() {
        let config = Config::from_markdown(
            "# Addresses\n\n## old@example.com\n\nReplaced By:\n\n- localuser@\n",
        )
        .unwrap();
        assert!(matches!(
            config.resolver.resolve("old@example.com"),
            crate::address::Resolution::Unknown { .. }
        ));
    }

    #[test]
    fn rejects_duplicate_trusted_sender_rules() {
        let result = Config::from_markdown(
            "# Trusted Senders\n\n## example.com\n\nAction: pass-through\n\n## example.com\n\nAction: migration-rules\n",
        );
        assert!(result.is_err());
    }

    #[test]
    fn loads_resource_limits() {
        let config = Config::from_markdown(
            "# Defaults\n\nMax Connections: 12\n\nMax Line Bytes: 2048\n\nMax Recipients: 20\n\nMax Data Bytes: 4096\n",
        )
        .unwrap();
        assert_eq!(config.limits.max_connections, 12);
        assert_eq!(config.limits.max_line_bytes, 2048);
        assert_eq!(config.limits.max_recipients, 20);
        assert_eq!(config.limits.max_data_bytes, 4096);
    }

    #[test]
    fn rejects_invalid_resource_limits() {
        for value in ["0", "not-a-number"] {
            let source = format!("# Defaults\n\nMax Connections: {value}\n");
            assert!(Config::from_markdown(&source).is_err());
        }
    }

    #[test]
    fn known_action_sets_default_pass_through() {
        let config = Config::from_markdown(
            "# Defaults\n\nKnown Action: pass-through\n\n# Addresses\n\n## old@example.com\n\nReplaced By:\n\n- new@example.net\n\n## strict@example.com\n\nReplaced By:\n\n- strict@example.net\n\nPass Through: false\n",
        )
        .unwrap();
        assert!(matches!(
            config.resolver.resolve("old@example.com"),
            crate::address::Resolution::Retired {
                pass_through: true,
                ..
            }
        ));
        assert!(matches!(
            config.resolver.resolve("strict@example.com"),
            crate::address::Resolution::Retired {
                pass_through: false,
                ..
            }
        ));
    }

    #[test]
    fn loads_blocked_sender_patterns() {
        let config = Config::from_markdown(
            "# Blocked Senders\n\n## jobs@moyville.net\n\n## @mail.gl1pro.shop\n\n## /.*@bad.example$/\n",
        )
        .unwrap();
        assert!(
            config
                .sender_policy
                .blocked_sender("jobs@moyville.net")
                .is_some()
        );
        assert!(
            config
                .sender_policy
                .blocked_sender("anything@mail.gl1pro.shop")
                .is_some()
        );
        assert!(
            config
                .sender_policy
                .blocked_sender("spam@bad.example")
                .is_some()
        );
    }
}
