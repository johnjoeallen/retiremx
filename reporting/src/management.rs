use anyhow::{bail, Context, Result};
use pulldown_cmark::{Event, HeadingLevel, Parser, Tag, TagEnd};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, HashSet},
    fmt::Write as FmtWrite,
    fs,
    path::Path,
};

#[derive(Debug, Clone, Serialize)]
pub struct ManagementConfig {
    pub source_path: String,
    pub source_sha256: String,
    pub unknown_message: String,
    pub unknown_action: String,
    pub retired_message: String,
    pub known_action: String,
    pub reject_sender_without_mx: bool,
    pub reject_null_sender: bool,
    pub reject_managed_sender_spoofing: bool,
    pub hostname: String,
    pub bind: String,
    pub port: i32,
    pub postfix_host: String,
    pub postfix_port: i32,
    pub max_connections: i32,
    pub max_line_bytes: i32,
    pub max_recipients: i32,
    pub max_data_bytes: i32,
    pub idle_timeout_seconds: i32,
    pub managed_domains: Vec<String>,
    pub recipients: Vec<RecipientGroup>,
    pub trusted_senders: Vec<TrustedSender>,
    pub blocked_senders: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RecipientGroup {
    pub source_address: String,
    pub members: Vec<String>,
    pub pass_through: bool,
    pub message: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct TrustedSender {
    pub pattern: String,
    pub action: String,
    pub verification: String,
}

#[derive(Debug, Serialize)]
pub struct ImportSummary {
    pub source_path: String,
    pub source_sha256: String,
    pub managed_domains: usize,
    pub recipient_groups: usize,
    pub recipient_members: usize,
    pub trusted_senders: usize,
    pub blocked_senders: usize,
}

#[derive(Debug, Clone)]
struct Section {
    depth: usize,
    heading: String,
    blocks: Vec<String>,
}

pub fn parse_file(path: &Path) -> Result<ManagementConfig> {
    let source = fs::read_to_string(path)
        .with_context(|| format!("reading configuration {}", path.display()))?;
    parse(&source, &path.display().to_string())
}

pub fn parse(source: &str, source_path: &str) -> Result<ManagementConfig> {
    let source_sha256 = sha256(source.as_bytes());
    let sections = shared_source_sections(parse_sections(source));
    let mut unknown_message = "No such address".to_string();
    let mut unknown_action = "reject".to_string();
    let mut retired_message = "This address is no longer in use".to_string();
    let mut known_action = "reject".to_string();
    let mut reject_sender_without_mx = true;
    let mut reject_null_sender = true;
    let mut reject_managed_sender_spoofing = true;
    let mut hostname = "localhost".to_string();
    let mut bind = "0.0.0.0".to_string();
    let mut port = 25;
    let mut postfix_host = "127.0.0.1".to_string();
    let mut postfix_port = 2525;
    let mut max_connections = 100;
    let mut max_line_bytes = 1000;
    let mut max_recipients = 100;
    let mut max_data_bytes = 10 * 1024 * 1024;
    let mut idle_timeout_seconds = 60;
    let mut managed_domains = Vec::new();

    for section in &sections {
        if section.depth != 1 {
            continue;
        }
        let values = fields(&section.blocks);
        if section.heading.eq_ignore_ascii_case("defaults") {
            if let Some(value) = values.get("unknown message") {
                unknown_message = value.clone();
            }
            if let Some(value) = values
                .get("unknown action")
                .or_else(|| values.get("unknown"))
            {
                unknown_action = action(value, &section.heading)?;
            }
            if let Some(value) = values.get("retired message") {
                retired_message = value.clone();
            }
            if let Some(value) = values
                .get("known action")
                .or_else(|| values.get("default action"))
            {
                known_action = action(value, &section.heading)?;
            }
            reject_sender_without_mx = bool_value(
                &values,
                "reject sender without mx",
                reject_sender_without_mx,
            )?;
            reject_null_sender = bool_value(&values, "reject null sender", reject_null_sender)?;
            reject_managed_sender_spoofing = bool_value(
                &values,
                "reject managed sender spoofing",
                reject_managed_sender_spoofing,
            )?;
            max_connections = positive_value(&values, "max connections", max_connections)?;
            max_line_bytes = positive_value(&values, "max line bytes", max_line_bytes)?;
            max_recipients = positive_value(&values, "max recipients", max_recipients)?;
            max_data_bytes = positive_value(&values, "max data bytes", max_data_bytes)?;
            idle_timeout_seconds =
                positive_value(&values, "idle timeout seconds", idle_timeout_seconds)?;
        } else if section.heading.eq_ignore_ascii_case("server") {
            if let Some(value) = values.get("hostname") {
                hostname = value.clone();
            }
            if let Some(value) = values.get("bind") {
                bind = value.clone();
            }
            if let Some(value) = values.get("port") {
                port = value
                    .parse()
                    .with_context(|| format!("Server: invalid port {value}"))?;
            }
            managed_domains = list(&values, "managed domains");
            for domain in &managed_domains {
                validate_domain(domain)?;
            }
        } else if section.heading.eq_ignore_ascii_case("postfix") {
            if let Some(value) = values.get("host") {
                postfix_host = value.clone();
            }
            if let Some(value) = values.get("port") {
                postfix_port = value
                    .parse()
                    .with_context(|| format!("Postfix: invalid port {value}"))?;
            }
        }
    }

    let mut recipients = Vec::new();
    let mut trusted_senders = Vec::new();
    let mut blocked_senders = Vec::new();
    let mut seen_sources = HashSet::new();
    let mut seen_trusted = HashSet::new();
    let mut seen_blocked = HashSet::new();

    for (index, section) in sections.iter().enumerate() {
        if section.depth != 2 {
            continue;
        }
        let Some(parent) = parent_heading(&sections, index) else {
            continue;
        };
        if parent.eq_ignore_ascii_case("trusted senders") {
            let pattern = section.heading.trim().to_ascii_lowercase();
            if !seen_trusted.insert(pattern.clone()) {
                bail!("duplicate trusted sender rule: {pattern}");
            }
            validate_sender_pattern(&pattern)?;
            let values = fields(&section.blocks);
            trusted_senders.push(TrustedSender {
                pattern,
                action: action(
                    values
                        .get("action")
                        .map(String::as_str)
                        .unwrap_or("migration-rules"),
                    &section.heading,
                )?,
                verification: match values
                    .get("verify")
                    .map(String::as_str)
                    .unwrap_or("none")
                    .to_ascii_lowercase()
                    .as_str()
                {
                    "none" | "mx" => values
                        .get("verify")
                        .cloned()
                        .unwrap_or_else(|| "none".into())
                        .to_ascii_lowercase(),
                    other => bail!("{}: unknown verification method {other}", section.heading),
                },
            });
        } else if parent.eq_ignore_ascii_case("blocked senders") {
            let pattern = section.heading.trim().to_ascii_lowercase();
            if !seen_blocked.insert(pattern.clone()) {
                bail!("duplicate blocked sender rule: {pattern}");
            }
            validate_sender_pattern(&pattern)?;
            blocked_senders.push(pattern);
        } else if section.heading.contains('@') {
            let source_address = section.heading.trim().to_ascii_lowercase();
            validate_address(&source_address, false)
                .with_context(|| format!("invalid source address {source_address}"))?;
            if !seen_sources.insert(source_address.clone()) {
                bail!("duplicate address definition: {source_address}");
            }
            let values = fields(&section.blocks);
            let configured_members = list(&values, "replaced by");
            let mut members = Vec::new();
            for member in configured_members {
                if let Err(error) = validate_address(&member, true) {
                    eprintln!("warning: {source_address}: ignoring replacement {member}: {error}");
                } else {
                    members.push(member);
                }
            }
            if members.is_empty() {
                eprintln!(
                    "warning: {source_address}: no valid replacements; source left unconfigured"
                );
                continue;
            }
            let pass_through = match values.get("pass through") {
                None => known_action == "pass-through",
                Some(value) => parse_bool(value)
                    .with_context(|| format!("{source_address}: invalid Pass Through value"))?,
            };
            recipients.push(RecipientGroup {
                source_address,
                members,
                pass_through,
                message: values.get("message").cloned(),
            });
        }
    }
    if managed_domains.is_empty() {
        managed_domains = recipients
            .iter()
            .filter_map(|group| {
                group
                    .source_address
                    .split_once('@')
                    .map(|(_, domain)| domain.to_string())
            })
            .filter(|domain| !domain.is_empty())
            .collect();
        managed_domains.sort();
        managed_domains.dedup();
    }
    detect_cycles(&recipients)?;
    Ok(ManagementConfig {
        source_path: source_path.into(),
        source_sha256,
        unknown_message,
        unknown_action,
        retired_message,
        known_action,
        reject_sender_without_mx,
        reject_null_sender,
        reject_managed_sender_spoofing,
        hostname,
        bind,
        port,
        postfix_host,
        postfix_port,
        max_connections,
        max_line_bytes,
        max_recipients,
        max_data_bytes,
        idle_timeout_seconds,
        managed_domains,
        recipients,
        trusted_senders,
        blocked_senders,
    })
}

pub fn summary(config: &ManagementConfig) -> ImportSummary {
    ImportSummary {
        source_path: config.source_path.clone(),
        source_sha256: config.source_sha256.clone(),
        managed_domains: config.managed_domains.len(),
        recipient_groups: config.recipients.len(),
        recipient_members: config
            .recipients
            .iter()
            .map(|group| group.members.len())
            .sum(),
        trusted_senders: config.trusted_senders.len(),
        blocked_senders: config.blocked_senders.len(),
    }
}

pub fn normalize_recipient_group(
    source: &str,
    members: &[String],
) -> Result<(String, Vec<String>)> {
    let source = source.trim().to_ascii_lowercase();
    validate_address(&source, false).context("invalid source address")?;
    let mut normalized = Vec::new();
    for member in members {
        let member = member.trim().to_ascii_lowercase();
        validate_address(&member, true).context("replacement must use a fully qualified domain")?;
        if !normalized.contains(&member) {
            normalized.push(member);
        }
    }
    if normalized.is_empty() {
        bail!("at least one replacement is required");
    }
    Ok((source, normalized))
}

pub fn normalize_blocked_sender(pattern: &str) -> Result<String> {
    let pattern = pattern.trim().to_ascii_lowercase();
    if pattern.is_empty() {
        bail!("blocked sender pattern is required");
    }
    validate_sender_pattern(&pattern)?;
    Ok(pattern)
}

pub fn ensure_schema<C: postgres::GenericClient>(client: &mut C) -> Result<()> {
    client.batch_execute(r#"
        CREATE TABLE IF NOT EXISTS management_config (
            singleton BOOLEAN PRIMARY KEY CHECK (singleton),
            source_path TEXT NOT NULL,
            source_sha256 TEXT NOT NULL,
            imported_at TIMESTAMPTZ NOT NULL DEFAULT now(),
            unknown_message TEXT NOT NULL,
            unknown_action TEXT NOT NULL,
            retired_message TEXT NOT NULL,
            known_action TEXT NOT NULL,
            reject_sender_without_mx BOOLEAN NOT NULL,
            reject_null_sender BOOLEAN NOT NULL,
            reject_managed_sender_spoofing BOOLEAN NOT NULL,
            hostname TEXT NOT NULL,
            bind TEXT NOT NULL,
            port INTEGER NOT NULL,
            postfix_host TEXT NOT NULL,
            postfix_port INTEGER NOT NULL,
            max_connections INTEGER NOT NULL DEFAULT 100,
            max_line_bytes INTEGER NOT NULL DEFAULT 1000,
            max_recipients INTEGER NOT NULL DEFAULT 100,
            max_data_bytes INTEGER NOT NULL DEFAULT 10485760,
            idle_timeout_seconds INTEGER NOT NULL DEFAULT 60
        );
        ALTER TABLE management_config ADD COLUMN IF NOT EXISTS max_connections INTEGER NOT NULL DEFAULT 100;
        ALTER TABLE management_config ADD COLUMN IF NOT EXISTS max_line_bytes INTEGER NOT NULL DEFAULT 1000;
        ALTER TABLE management_config ADD COLUMN IF NOT EXISTS max_recipients INTEGER NOT NULL DEFAULT 100;
        ALTER TABLE management_config ADD COLUMN IF NOT EXISTS max_data_bytes INTEGER NOT NULL DEFAULT 10485760;
        ALTER TABLE management_config ADD COLUMN IF NOT EXISTS idle_timeout_seconds INTEGER NOT NULL DEFAULT 60;
        CREATE TABLE IF NOT EXISTS management_domains (domain TEXT PRIMARY KEY);
        CREATE TABLE IF NOT EXISTS management_recipient_groups (
            source_address TEXT PRIMARY KEY,
            pass_through BOOLEAN NOT NULL,
            message TEXT
        );
        CREATE TABLE IF NOT EXISTS management_recipient_members (
            source_address TEXT NOT NULL REFERENCES management_recipient_groups(source_address) ON DELETE CASCADE,
            position INTEGER NOT NULL,
            member_address TEXT NOT NULL,
            PRIMARY KEY (source_address, position)
        );
        CREATE TABLE IF NOT EXISTS management_trusted_senders (
            pattern TEXT PRIMARY KEY,
            action TEXT NOT NULL,
            verification TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS management_blocked_senders (pattern TEXT PRIMARY KEY);
        CREATE TABLE IF NOT EXISTS management_imports (
            import_id BIGSERIAL PRIMARY KEY,
            source_path TEXT NOT NULL,
            source_sha256 TEXT NOT NULL,
            imported_at TIMESTAMPTZ NOT NULL DEFAULT now(),
            applied BOOLEAN NOT NULL,
            dry_run BOOLEAN NOT NULL,
            summary JSONB NOT NULL
        );
    "#)?;
    Ok(())
}

pub fn replace_config(
    client: &mut postgres::Client,
    config: &ManagementConfig,
    dry_run: bool,
) -> Result<()> {
    let summary = serde_json::to_value(summary(config))?;
    let mut tx = client.transaction()?;
    ensure_schema(&mut tx)?;
    if !dry_run {
        tx.execute("DELETE FROM management_domains", &[])?;
        tx.execute("DELETE FROM management_recipient_members", &[])?;
        tx.execute("DELETE FROM management_recipient_groups", &[])?;
        tx.execute("DELETE FROM management_trusted_senders", &[])?;
        tx.execute("DELETE FROM management_blocked_senders", &[])?;
        tx.execute("DELETE FROM management_config", &[])?;
        tx.execute("INSERT INTO management_config (singleton, source_path, source_sha256, unknown_message, unknown_action, retired_message, known_action, reject_sender_without_mx, reject_null_sender, reject_managed_sender_spoofing, hostname, bind, port, postfix_host, postfix_port, max_connections, max_line_bytes, max_recipients, max_data_bytes, idle_timeout_seconds) VALUES (true, $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19)", &[&config.source_path, &config.source_sha256, &config.unknown_message, &config.unknown_action, &config.retired_message, &config.known_action, &config.reject_sender_without_mx, &config.reject_null_sender, &config.reject_managed_sender_spoofing, &config.hostname, &config.bind, &config.port, &config.postfix_host, &config.postfix_port, &config.max_connections, &config.max_line_bytes, &config.max_recipients, &config.max_data_bytes, &config.idle_timeout_seconds])?;
        for domain in &config.managed_domains {
            tx.execute(
                "INSERT INTO management_domains (domain) VALUES ($1)",
                &[domain],
            )?;
        }
        for group in &config.recipients {
            tx.execute("INSERT INTO management_recipient_groups (source_address, pass_through, message) VALUES ($1, $2, $3)", &[&group.source_address, &group.pass_through, &group.message])?;
            for (position, member) in group.members.iter().enumerate() {
                let position = position as i32;
                tx.execute("INSERT INTO management_recipient_members (source_address, position, member_address) VALUES ($1, $2, $3)", &[&group.source_address, &position, member])?;
            }
        }
        for rule in &config.trusted_senders {
            tx.execute("INSERT INTO management_trusted_senders (pattern, action, verification) VALUES ($1, $2, $3)", &[&rule.pattern, &rule.action, &rule.verification])?;
        }
        for pattern in &config.blocked_senders {
            tx.execute(
                "INSERT INTO management_blocked_senders (pattern) VALUES ($1)",
                &[pattern],
            )?;
        }
    }
    tx.execute("INSERT INTO management_imports (source_path, source_sha256, applied, dry_run, summary) VALUES ($1, $2, $3, $4, $5)", &[&config.source_path, &config.source_sha256, &(!dry_run), &dry_run, &summary])?;
    tx.commit()?;
    Ok(())
}

pub fn export_markdown<C: postgres::GenericClient>(client: &mut C) -> Result<String> {
    let Some(config) = client.query_opt(
        "SELECT unknown_message, unknown_action, retired_message, known_action, reject_sender_without_mx, reject_null_sender, reject_managed_sender_spoofing, hostname, bind, port, postfix_host, postfix_port, max_connections, max_line_bytes, max_recipients, max_data_bytes, idle_timeout_seconds FROM management_config WHERE singleton = true",
        &[],
    )? else {
        bail!("management configuration has not been imported");
    };
    let domains: Vec<String> = client
        .query("SELECT domain FROM management_domains ORDER BY domain", &[])?
        .iter()
        .map(|row| row.get("domain"))
        .collect();
    let trusted: Vec<(String, String, String)> = client
        .query(
            "SELECT pattern, action, verification FROM management_trusted_senders ORDER BY pattern",
            &[],
        )?
        .iter()
        .map(|row| {
            (
                row.get("pattern"),
                row.get("action"),
                row.get("verification"),
            )
        })
        .collect();
    let blocked: Vec<String> = client
        .query(
            "SELECT pattern FROM management_blocked_senders ORDER BY pattern",
            &[],
        )?
        .iter()
        .map(|row| row.get("pattern"))
        .collect();
    let mut groups: Vec<RecipientGroup> = client
        .query(
            "SELECT source_address, pass_through, message FROM management_recipient_groups ORDER BY source_address",
            &[],
        )?
        .iter()
        .map(|row| RecipientGroup {
            source_address: row.get("source_address"),
            members: Vec::new(),
            pass_through: row.get("pass_through"),
            message: row.get("message"),
        })
        .collect();
    for row in client.query(
        "SELECT source_address, member_address FROM management_recipient_members ORDER BY source_address, position",
        &[],
    )? {
        if let Some(group) = groups.iter_mut().find(|group| {
            group.source_address == row.get::<_, String>("source_address")
        }) {
            group.members.push(row.get("member_address"));
        }
    }

    let mut output = String::new();
    writeln!(output, "# Defaults\n")?;
    writeln!(
        output,
        "Unknown Message: {}\n",
        config.get::<_, String>("unknown_message")
    )?;
    writeln!(
        output,
        "Unknown Action: {}\n",
        config.get::<_, String>("unknown_action")
    )?;
    writeln!(
        output,
        "Retired Message: {}\n",
        config.get::<_, String>("retired_message")
    )?;
    writeln!(
        output,
        "Known Action: {}\n",
        config.get::<_, String>("known_action")
    )?;
    writeln!(
        output,
        "Reject Sender Without MX: {}\n",
        config.get::<_, bool>("reject_sender_without_mx")
    )?;
    writeln!(
        output,
        "Reject Null Sender: {}\n",
        config.get::<_, bool>("reject_null_sender")
    )?;
    writeln!(
        output,
        "Reject Managed Sender Spoofing: {}\n",
        config.get::<_, bool>("reject_managed_sender_spoofing")
    )?;
    writeln!(
        output,
        "Max Connections: {}\n",
        config.get::<_, i32>("max_connections")
    )?;
    writeln!(
        output,
        "Max Line Bytes: {}\n",
        config.get::<_, i32>("max_line_bytes")
    )?;
    writeln!(
        output,
        "Max Recipients: {}\n",
        config.get::<_, i32>("max_recipients")
    )?;
    writeln!(
        output,
        "Max Data Bytes: {}\n",
        config.get::<_, i32>("max_data_bytes")
    )?;
    writeln!(
        output,
        "Idle Timeout Seconds: {}\n",
        config.get::<_, i32>("idle_timeout_seconds")
    )?;
    writeln!(output, "# Server\n")?;
    writeln!(
        output,
        "Hostname: {}\n",
        config.get::<_, String>("hostname")
    )?;
    writeln!(output, "Managed Domains:\n")?;
    for domain in &domains {
        writeln!(output, "- {domain}")?;
    }
    writeln!(output, "\nBind: {}\n", config.get::<_, String>("bind"))?;
    writeln!(output, "Port: {}\n", config.get::<_, i32>("port"))?;
    writeln!(output, "# Postfix\n")?;
    writeln!(
        output,
        "Host: {}\n",
        config.get::<_, String>("postfix_host")
    )?;
    writeln!(output, "Port: {}\n", config.get::<_, i32>("postfix_port"))?;
    writeln!(output, "# Trusted Senders\n")?;
    for (pattern, action, verification) in trusted {
        writeln!(
            output,
            "## {pattern}\n\nAction: {action}\n\nVerify: {verification}\n"
        )?;
    }
    writeln!(output, "# Blocked Senders\n")?;
    for pattern in blocked {
        writeln!(output, "## {pattern}\n")?;
    }
    writeln!(output, "# Addresses\n")?;
    for group in groups {
        writeln!(output, "## {}\n\nReplaced By:\n", group.source_address)?;
        for member in group.members {
            writeln!(output, "- {member}")?;
        }
        writeln!(output)?;
        if group.pass_through {
            writeln!(output, "Pass Through: true\n")?;
        }
        if let Some(message) = group.message {
            writeln!(output, "Message: {message}\n")?;
        }
    }
    Ok(output)
}

fn parse_sections(source: &str) -> Vec<Section> {
    let mut sections = Vec::new();
    let mut current = None;
    let mut buffer = String::new();
    let flush = |sections: &mut Vec<Section>, current: &mut Option<usize>, buffer: &mut String| {
        if let Some(index) = *current {
            if !buffer.trim().is_empty() {
                sections[index].blocks.push(buffer.trim().to_string());
            }
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
                sections.push(Section {
                    depth,
                    heading: String::new(),
                    blocks: Vec::new(),
                });
                current = Some(sections.len() - 1);
            }
            Event::End(TagEnd::Heading(_)) => {
                if let Some(index) = current {
                    sections[index].heading = buffer.trim().to_string();
                    buffer.clear();
                }
            }
            Event::Start(Tag::Paragraph) | Event::Start(Tag::Item) => {}
            Event::End(TagEnd::Paragraph) | Event::End(TagEnd::Item) => {
                flush(&mut sections, &mut current, &mut buffer)
            }
            Event::Text(text) | Event::Code(text) => buffer.push_str(&text),
            Event::SoftBreak | Event::HardBreak => buffer.push(' '),
            Event::Start(Tag::List(_)) | Event::End(TagEnd::List(_)) => {}
            _ => {}
        }
    }
    sections
}

fn shared_source_sections(mut sections: Vec<Section>) -> Vec<Section> {
    for index in 0..sections.len() {
        if sections[index].depth != 2
            || !sections[index].heading.contains('@')
            || !sections[index].blocks.is_empty()
        {
            continue;
        }
        let mut next = index + 1;
        while next < sections.len()
            && sections[next].depth == 2
            && sections[next].heading.contains('@')
        {
            if !sections[next].blocks.is_empty() {
                sections[index].blocks = sections[next].blocks.clone();
                break;
            }
            next += 1;
        }
    }
    sections
}

fn parent_heading(sections: &[Section], index: usize) -> Option<String> {
    sections[..index]
        .iter()
        .rev()
        .find(|section| section.depth == 1)
        .map(|section| section.heading.clone())
}

fn fields(blocks: &[String]) -> HashMap<String, String> {
    let mut values = HashMap::new();
    let mut active = None;
    for block in blocks {
        if let Some((key, value)) = block.split_once(':') {
            let key = key.trim().to_ascii_lowercase();
            values.insert(key.clone(), value.trim().to_string());
            active = value.trim().is_empty().then_some(key);
        } else if let Some(key) = &active {
            let value = values.entry(key.clone()).or_default();
            if !value.is_empty() {
                value.push('|');
            }
            value.push_str(block.trim().trim_start_matches("- "));
        }
    }
    values
}

fn list(values: &HashMap<String, String>, key: &str) -> Vec<String> {
    values
        .get(key)
        .map(|value| {
            value
                .split('|')
                .map(|item| item.trim().to_ascii_lowercase())
                .filter(|item| !item.is_empty())
                .collect()
        })
        .unwrap_or_default()
}
fn bool_value(values: &HashMap<String, String>, key: &str, default: bool) -> Result<bool> {
    values
        .get(key)
        .map(|value| parse_bool(value))
        .unwrap_or(Ok(default))
}
fn positive_value(values: &HashMap<String, String>, key: &str, default: i32) -> Result<i32> {
    let Some(value) = values.get(key) else {
        return Ok(default);
    };
    let parsed = value
        .parse::<i32>()
        .with_context(|| format!("Defaults: invalid {key} {value}"))?;
    if parsed <= 0 {
        bail!("Defaults: {key} must be greater than zero");
    }
    Ok(parsed)
}
fn parse_bool(value: &str) -> Result<bool> {
    match value.trim().to_ascii_lowercase().as_str() {
        "true" | "yes" | "on" => Ok(true),
        "false" | "no" | "off" => Ok(false),
        other => bail!("invalid boolean {other}"),
    }
}
fn action(value: &str, context: &str) -> Result<String> {
    match value.trim().to_ascii_lowercase().as_str() {
        "reject" | "migration-rules" | "migration" => Ok("migration-rules".into()),
        "pass-through" | "passthrough" => Ok("pass-through".into()),
        other => bail!("{context}: invalid action {other}"),
    }
}
fn validate_domain(domain: &str) -> Result<()> {
    let value = domain.strip_suffix(".*").unwrap_or(domain);
    if value.is_empty()
        || value.split('.').any(|label| {
            label.is_empty()
                || label.starts_with('-')
                || label.ends_with('-')
                || label
                    .chars()
                    .any(|c| !(c.is_ascii_alphanumeric() || c == '-'))
        })
    {
        bail!("domain is malformed: {domain}");
    }
    Ok(())
}
fn validate_address(address: &str, replacement: bool) -> Result<()> {
    let Some((local, domain)) = address.split_once('@') else {
        bail!("expected local@domain");
    };
    if local.is_empty()
        || local
            .chars()
            .any(|c| !(c.is_ascii_alphanumeric() || ".!#$%&'*+-/=?^_`{|}~".contains(c)))
    {
        bail!("local part is malformed");
    }
    if replacement && (domain.is_empty() || domain.ends_with(".*")) {
        bail!("replacement must use a fully qualified domain");
    }
    if !domain.is_empty() {
        validate_domain(domain)?;
    }
    Ok(())
}
fn validate_sender_pattern(pattern: &str) -> Result<()> {
    if pattern.starts_with('/') {
        if !pattern.ends_with('/') || pattern.len() < 3 {
            bail!("invalid regex sender pattern: {pattern}");
        }
        regex::Regex::new(&pattern[1..pattern.len() - 1])
            .with_context(|| format!("invalid regex sender pattern: {pattern}"))?;
        return Ok(());
    }
    if pattern.starts_with('@') {
        let domain = pattern.trim_start_matches('@').replace(['*', '?'], "x");
        return validate_domain(&domain);
    }
    if pattern.contains('*') || pattern.contains('?') {
        let candidate = pattern.replace('*', "sender").replace('?', "x");
        return validate_address(&candidate, false);
    }
    if pattern.contains('@') {
        return validate_address(pattern, false);
    }
    validate_domain(pattern.trim_matches('*'))
}
fn detect_cycles(groups: &[RecipientGroup]) -> Result<()> {
    let graph = groups
        .iter()
        .map(|group| {
            (
                group.source_address.as_str(),
                group.members.iter().map(String::as_str).collect::<Vec<_>>(),
            )
        })
        .collect::<HashMap<_, _>>();
    fn visit<'a>(
        node: &'a str,
        graph: &HashMap<&'a str, Vec<&'a str>>,
        visiting: &mut HashSet<&'a str>,
        visited: &mut HashSet<&'a str>,
        path: &mut Vec<&'a str>,
    ) -> Result<()> {
        if visiting.contains(node) {
            bail!("address cycle detected: {}", path.join(" -> "));
        }
        if !visited.insert(node) {
            return Ok(());
        }
        visiting.insert(node);
        path.push(node);
        if let Some(members) = graph.get(node) {
            for member in members {
                if graph.contains_key(member) {
                    visit(member, graph, visiting, visited, path)?;
                }
            }
        }
        path.pop();
        visiting.remove(node);
        Ok(())
    }
    let mut visiting = HashSet::new();
    let mut visited = HashSet::new();
    for node in graph.keys() {
        visit(node, &graph, &mut visiting, &mut visited, &mut Vec::new())?;
    }
    Ok(())
}
fn sha256(source: &[u8]) -> String {
    Sha256::digest(source)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::parse;

    #[test]
    fn imports_groups_shared_sources_and_policies() {
        let config = parse(
            r#"# Defaults

Known Action: pass-through

Unknown Action: reject

# Server

Managed Domains:

- moyville.net

# Trusted Senders

## trusted.example

Action: pass-through

Verify: mx

# Blocked Senders

## *@spam.example

# Addresses

## old.one@moyville.net

## old.two@moyville.net

Replaced By:

- new@example.net
"#,
            "test.md",
        )
        .unwrap();
        assert_eq!(config.recipients.len(), 2);
        assert_eq!(config.recipients[0].members, vec!["new@example.net"]);
        assert_eq!(config.trusted_senders[0].verification, "mx");
        assert_eq!(config.blocked_senders, vec!["*@spam.example"]);
    }

    #[test]
    fn rejects_cycles() {
        let result = parse("# Addresses\n\n## a@example.com\n\nReplaced By:\n\n- b@example.com\n\n## b@example.com\n\nReplaced By:\n\n- a@example.com\n", "test.md");
        assert!(result.is_err());
    }

    #[test]
    fn ignores_unqualified_replacements() {
        let config = parse(
            "# Addresses\n\n## postmaster@example.com\n\nReplaced By:\n\n- root\n",
            "test.md",
        )
        .unwrap();
        assert!(config.recipients.is_empty());
    }
}
