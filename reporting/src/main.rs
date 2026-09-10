use anyhow::{Context, Result};
use clap::Parser;
use postgres::{Client, NoTls};
use serde_json::Value;
use std::{
    fs::{self, Metadata, OpenOptions},
    io::{BufRead, BufReader, Seek, SeekFrom},
    path::PathBuf,
    thread,
    time::Duration,
};
use uuid::Uuid;

mod management;
mod web;

#[derive(Parser, Debug)]
#[command(name = "retiremx-report", about = "retiremx JSONL reporting collector")]
struct Args {
    #[arg(long, value_enum, default_value_t = Mode::Collector)]
    mode: Mode,
    #[arg(long, env = "DATABASE_URL")]
    database_url: String,
    #[arg(long, env = "RETIREMX_LOG_PATH", default_value = "/logs/events.jsonl")]
    log_path: PathBuf,
    #[arg(long, env = "RETIREMX_POLL_SECONDS", default_value_t = 1)]
    poll_seconds: u64,
    #[arg(long, default_value = "0.0.0.0:8080")]
    bind: String,
    #[arg(
        long,
        env = "RETIREMX_CONFIG_PATH",
        default_value = "/etc/retiremx/retiremx.md"
    )]
    retiremx_config: PathBuf,
    #[arg(long, default_value = "/etc/retiremx/retiremx.md")]
    input: PathBuf,
    #[arg(long)]
    apply: bool,
    #[arg(long)]
    yes: bool,
    #[arg(long)]
    dry_run: bool,
    #[arg(long)]
    output: Option<PathBuf>,
}

#[derive(clap::ValueEnum, Clone, Debug)]
enum Mode {
    Collector,
    Web,
    Import,
    Export,
}

struct Cursor {
    identity: FileIdentity,
    offset: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FileIdentity {
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
    length: u64,
}

impl FileIdentity {
    fn from_metadata(metadata: &Metadata) -> Self {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            Self {
                device: metadata.dev(),
                inode: metadata.ino(),
                length: metadata.len(),
            }
        }
        #[cfg(not(unix))]
        Self {
            length: metadata.len(),
        }
    }

    fn same_file(self, other: Self) -> bool {
        #[cfg(unix)]
        {
            self.device == other.device && self.inode == other.inode
        }
        #[cfg(not(unix))]
        {
            self.length == other.length
        }
    }
}

fn main() -> Result<()> {
    let args = Args::parse();
    match args.mode {
        Mode::Web => {
            let runtime = tokio::runtime::Runtime::new()?;
            return runtime.block_on(web::run(args.database_url, args.bind, args.retiremx_config));
        }
        Mode::Import => return import_config(&args),
        Mode::Export => return export_config(&args),
        Mode::Collector => {}
    }
    let mut client = connect_with_retry(&args.database_url)?;
    ensure_schema(&mut client)?;
    management::ensure_schema(&mut client)?;
    let mut cursor = None;

    loop {
        match ingest_available(&args.log_path, &mut cursor, &mut client) {
            Ok(inserted) => {
                if inserted > 0 {
                    eprintln!("ingested {inserted} recipient events");
                }
            }
            Err(error) => {
                eprintln!("collector error: {error:#}; reconnecting");
                thread::sleep(Duration::from_secs(args.poll_seconds.max(1)));
                client = connect_with_retry(&args.database_url)?;
                ensure_schema(&mut client)?;
            }
        }
        thread::sleep(Duration::from_secs(args.poll_seconds.max(1)));
    }
}

fn import_config(args: &Args) -> Result<()> {
    if args.apply && !args.yes {
        anyhow::bail!("--apply requires --yes to confirm management configuration replacement");
    }
    if args.dry_run && args.apply {
        anyhow::bail!("--dry-run and --apply cannot be used together");
    }
    let config = management::parse_file(&args.input)?;
    let summary = management::summary(&config);
    println!("{}", serde_json::to_string_pretty(&summary)?);
    if !args.apply {
        eprintln!(
            "dry run: management configuration was not changed; use --apply --yes to replace it"
        );
        return Ok(());
    }
    let mut client = Client::connect(&args.database_url, NoTls)
        .context("connecting to PostgreSQL for management import")?;
    management::ensure_schema(&mut client)?;
    management::replace_config(&mut client, &config, false)?;
    println!("management configuration imported and reinitialized");
    Ok(())
}

fn export_config(args: &Args) -> Result<()> {
    let mut client = Client::connect(&args.database_url, NoTls)
        .context("connecting to PostgreSQL for management export")?;
    management::ensure_schema(&mut client)?;
    let markdown = management::export_markdown(&mut client)?;
    if let Some(output) = &args.output {
        let temporary = output.with_extension("tmp");
        fs::write(&temporary, markdown.as_bytes())
            .with_context(|| format!("writing temporary export {}", temporary.display()))?;
        fs::rename(&temporary, output)
            .with_context(|| format!("installing export {}", output.display()))?;
        println!("exported management configuration to {}", output.display());
    } else {
        print!("{markdown}");
    }
    Ok(())
}

fn connect_with_retry(database_url: &str) -> Result<Client> {
    loop {
        match Client::connect(database_url, NoTls) {
            Ok(client) => return Ok(client),
            Err(error) => {
                eprintln!("waiting for PostgreSQL: {error}");
                thread::sleep(Duration::from_secs(2));
            }
        }
    }
}

pub(crate) fn ensure_schema(client: &mut Client) -> Result<()> {
    client.batch_execute(
        r#"
        CREATE TABLE IF NOT EXISTS recipient_events (
            event_id UUID PRIMARY KEY,
            event_time TIMESTAMPTZ NOT NULL,
            mail_from TEXT NOT NULL,
            recipient TEXT NOT NULL,
            decision TEXT NOT NULL,
            replacement TEXT,
            subject TEXT,
            message_id TEXT,
            helo TEXT,
            remote_ip TEXT,
            session_id BIGINT,
            payload JSONB NOT NULL
        );

        CREATE INDEX IF NOT EXISTS recipient_events_time_idx
            ON recipient_events (event_time DESC);

        CREATE INDEX IF NOT EXISTS recipient_events_recipient_time_idx
            ON recipient_events (recipient, event_time DESC);

        CREATE INDEX IF NOT EXISTS recipient_events_sender_time_idx
            ON recipient_events (mail_from, event_time DESC);

        ALTER TABLE recipient_events ADD COLUMN IF NOT EXISTS subject TEXT;
        ALTER TABLE recipient_events ADD COLUMN IF NOT EXISTS message_id TEXT;
        ALTER TABLE recipient_events ADD COLUMN IF NOT EXISTS helo TEXT;

        CREATE TABLE IF NOT EXISTS message_metadata (
            session_id BIGINT NOT NULL,
            recipient TEXT NOT NULL,
            received_time TIMESTAMPTZ NOT NULL,
            subject TEXT,
            message_id TEXT,
            helo TEXT,
            PRIMARY KEY (session_id, recipient, received_time)
        );

        CREATE INDEX IF NOT EXISTS message_metadata_lookup_idx
            ON message_metadata (session_id, recipient, received_time DESC);
        "#,
    )?;
    Ok(())
}

fn ingest_available(
    path: &PathBuf,
    cursor: &mut Option<Cursor>,
    client: &mut Client,
) -> Result<usize> {
    let metadata = match fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(error) => return Err(error).with_context(|| format!("reading {}", path.display())),
    };
    let identity = FileIdentity::from_metadata(&metadata);
    let offset = match cursor {
        Some(cursor) if cursor.identity.same_file(identity) && identity.length >= cursor.offset => {
            cursor.offset
        }
        _ => 0,
    };

    let mut file = OpenOptions::new().read(true).open(path)?;
    file.seek(SeekFrom::Start(offset))?;
    let mut reader = BufReader::new(file);
    let mut current_offset = offset;
    let mut inserted = 0;

    loop {
        let line_start = current_offset;
        let mut line = String::new();
        let bytes = reader.read_line(&mut line)?;
        if bytes == 0 {
            break;
        }
        if !line.ends_with('\n') {
            break;
        }
        current_offset += bytes as u64;
        if ingest_line(client, line.trim_end_matches(['\r', '\n']))? {
            inserted += 1;
        }
        if current_offset < line_start {
            break;
        }
    }
    *cursor = Some(Cursor {
        identity,
        offset: current_offset,
    });
    Ok(inserted)
}

fn ingest_line(client: &mut Client, line: &str) -> Result<bool> {
    let event: Value = match serde_json::from_str(line) {
        Ok(event) => event,
        Err(error) => {
            eprintln!("ignoring invalid JSON event: {error}");
            return Ok(false);
        }
    };
    match event.get("event").and_then(Value::as_str) {
        Some("message_received") => return update_message_metadata(client, &event),
        Some("recipient_decision") => {}
        _ => return Ok(false),
    }

    let Some(event_id) = event.get("event_id").and_then(Value::as_str) else {
        eprintln!("ignoring recipient event without event_id");
        return Ok(false);
    };
    let event_id = match Uuid::parse_str(event_id) {
        Ok(event_id) => event_id,
        Err(error) => {
            eprintln!("ignoring recipient event with invalid event_id: {error}");
            return Ok(false);
        }
    };
    let Some(timestamp) = event.get("timestamp").and_then(Value::as_u64) else {
        eprintln!("ignoring recipient event without timestamp");
        return Ok(false);
    };
    let timestamp = timestamp as f64;
    let Some(recipient) = event.get("recipient").and_then(Value::as_str) else {
        eprintln!("ignoring recipient event without recipient");
        return Ok(false);
    };
    let Some(decision) = event.get("decision").and_then(Value::as_str) else {
        eprintln!("ignoring recipient event without decision");
        return Ok(false);
    };
    let inserted = client.execute(
        r#"
        INSERT INTO recipient_events
            (event_id, event_time, mail_from, recipient, decision,
             replacement, subject, message_id, helo, remote_ip, session_id, payload)
            VALUES
            ($1, to_timestamp($2::double precision), $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
        ON CONFLICT (event_id) DO NOTHING
        "#,
        &[
            &event_id,
            &timestamp,
            &event
                .get("mail_from")
                .and_then(Value::as_str)
                .unwrap_or("<>"),
            &recipient,
            &decision,
            &event.get("replacement").and_then(Value::as_str),
            &event.get("subject").and_then(Value::as_str),
            &event.get("message_id").and_then(Value::as_str),
            &event.get("helo").and_then(Value::as_str),
            &event.get("remote_ip").and_then(Value::as_str),
            &event.get("session_id").and_then(Value::as_i64),
            &event,
        ],
    )?;
    Ok(inserted == 1)
}

fn update_message_metadata(client: &mut Client, event: &Value) -> Result<bool> {
    let Some(timestamp) = event.get("timestamp").and_then(Value::as_u64) else {
        return Ok(false);
    };
    let Some(session_id) = event.get("session_id").and_then(Value::as_i64) else {
        return Ok(false);
    };
    let Some(recipients) = event.get("rcpt_to").and_then(Value::as_array) else {
        return Ok(false);
    };
    let timestamp = timestamp as f64;
    let subject = event.get("subject").and_then(Value::as_str);
    let message_id = event.get("message_id").and_then(Value::as_str);
    let helo = event.get("helo").and_then(Value::as_str);
    let mut updated = false;
    for recipient in recipients.iter().filter_map(Value::as_str) {
        client.execute(
            r#"
            INSERT INTO message_metadata
                (session_id, recipient, received_time, subject, message_id, helo)
            VALUES ($1, $2, to_timestamp($3::double precision), $4, $5, $6)
            ON CONFLICT (session_id, recipient, received_time) DO UPDATE
            SET subject = EXCLUDED.subject,
                message_id = EXCLUDED.message_id,
                helo = EXCLUDED.helo
            "#,
            &[
                &session_id,
                &recipient,
                &timestamp,
                &subject,
                &message_id,
                &helo,
            ],
        )?;
        updated |= client.execute(
            r#"
            UPDATE recipient_events
            SET subject = $1, message_id = $2, helo = $3
            WHERE session_id = $4
              AND recipient = $5
              AND decision = 'pass-through'
              AND event_time <= to_timestamp($6::double precision)
            "#,
            &[
                &subject,
                &message_id,
                &helo,
                &session_id,
                &recipient,
                &timestamp,
            ],
        )? > 0;
    }
    Ok(updated)
}
