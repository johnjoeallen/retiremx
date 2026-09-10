use crate::management;
use anyhow::{Context, Result};
use axum::{
    extract::{Json as RequestJson, Query, State},
    http::{header, StatusCode},
    response::{Html, IntoResponse, Json},
    routing::{get, post},
    Router,
};
use postgres::NoTls;
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::PathBuf,
    sync::Arc,
};

#[derive(Clone)]
struct AppState {
    database_url: Arc<str>,
    retiremx_config: Arc<PathBuf>,
}

#[derive(Debug, Serialize)]
struct HourRow {
    hour_start: i64,
    label: String,
    count: i64,
}

#[derive(Debug, Serialize)]
struct EventRow {
    event_time: String,
    recipient: String,
    sender: String,
    decision: String,
    replacement: Option<String>,
    subject: Option<String>,
    message_id: Option<String>,
    helo: Option<String>,
    remote_ip: Option<String>,
    session_id: Option<i64>,
}

#[derive(Debug, Deserialize)]
struct EventsQuery {
    hour_start: i64,
    page: Option<i64>,
    per_page: Option<i64>,
    recipient: Option<String>,
}

#[derive(Debug, Deserialize)]
struct HoursQuery {
    recipient: Option<String>,
}

#[derive(Debug, Deserialize)]
struct SendersQuery {
    recipient: Option<String>,
    page: Option<i64>,
    per_page: Option<i64>,
}

#[derive(Debug, Serialize)]
struct EventsResponse {
    hour_start: i64,
    page: i64,
    per_page: i64,
    total: i64,
    events: Vec<EventRow>,
}

#[derive(Debug, Serialize)]
struct SenderRow {
    sender: String,
    count: i64,
}

#[derive(Debug, Serialize)]
struct SendersResponse {
    recipient: String,
    page: i64,
    per_page: i64,
    total: i64,
    senders: Vec<SenderRow>,
}

#[derive(Debug, Serialize)]
struct ManagementRecipient {
    source_address: String,
    members: Vec<String>,
    pass_through: bool,
    message: Option<String>,
}

#[derive(Debug, Serialize)]
struct ManagementSnapshot {
    source_path: Option<String>,
    source_sha256: Option<String>,
    imported_at: Option<String>,
    unknown_action: Option<String>,
    known_action: Option<String>,
    managed_domains: Vec<String>,
    recipients: Vec<ManagementRecipient>,
    blocked_senders: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct ManagementRecipientInput {
    source_address: String,
    members: Vec<String>,
    pass_through: bool,
    message: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ManagementSourceQuery {
    source: String,
}

#[derive(Debug, Deserialize)]
struct BlockedSenderInput {
    pattern: String,
}

#[derive(Debug, Deserialize)]
struct BlockedSenderQuery {
    pattern: String,
}

pub async fn run(database_url: String, bind: String, retiremx_config: PathBuf) -> Result<()> {
    let schema_database_url = database_url.clone();
    tokio::task::spawn_blocking(move || {
        let mut client = postgres::Client::connect(&schema_database_url, NoTls)
            .context("connecting to PostgreSQL")?;
        crate::ensure_schema(&mut client).context("ensuring reporting event schema")?;
        management::ensure_schema(&mut client).context("ensuring management schema")?;
        Ok::<_, anyhow::Error>(())
    })
    .await
    .context("waiting for reporting schema migration")??;
    let listener = tokio::net::TcpListener::bind(&bind)
        .await
        .with_context(|| format!("binding dashboard listener to {bind}"))?;
    let state = AppState {
        database_url: Arc::from(database_url),
        retiremx_config: Arc::new(retiremx_config),
    };
    let app = Router::new()
        .route("/", get(index))
        .route("/manage", get(manage_index))
        .route("/api/recipients", get(api_recipients))
        .route("/api/hours", get(api_hours))
        .route("/api/events", get(api_events))
        .route("/api/senders", get(api_senders))
        .route("/api/management", get(api_management))
        .route("/api/management/export", get(api_export_management))
        .route("/api/management/publish", post(api_publish_management))
        .route(
            "/api/management/recipients",
            post(api_save_management_recipient).delete(api_delete_management_recipient),
        )
        .route(
            "/api/management/blocked-senders",
            post(api_save_blocked_sender).delete(api_delete_blocked_sender),
        )
        .with_state(state);
    eprintln!("dashboard listening on {bind}");
    axum::serve(listener, app)
        .await
        .context("dashboard server")?;
    Ok(())
}

async fn index() -> impl IntoResponse {
    Html(render_dashboard())
}

async fn api_recipients(State(state): State<AppState>) -> impl IntoResponse {
    match load_recipients(state.database_url).await {
        Ok(recipients) => Json(recipients).into_response(),
        Err(error) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({"error": error.to_string()})),
        )
            .into_response(),
    }
}

async fn api_hours(
    State(state): State<AppState>,
    Query(query): Query<HoursQuery>,
) -> impl IntoResponse {
    match load_hours(state.database_url, query.recipient).await {
        Ok(hours) => Json(hours).into_response(),
        Err(error) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({"error": error.to_string()})),
        )
            .into_response(),
    }
}

async fn api_events(
    State(state): State<AppState>,
    Query(query): Query<EventsQuery>,
) -> impl IntoResponse {
    let page = query.page.unwrap_or(1).max(1);
    let per_page = query.per_page.unwrap_or(50).clamp(10, 200);
    match load_events(
        state.database_url,
        query.hour_start,
        page,
        per_page,
        query.recipient,
    )
    .await
    {
        Ok(response) => Json(response).into_response(),
        Err(error) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({"error": error.to_string()})),
        )
            .into_response(),
    }
}

async fn api_senders(
    State(state): State<AppState>,
    Query(query): Query<SendersQuery>,
) -> impl IntoResponse {
    let Some(recipient) = query.recipient.filter(|value| !value.is_empty()) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "recipient is required"})),
        )
            .into_response();
    };
    let page = query.page.unwrap_or(1).max(1);
    let per_page = query.per_page.unwrap_or(50).clamp(10, 200);
    match load_senders(state.database_url, recipient, page, per_page).await {
        Ok(response) => Json(response).into_response(),
        Err(error) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({"error": error.to_string()})),
        )
            .into_response(),
    }
}

async fn manage_index() -> impl IntoResponse {
    Html(render_management())
}

async fn api_management(State(state): State<AppState>) -> impl IntoResponse {
    match load_management(state.database_url).await {
        Ok(snapshot) => Json(snapshot).into_response(),
        Err(error) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({"error": error.to_string()})),
        )
            .into_response(),
    }
}

async fn api_export_management(State(state): State<AppState>) -> impl IntoResponse {
    match export_management(state.database_url).await {
        Ok(markdown) => (
            [
                (header::CONTENT_TYPE, "text/markdown; charset=utf-8"),
                (
                    header::CONTENT_DISPOSITION,
                    "attachment; filename=retiremx.md",
                ),
            ],
            markdown,
        )
            .into_response(),
        Err(error) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({"error": error.to_string()})),
        )
            .into_response(),
    }
}

async fn api_publish_management(State(state): State<AppState>) -> impl IntoResponse {
    match publish_management(state.database_url, state.retiremx_config).await {
        Ok(path) => Json(serde_json::json!({
            "ok": true,
            "path": path.display().to_string(),
            "message": "Configuration published; RetireMX will reload it automatically"
        }))
        .into_response(),
        Err(error) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": error.to_string()})),
        )
            .into_response(),
    }
}

async fn api_save_management_recipient(
    State(state): State<AppState>,
    RequestJson(input): RequestJson<ManagementRecipientInput>,
) -> impl IntoResponse {
    match save_management_recipient(state.database_url, input).await {
        Ok(recipient) => Json(recipient).into_response(),
        Err(error) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": error.to_string()})),
        )
            .into_response(),
    }
}

async fn api_delete_management_recipient(
    State(state): State<AppState>,
    Query(query): Query<ManagementSourceQuery>,
) -> impl IntoResponse {
    match delete_management_recipient(state.database_url, query.source).await {
        Ok(()) => Json(serde_json::json!({"ok": true})).into_response(),
        Err(error) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": error.to_string()})),
        )
            .into_response(),
    }
}

async fn api_save_blocked_sender(
    State(state): State<AppState>,
    RequestJson(input): RequestJson<BlockedSenderInput>,
) -> impl IntoResponse {
    match save_blocked_sender(state.database_url, input.pattern).await {
        Ok(pattern) => Json(serde_json::json!({"pattern": pattern})).into_response(),
        Err(error) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": error.to_string()})),
        )
            .into_response(),
    }
}

async fn api_delete_blocked_sender(
    State(state): State<AppState>,
    Query(query): Query<BlockedSenderQuery>,
) -> impl IntoResponse {
    match delete_blocked_sender(state.database_url, query.pattern).await {
        Ok(()) => Json(serde_json::json!({"ok": true})).into_response(),
        Err(error) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": error.to_string()})),
        )
            .into_response(),
    }
}

async fn load_recipients(database_url: Arc<str>) -> Result<Vec<String>> {
    tokio::task::spawn_blocking(move || {
        let mut client =
            postgres::Client::connect(&database_url, NoTls).context("connecting to PostgreSQL")?;
        let rows = client.query(
            "SELECT DISTINCT recipient FROM recipient_events ORDER BY recipient",
            &[],
        )?;
        Ok(rows.iter().map(|row| row.get("recipient")).collect())
    })
    .await
    .context("waiting for recipient query")?
}

async fn load_hours(database_url: Arc<str>, recipient: Option<String>) -> Result<Vec<HourRow>> {
    tokio::task::spawn_blocking(move || {
        let mut client =
            postgres::Client::connect(&database_url, NoTls).context("connecting to PostgreSQL")?;
        let recipient_filter = recipient.as_deref();
        let rows = client.query(
            r#"
            SELECT
                extract(epoch FROM date_trunc('hour', event_time AT TIME ZONE 'UTC'))::bigint AS hour_start,
                to_char(date_trunc('hour', event_time AT TIME ZONE 'UTC'), 'YYYY-MM-DD HH24:00') AS label,
                count(*) AS count
            FROM recipient_events
            WHERE ($1::text IS NULL OR recipient = $1::text)
            GROUP BY hour_start, label
            ORDER BY hour_start DESC
            LIMIT 168
            "#,
            &[&recipient_filter],
        )?;
        Ok(rows
            .iter()
            .map(|row| HourRow {
                hour_start: row.get("hour_start"),
                label: row.get("label"),
                count: row.get("count"),
            })
            .collect())
    })
    .await
    .context("waiting for hour query")?
}

async fn load_events(
    database_url: Arc<str>,
    hour_start: i64,
    page: i64,
    per_page: i64,
    recipient: Option<String>,
) -> Result<EventsResponse> {
    tokio::task::spawn_blocking(move || {
        let mut client =
            postgres::Client::connect(&database_url, NoTls).context("connecting to PostgreSQL")?;
        let hour_start_seconds = hour_start as f64;
        let recipient_filter = recipient.as_deref();
        let total: i64 = client
            .query_one(
                r#"
                SELECT count(*)
                FROM recipient_events
                WHERE event_time >= to_timestamp($1::double precision)
                  AND event_time < to_timestamp(($1 + 3600)::double precision)
                  AND ($2::text IS NULL OR recipient = $2::text)
                "#,
                &[&hour_start_seconds, &recipient_filter],
            )?
            .get(0);
        let offset = (page - 1) * per_page;
        let rows = client.query(
            r#"
            SELECT
                to_char(event_time AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS event_time,
                recipient,
                mail_from AS sender,
                decision,
                e.replacement,
                COALESCE(e.subject, metadata.subject) AS subject,
                COALESCE(e.message_id, metadata.message_id) AS message_id,
                COALESCE(e.helo, metadata.helo) AS helo,
                e.remote_ip,
                e.session_id
            FROM recipient_events e
            LEFT JOIN LATERAL (
                SELECT subject, message_id, helo
                FROM message_metadata m
                WHERE m.session_id = e.session_id
                  AND m.recipient = e.recipient
                  AND m.received_time >= e.event_time
                ORDER BY m.received_time
                LIMIT 1
            ) metadata ON true
            WHERE event_time >= to_timestamp($1::double precision)
              AND event_time < to_timestamp(($1 + 3600)::double precision)
              AND ($2::text IS NULL OR e.recipient = $2::text)
            ORDER BY e.event_time DESC, e.event_id DESC
            LIMIT $3::bigint OFFSET $4::bigint
            "#,
            &[&hour_start_seconds, &recipient_filter, &per_page, &offset],
        )?;
        let events = rows
            .iter()
            .map(|row| EventRow {
                event_time: row.get("event_time"),
                recipient: row.get("recipient"),
                sender: row.get("sender"),
                decision: row.get("decision"),
                replacement: row.get("replacement"),
                subject: row.get("subject"),
                message_id: row.get("message_id"),
                helo: row.get("helo"),
                remote_ip: row.get("remote_ip"),
                session_id: row.get("session_id"),
            })
            .collect();
        Ok(EventsResponse {
            hour_start,
            page,
            per_page,
            total,
            events,
        })
    })
    .await
    .context("waiting for event query")?
}

async fn load_senders(
    database_url: Arc<str>,
    recipient: String,
    page: i64,
    per_page: i64,
) -> Result<SendersResponse> {
    tokio::task::spawn_blocking(move || {
        let mut client =
            postgres::Client::connect(&database_url, NoTls).context("connecting to PostgreSQL")?;
        let total: i64 = client
            .query_one(
                "SELECT count(DISTINCT mail_from) FROM recipient_events WHERE recipient = $1",
                &[&recipient],
            )?
            .get(0);
        let offset = (page - 1) * per_page;
        let rows = client.query(
            r#"
            SELECT mail_from AS sender, count(*) AS count
            FROM recipient_events
            WHERE recipient = $1
            GROUP BY mail_from
            ORDER BY count DESC, sender
            LIMIT $2::bigint OFFSET $3::bigint
            "#,
            &[&recipient, &per_page, &offset],
        )?;
        let senders = rows
            .iter()
            .map(|row| SenderRow {
                sender: row.get("sender"),
                count: row.get("count"),
            })
            .collect();
        Ok(SendersResponse {
            recipient,
            page,
            per_page,
            total,
            senders,
        })
    })
    .await
    .context("waiting for sender query")?
}

async fn load_management(database_url: Arc<str>) -> Result<ManagementSnapshot> {
    tokio::task::spawn_blocking(move || {
        let mut client =
            postgres::Client::connect(&database_url, NoTls).context("connecting to PostgreSQL")?;
        management::ensure_schema(&mut client)?;
        let config = client.query_opt(
            r#"
            SELECT source_path, source_sha256,
                   to_char(imported_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'),
                   unknown_action, known_action
            FROM management_config
            WHERE singleton = true
            "#,
            &[],
        )?;
        let (source_path, source_sha256, imported_at, unknown_action, known_action) =
            config.map_or((None, None, None, None, None), |row| {
                (
                    Some(row.get(0)),
                    Some(row.get(1)),
                    Some(row.get(2)),
                    Some(row.get(3)),
                    Some(row.get(4)),
                )
            });
        let managed_domains = client
            .query("SELECT domain FROM management_domains ORDER BY domain", &[])?
            .iter()
            .map(|row| row.get("domain"))
            .collect();
        let blocked_senders = client
            .query(
                "SELECT pattern FROM management_blocked_senders ORDER BY pattern",
                &[],
            )?
            .iter()
            .map(|row| row.get("pattern"))
            .collect();
        let mut recipients = client
            .query(
                "SELECT source_address, pass_through, message FROM management_recipient_groups ORDER BY source_address",
                &[],
            )?
            .iter()
            .map(|row| ManagementRecipient {
                source_address: row.get("source_address"),
                members: Vec::new(),
                pass_through: row.get("pass_through"),
                message: row.get("message"),
            })
            .collect::<Vec<_>>();
        let members = client.query(
            "SELECT source_address, member_address FROM management_recipient_members ORDER BY source_address, position",
            &[],
        )?;
        for member in members {
            if let Some(recipient) = recipients
                .iter_mut()
                .find(|recipient| recipient.source_address == member.get::<_, String>("source_address"))
            {
                recipient.members.push(member.get("member_address"));
            }
        }
        Ok(ManagementSnapshot {
            source_path,
            source_sha256,
            imported_at,
            unknown_action,
            known_action,
            managed_domains,
            recipients,
            blocked_senders,
        })
    })
    .await
    .context("waiting for management query")?
}

async fn export_management(database_url: Arc<str>) -> Result<String> {
    tokio::task::spawn_blocking(move || {
        let mut client =
            postgres::Client::connect(&database_url, NoTls).context("connecting to PostgreSQL")?;
        management::ensure_schema(&mut client)?;
        management::export_markdown(&mut client)
    })
    .await
    .context("waiting for management export")?
}

async fn publish_management(database_url: Arc<str>, path: Arc<PathBuf>) -> Result<PathBuf> {
    tokio::task::spawn_blocking(move || {
        let mut client =
            postgres::Client::connect(&database_url, NoTls).context("connecting to PostgreSQL")?;
        management::ensure_schema(&mut client)?;
        let markdown = management::export_markdown(&mut client)?;
        atomic_write(&path, markdown.as_bytes())?;
        Ok(path.as_ref().clone())
    })
    .await
    .context("waiting for management publish")?
}

fn atomic_write(path: &PathBuf, contents: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .context("configuration path has no parent directory")?;
    let file_name = path
        .file_name()
        .context("configuration path has no file name")?
        .to_string_lossy();
    let temporary = parent.join(format!(".{file_name}.tmp-{}", std::process::id()));
    let result = (|| -> Result<()> {
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temporary)
            .with_context(|| format!("creating temporary configuration {}", temporary.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&temporary, fs::Permissions::from_mode(0o660))?;
        }
        file.write_all(contents)?;
        file.sync_all()?;
        fs::rename(&temporary, path)
            .with_context(|| format!("installing configuration {}", path.display()))?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

async fn save_management_recipient(
    database_url: Arc<str>,
    input: ManagementRecipientInput,
) -> Result<ManagementRecipient> {
    tokio::task::spawn_blocking(move || {
        let (source_address, members) =
            management::normalize_recipient_group(&input.source_address, &input.members)?;
        let message = input.message.filter(|message| !message.trim().is_empty());
        let mut client =
            postgres::Client::connect(&database_url, NoTls).context("connecting to PostgreSQL")?;
        management::ensure_schema(&mut client)?;
        let mut transaction = client.transaction()?;
        transaction.execute(
            "DELETE FROM management_recipient_groups WHERE source_address = $1",
            &[&source_address],
        )?;
        transaction.execute(
            "INSERT INTO management_recipient_groups (source_address, pass_through, message) VALUES ($1, $2, $3)",
            &[&source_address, &input.pass_through, &message],
        )?;
        for (position, member) in members.iter().enumerate() {
            let position = position as i32;
            transaction.execute(
                "INSERT INTO management_recipient_members (source_address, position, member_address) VALUES ($1, $2, $3)",
                &[&source_address, &position, member],
            )?;
        }
        transaction.commit()?;
        Ok(ManagementRecipient {
            source_address,
            members,
            pass_through: input.pass_through,
            message,
        })
    })
    .await
    .context("waiting for management save")?
}

async fn delete_management_recipient(database_url: Arc<str>, source: String) -> Result<()> {
    tokio::task::spawn_blocking(move || {
        let source = source.trim().to_ascii_lowercase();
        let mut client =
            postgres::Client::connect(&database_url, NoTls).context("connecting to PostgreSQL")?;
        management::ensure_schema(&mut client)?;
        client.execute(
            "DELETE FROM management_recipient_groups WHERE source_address = $1",
            &[&source],
        )?;
        Ok(())
    })
    .await
    .context("waiting for management delete")?
}

async fn save_blocked_sender(database_url: Arc<str>, pattern: String) -> Result<String> {
    tokio::task::spawn_blocking(move || {
        let pattern = management::normalize_blocked_sender(&pattern)?;
        let mut client =
            postgres::Client::connect(&database_url, NoTls).context("connecting to PostgreSQL")?;
        management::ensure_schema(&mut client)?;
        client.execute(
            "INSERT INTO management_blocked_senders (pattern) VALUES ($1) ON CONFLICT (pattern) DO NOTHING",
            &[&pattern],
        )?;
        Ok(pattern)
    })
    .await
    .context("waiting for blocked sender save")?
}

async fn delete_blocked_sender(database_url: Arc<str>, pattern: String) -> Result<()> {
    tokio::task::spawn_blocking(move || {
        let pattern = management::normalize_blocked_sender(&pattern)?;
        let mut client =
            postgres::Client::connect(&database_url, NoTls).context("connecting to PostgreSQL")?;
        management::ensure_schema(&mut client)?;
        client.execute(
            "DELETE FROM management_blocked_senders WHERE pattern = $1",
            &[&pattern],
        )?;
        Ok(())
    })
    .await
    .context("waiting for blocked sender delete")?
}

fn render_dashboard() -> String {
    r#"<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>retiremx · incoming mail</title>
  <style>
    :root { color-scheme: dark; font: 15px system-ui, sans-serif; }
    body { margin: 0; min-height: 100vh; color: #e9eef5; background: #0d1421; }
    header { padding: 2rem clamp(1rem, 4vw, 4rem); background: linear-gradient(120deg, #172b4d, #163d43); }
    h1 { margin: 0; font-size: clamp(1.6rem, 4vw, 2.5rem); letter-spacing: -.03em; }
    header p { margin: .45rem 0 0; color: #b9c9d9; }
    main { width: min(1500px, calc(100% - 2rem)); margin: 1.25rem auto 3rem; }
    .toolbar { display: flex; flex-wrap: wrap; gap: .75rem; align-items: center; padding: 1rem; border: 1px solid #263852; border-radius: 14px; background: #131e2d; }
    label { color: #b9c9d9; font-weight: 600; }
    select, button { border: 1px solid #3c5677; border-radius: 8px; padding: .6rem .8rem; color: #e9eef5; background: #1a2a3f; font: inherit; }
    button { cursor: pointer; font-weight: 650; } button:hover { background: #284363; } button:disabled { cursor: not-allowed; opacity: .45; }
    .summary { margin-left: auto; color: #91abc5; }
    .action-notice { color: #f0c674; }
    .hour-picker { display: inline-flex; align-items: center; gap: .35rem; }
    .hour-picker button { width: auto; min-width: 2.3rem; padding: .55rem .7rem; }
    #hour-display { min-width: 18rem; }
    .blocked-action { color: #fff; background: #9b303b; border-color: #d15b67; }
    .blocked-action:hover { background: #c13e4b; }
    .sender-cell { display: flex; align-items: center; gap: .35rem; }
    .subject-cell { position: relative; max-width: 32rem; }
    .subject-text { cursor: help; border-bottom: 1px dotted #8eabc7; }
    .subject-text:focus { outline: 2px solid #72a9dc; outline-offset: 3px; }
    .subject-popup { display: none; position: fixed; z-index: 20; width: min(30rem, calc(100vw - 2rem)); max-height: 20rem; overflow: auto; padding: .45rem; border: 1px solid #4a6e93; border-radius: 10px; background: #101b2a; box-shadow: 0 12px 30px #0009; }
    .subject-popup.visible { display: block; }
    .subject-popup table { width: 100%; border-collapse: collapse; }
    .subject-popup th, .subject-popup td { padding: .45rem .55rem; white-space: normal; vertical-align: top; }
    .subject-popup th { position: static; width: 7rem; color: #9fc0df; background: #182b42; font-size: .75rem; }
    .subject-popup td { color: #edf4fb; overflow-wrap: anywhere; }
    .block-icon { width: 2rem; height: 2rem; padding: .35rem; line-height: 1; }
    .block-icon svg { width: 1.05rem; height: 1.05rem; display: block; }
    .block-sender { color: #fff; background: #287a57; border-color: #4caf82; }
    .block-sender:hover { background: #36956b; }
    .block-domain { color: #fff; background: #2d5d9a; border-color: #5d91d1; }
    .block-domain:hover { background: #3974bb; }
    .tabs { display: flex; gap: .5rem; margin-top: 1rem; }
    .tab.active { color: #fff; background: #2d5b7d; }
    .manage-link { display: inline-block; margin-top: .8rem; padding: .55rem .8rem; border: 1px solid #4f7ea0; border-radius: 8px; color: #d8efff; background: #21415b; text-decoration: none; font-weight: 650; }
    .manage-link:hover { background: #2d5b7d; }
    .table-wrap { overflow-x: auto; margin-top: 1rem; border: 1px solid #263852; border-radius: 14px; background: #131e2d; }
    table { width: 100%; border-collapse: collapse; }
    th, td { padding: .75rem .9rem; text-align: left; border-bottom: 1px solid #22334b; white-space: nowrap; }
    th { position: sticky; top: 0; color: #b9c9d9; background: #18283d; font-size: .83rem; text-transform: uppercase; letter-spacing: .06em; }
    tbody tr:hover { background: #192b43; }
    .decision-pass-through { color: #79dfaa; } .decision-replacement { color: #f0c674; } .decision-rejected, .decision-unknown { color: #ff8f8f; }
    .empty, .error { padding: 2rem; text-align: center; color: #9eb0c5; }
    .error { color: #ff9e9e; }
    .pager { display: flex; justify-content: center; align-items: center; gap: 1rem; margin-top: 1rem; color: #b9c9d9; }
    @media (max-width: 700px) { .summary { width: 100%; margin-left: 0; } th, td { padding: .6rem; } }
  </style>
</head>
<body>
  <header><h1>retiremx</h1><p>Incoming recipient decisions, grouped by UTC hour and displayed in local time.</p><a class="manage-link" href="/manage">Manage configuration →</a></header>
  <main>
    <section class="toolbar">
      <label for="recipient">Recipient</label>
      <select id="recipient" aria-label="Recipient"><option>Loading…</option></select>
      <span id="hour-label">Received hour</span>
      <span id="hour-picker" class="hour-picker">
        <button id="hour-previous" type="button" aria-label="Previous received hour">←</button>
        <button id="hour-display" type="button" aria-live="polite">Loading…</button>
        <button id="hour-next" type="button" aria-label="Next received hour">→</button>
      </span>
      <button id="refresh" type="button">Refresh</button>
      <button id="save-config" type="button" disabled>Save</button>
      <span id="summary" class="summary">Loading…</span>
      <span id="action-notice" class="action-notice"></span>
    </section>
    <nav class="tabs" aria-label="Dashboard views">
      <button id="events-tab" class="tab active" type="button">Events</button>
      <button id="senders-tab" class="tab" type="button">Senders for recipient</button>
    </nav>
    <div id="table" class="table-wrap"></div>
    <nav class="pager" aria-label="Event pages">
      <button id="previous" type="button">← Previous</button>
      <span id="page">Page 1</span>
      <button id="next" type="button">Next →</button>
    </nav>
  </main>
  <script>
    const recipientSelect = document.querySelector('#recipient');
    const hourPicker = document.querySelector('#hour-picker');
    const hourPrevious = document.querySelector('#hour-previous');
    const hourDisplay = document.querySelector('#hour-display');
    const hourNext = document.querySelector('#hour-next');
    const hourLabel = document.querySelector('#hour-label');
    const eventsTab = document.querySelector('#events-tab');
    const sendersTab = document.querySelector('#senders-tab');
    const table = document.querySelector('#table');
    const summary = document.querySelector('#summary');
    const pageLabel = document.querySelector('#page');
    const previous = document.querySelector('#previous');
    const next = document.querySelector('#next');
    const actionNotice = document.querySelector('#action-notice');
    const saveConfigButton = document.querySelector('#save-config');
    const perPage = 50;
    let page = 1;
    let selectedHour = null;
    let hourOptions = [];
    let hourIndex = -1;
    let selectedRecipient = '';
    let activeTab = 'events';
    let blockedPatterns = [];
    let configDirty = false;

    function markConfigDirty() {
      configDirty = true;
      saveConfigButton.disabled = false;
      actionNotice.textContent = 'Configuration changed — save when ready';
    }

    async function saveConfig() {
      saveConfigButton.disabled = true;
      const response = await fetch('/api/management/publish', {method: 'POST'});
      const data = await response.json().catch(() => ({}));
      if (!response.ok) {
        saveConfigButton.disabled = false;
        actionNotice.textContent = data.error || 'Unable to save configuration';
        return;
      }
      configDirty = false;
      actionNotice.textContent = data.message || 'Configuration saved';
    }

    const localTime = value => new Intl.DateTimeFormat(undefined, {
      dateStyle: 'medium', timeStyle: 'medium'
    }).format(new Date(value));

    function updateBlockButtons() {
      for (const button of document.querySelectorAll('.block-icon')) {
        const blocked = blockedPatterns.includes(button.dataset.pattern);
        const action = blocked ? 'Unblock' : 'Block';
        button.title = `${action} ${button.dataset.kind}`;
        button.setAttribute('aria-label', `${action} ${button.dataset.kind}`);
        button.classList.toggle('blocked-action', blocked);
        button.classList.toggle('block-sender', !blocked && button.dataset.kind === 'sender');
        button.classList.toggle('block-domain', !blocked && button.dataset.kind === 'domain');
      }
    }

    async function toggleBlocked(pattern, kind, button) {
      button.disabled = true;
      const blocked = blockedPatterns.includes(pattern);
      const response = await fetch(blocked
        ? `/api/management/blocked-senders?pattern=${encodeURIComponent(pattern)}`
        : '/api/management/blocked-senders', {
          method: blocked ? 'DELETE' : 'POST',
          headers: {'content-type': 'application/json'},
          body: blocked ? undefined : JSON.stringify({pattern})
        });
      if (!response.ok) {
        const error = await response.json().catch(() => ({}));
        actionNotice.textContent = error.error || 'Unable to block sender';
        button.disabled = false;
        return;
      }
      blockedPatterns = blocked
        ? blockedPatterns.filter(value => value !== pattern)
        : [...blockedPatterns, pattern];
      actionNotice.textContent = `${blocked ? 'Removed' : 'Added'} ${kind} rule: ${pattern}`;
      markConfigDirty();
      updateBlockButtons();
      for (const item of document.querySelectorAll('.block-icon')) item.disabled = false;
    }

    async function loadBlockedSenders() {
      const response = await fetch('/api/management', {cache: 'no-store'});
      if (!response.ok) throw new Error('Unable to load blocked sender rules');
      blockedPatterns = (await response.json()).blocked_senders;
    }

    async function loadHours() {
      const filter = selectedRecipient ? `?recipient=${encodeURIComponent(selectedRecipient)}` : '';
      const response = await fetch(`/api/hours${filter}`, {cache: 'no-store'});
      if (!response.ok) throw new Error('Unable to load hour list');
      const hours = await response.json();
      const old = selectedHour;
      hourOptions = hours;
      hourIndex = hours.findIndex(hour => hour.hour_start === old);
      if (hourIndex < 0) hourIndex = hours.length ? 0 : -1;
      selectedHour = hourIndex >= 0 ? hours[hourIndex].hour_start : null;
      renderHourPicker();
      return hours;
    }

    function renderHourPicker() {
      if (hourIndex < 0) {
        hourDisplay.textContent = 'No received hours';
        hourPrevious.disabled = true; hourNext.disabled = true;
        return;
      }
      const hour = hourOptions[hourIndex];
      hourDisplay.textContent = `${localTime(hour.hour_start * 1000)} · ${hour.count} events`;
      hourPrevious.disabled = hourIndex >= hourOptions.length - 1;
      hourNext.disabled = hourIndex <= 0;
    }

    function moveHour(delta) {
      const nextIndex = hourIndex + delta;
      if (nextIndex < 0 || nextIndex >= hourOptions.length) return;
      hourIndex = nextIndex;
      selectedHour = hourOptions[hourIndex].hour_start;
      page = 1;
      renderHourPicker();
      loadEvents().catch(() => refresh());
    }

    async function loadRecipients() {
      const response = await fetch('/api/recipients', {cache: 'no-store'});
      if (!response.ok) throw new Error('Unable to load recipient list');
      const recipients = await response.json();
      const old = selectedRecipient;
      recipientSelect.replaceChildren();
      const all = document.createElement('option');
      all.value = ''; all.textContent = 'All recipients'; recipientSelect.append(all);
      for (const recipient of recipients) {
        const option = document.createElement('option');
        option.value = recipient; option.textContent = recipient; recipientSelect.append(option);
      }
      selectedRecipient = recipients.includes(old) ? old : '';
      recipientSelect.value = selectedRecipient;
    }

    function decodeMimeSubject(value) {
      return value.replace(/=\?([^?]+)\?([bqBQ])\?([^?]*)\?=/g, (whole, charset, encoding, data) => {
        try {
          let bytes;
          if (encoding.toLowerCase() === 'b') {
            const binary = atob(data);
            bytes = Uint8Array.from(binary, character => character.charCodeAt(0));
          } else {
            const decoded = data.replace(/_/g, ' ').replace(/=([0-9a-f]{2})/gi, (_, hex) => String.fromCharCode(parseInt(hex, 16)));
            bytes = Uint8Array.from(decoded, character => character.charCodeAt(0));
          }
          return new TextDecoder(charset || 'utf-8').decode(bytes);
        } catch (_) {
          return whole;
        }
      });
    }

    function renderEvents(data) {
      table.replaceChildren();
      if (!data.events.length) {
        table.textContent = 'No events in this hour.';
        table.className = 'table-wrap empty';
      } else {
        table.className = 'table-wrap';
        const t = document.createElement('table');
        t.innerHTML = '<thead><tr><th>Time</th><th>From</th><th>To</th><th>Subject</th><th>Result</th></tr></thead>';
        const body = document.createElement('tbody');
        for (const event of data.events) {
          const row = document.createElement('tr');
          for (const value of [localTime(event.event_time), '', event.recipient, '', event.decision]) {
            const cell = document.createElement('td'); cell.textContent = value; row.append(cell);
          }
          row.children[4].className = `decision-${event.decision.replaceAll('_', '-')}`;
          if (event.sender && event.sender !== '<>' && event.sender.includes('@')) {
            const senderCell = row.children[1];
            senderCell.textContent = '';
            senderCell.className = 'sender-cell';
            const senderButton = document.createElement('button');
            senderButton.className = 'block-icon block-sender';
            senderButton.dataset.pattern = event.sender;
            senderButton.dataset.kind = 'sender';
            senderButton.innerHTML = '<svg viewBox="0 0 24 24" aria-hidden="true"><path fill="currentColor" d="M12 12a4 4 0 1 0 0-8 4 4 0 0 0 0 8Zm0 2c-4.42 0-8 2.24-8 5v1h16v-1c0-2.76-3.58-5-8-5Z"/></svg>';
            senderButton.onclick = () => toggleBlocked(event.sender, 'sender', senderButton);
            const domainButton = document.createElement('button');
            const domainPattern = `@${event.sender.split('@').pop()}`;
            domainButton.className = 'block-icon block-domain';
            domainButton.dataset.pattern = domainPattern;
            domainButton.dataset.kind = 'domain';
            domainButton.innerHTML = '<svg viewBox="0 0 24 24" aria-hidden="true"><path fill="currentColor" d="M12 2a10 10 0 1 0 0 20 10 10 0 0 0 0-20Zm6.92 9h-3.06a15.7 15.7 0 0 0-1.02-5.1A8.03 8.03 0 0 1 18.92 11ZM12 4c.83 1.2 1.55 3.73 1.78 7h-3.56C10.45 7.73 11.17 5.2 12 4ZM9.16 5.9A15.7 15.7 0 0 0 8.14 11H5.08a8.03 8.03 0 0 1 4.08-5.1ZM5.08 13h3.06a15.7 15.7 0 0 0 1.02 5.1A8.03 8.03 0 0 1 5.08 13Zm6.92 7c-.83-1.2-1.55-3.73-1.78-7h3.56c-.23 3.27-.95 5.8-1.78 7Zm2.84-1.9a15.7 15.7 0 0 0 1.02-5.1h3.06a8.03 8.03 0 0 1-4.08 5.1Z"/></svg>';
            domainButton.onclick = () => toggleBlocked(domainPattern, 'domain', domainButton);
            const senderText = document.createElement('span'); senderText.textContent = event.sender;
            senderCell.append(senderButton, domainButton, senderText);
          } else {
            row.children[1].textContent = event.sender || '<>';
          }
          const subjectCell = row.children[3];
          subjectCell.className = 'subject-cell';
          const decodedSubject = decodeMimeSubject(event.subject || '');
          const subjectText = document.createElement('span');
          subjectText.className = 'subject-text';
          subjectText.tabIndex = 0;
          subjectText.textContent = decodedSubject || '—';
          const popup = document.createElement('div');
          popup.className = 'subject-popup';
          const popupTable = document.createElement('table');
          const popupBody = document.createElement('tbody');
          const metadata = [
            ['Subject', decodedSubject || '—'],
            ['Message-ID', event.message_id],
            ['HELO', event.helo],
            ['Remote IP', event.remote_ip],
            ['Session', event.session_id],
            ['Replacement', event.replacement],
          ];
          for (const [label, value] of metadata) {
            if (value === null || value === undefined || value === '') continue;
            const metadataRow = document.createElement('tr');
            const labelCell = document.createElement('th'); labelCell.textContent = label;
            const valueCell = document.createElement('td'); valueCell.textContent = String(value);
            metadataRow.append(labelCell, valueCell); popupBody.append(metadataRow);
          }
          popupTable.append(popupBody); popup.append(popupTable);
          function showSubjectPopup() {
            const rect = subjectText.getBoundingClientRect();
            popup.style.left = `${Math.max(8, Math.min(rect.left, window.innerWidth - 380))}px`;
            popup.style.top = `${rect.bottom + 8 < window.innerHeight - 180 ? rect.bottom + 8 : Math.max(8, rect.top - 180)}px`;
            popup.classList.add('visible');
          }
          subjectText.addEventListener('mouseenter', showSubjectPopup);
          subjectText.addEventListener('focus', showSubjectPopup);
          subjectText.addEventListener('mouseleave', () => popup.classList.remove('visible'));
          subjectText.addEventListener('blur', () => popup.classList.remove('visible'));
          subjectCell.append(subjectText, popup);
          body.append(row);
        }
        t.append(body); table.append(t);
        updateBlockButtons();
      }
      const pages = Math.max(1, Math.ceil(data.total / data.per_page));
      pageLabel.textContent = `Page ${data.page} of ${pages} · ${data.total} events`;
      previous.disabled = data.page <= 1;
      next.disabled = data.page >= pages;
      const filterLabel = selectedRecipient ? ` for ${selectedRecipient}` : '';
      summary.textContent = selectedHour === null ? 'No events' : `${data.total} events in selected hour${filterLabel}`;
    }

    async function loadEvents() {
      if (selectedHour === null) { table.textContent = 'No recorded hours.'; summary.textContent = 'No events'; return; }
      const filter = selectedRecipient ? `&recipient=${encodeURIComponent(selectedRecipient)}` : '';
      const response = await fetch(`/api/events?hour_start=${selectedHour}&page=${page}&per_page=${perPage}${filter}`, {cache: 'no-store'});
      if (!response.ok) throw new Error('Unable to load events');
      renderEvents(await response.json());
    }

    function renderSenders(data) {
      table.replaceChildren();
      if (!data.senders.length) {
        table.textContent = 'No senders recorded for this recipient.';
        table.className = 'table-wrap empty';
      } else {
        table.className = 'table-wrap';
        const t = document.createElement('table');
        t.innerHTML = '<thead><tr><th>Sender</th><th>Messages</th></tr></thead>';
        const body = document.createElement('tbody');
        for (const sender of data.senders) {
          const row = document.createElement('tr');
          for (const value of [sender.sender, String(sender.count)]) {
            const cell = document.createElement('td'); cell.textContent = value; row.append(cell);
          }
          row.children[1].style.textAlign = 'right';
          body.append(row);
        }
        t.append(body); table.append(t);
      }
      const pages = Math.max(1, Math.ceil(data.total / data.per_page));
      pageLabel.textContent = `Page ${data.page} of ${pages} · ${data.total} senders`;
      previous.disabled = data.page <= 1;
      next.disabled = data.page >= pages;
      summary.textContent = `${data.total} senders for ${data.recipient}`;
    }

    async function loadSenders() {
      if (!selectedRecipient) {
        table.className = 'table-wrap empty';
        table.textContent = 'Select a recipient to view its senders.';
        summary.textContent = 'Select a recipient';
        pageLabel.textContent = 'Page 1';
        previous.disabled = true; next.disabled = true;
        return;
      }
      const response = await fetch(`/api/senders?recipient=${encodeURIComponent(selectedRecipient)}&page=${page}&per_page=${perPage}`, {cache: 'no-store'});
      if (!response.ok) throw new Error('Unable to load sender list');
      renderSenders(await response.json());
    }

    function setTab(tab) {
      activeTab = tab;
      const events = tab === 'events';
      eventsTab.classList.toggle('active', events);
      sendersTab.classList.toggle('active', !events);
      hourLabel.hidden = !events;
      hourPicker.hidden = !events;
    }

    async function refresh() {
      try {
        table.textContent = 'Loading…';
        await loadBlockedSenders();
        await loadRecipients();
        if (activeTab === 'events') { await loadHours(); await loadEvents(); }
        else { await loadSenders(); }
      }
      catch (error) { table.className = 'table-wrap error'; table.textContent = error.message; summary.textContent = 'Dashboard unavailable'; }
    }
    recipientSelect.addEventListener('change', async () => {
      selectedRecipient = recipientSelect.value;
      page = 1;
      try {
        if (activeTab === 'events') { await loadHours(); await loadEvents(); }
        else { await loadSenders(); }
      }
      catch (error) { table.className = 'table-wrap error'; table.textContent = error.message; }
    });
    hourPrevious.addEventListener('click', () => moveHour(1));
    hourNext.addEventListener('click', () => moveHour(-1));
    eventsTab.addEventListener('click', () => { page = 1; setTab('events'); refresh(); });
    sendersTab.addEventListener('click', () => { page = 1; setTab('senders'); refresh(); });
    previous.addEventListener('click', () => { if (page > 1) { page--; activeTab === 'events' ? loadEvents() : loadSenders(); } });
    next.addEventListener('click', () => { page++; activeTab === 'events' ? loadEvents() : loadSenders(); });
    document.querySelector('#refresh').addEventListener('click', refresh);
    saveConfigButton.addEventListener('click', saveConfig);
    refresh();
  </script>
</body>
</html>"#
    .to_owned()
}

fn render_management() -> String {
    r#"<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>retiremx · management</title>
  <style>
    :root { color-scheme: dark; font: 15px system-ui, sans-serif; }
    body { margin: 0; min-height: 100vh; color: #e9eef5; background: #0d1421; }
    header { padding: 2rem clamp(1rem, 4vw, 4rem); background: linear-gradient(120deg, #352050, #163d43); }
    h1 { margin: 0; font-size: clamp(1.6rem, 4vw, 2.5rem); letter-spacing: -.03em; }
    header p { margin: .45rem 0 0; color: #c8bad9; } a { color: #9edcff; }
    main { width: min(1500px, calc(100% - 2rem)); margin: 1.25rem auto 3rem; }
    .grid { display: grid; grid-template-columns: minmax(280px, 380px) 1fr; gap: 1rem; align-items: start; }
    .card { padding: 1rem; border: 1px solid #3b3152; border-radius: 14px; background: #131e2d; }
    .card h2 { margin: 0 0 1rem; font-size: 1.05rem; }
    label { display: block; margin: .85rem 0 .35rem; color: #c6b9d8; font-weight: 650; }
    input, textarea, button { box-sizing: border-box; width: 100%; border: 1px solid #4b5677; border-radius: 8px; padding: .65rem .75rem; color: #e9eef5; background: #1a2a3f; font: inherit; }
    textarea { min-height: 130px; resize: vertical; }
    button { cursor: pointer; font-weight: 650; } button:hover { background: #284363; } button:disabled { cursor: not-allowed; opacity: .45; }
    .actions { display: flex; gap: .6rem; margin-top: 1rem; } .actions button { width: auto; flex: 1; }
    .secondary { background: transparent; } .danger { color: #ffadad; border-color: #7b444d; }
    .status { display: flex; flex-wrap: wrap; gap: .7rem 1.5rem; margin-bottom: 1rem; color: #a9bdd2; }
    .status strong { color: #e9eef5; } .notice { min-height: 1.4rem; margin-top: .75rem; color: #f0c674; }
    .search { margin-bottom: 1rem; }
    .table-wrap { overflow-x: auto; border: 1px solid #263852; border-radius: 14px; background: #131e2d; }
    table { width: 100%; border-collapse: collapse; } th, td { padding: .75rem .9rem; text-align: left; border-bottom: 1px solid #22334b; vertical-align: top; }
    th { color: #b9c9d9; background: #18283d; font-size: .83rem; text-transform: uppercase; letter-spacing: .06em; }
    td small { display: block; margin-top: .25rem; color: #91abc5; white-space: pre-wrap; } td button { width: auto; padding: .35rem .55rem; }
    .empty, .error { padding: 2rem; text-align: center; color: #9eb0c5; } .error { color: #ff9e9e; }
    @media (max-width: 850px) { .grid { grid-template-columns: 1fr; } }
  </style>
</head>
<body>
  <header><h1>retiremx management</h1><p>Manage the desired recipient configuration. <a href="/">← View incoming mail</a></p></header>
  <main>
    <section class="card">
      <div class="status">
        <span>Source: <strong id="source">Loading…</strong></span>
        <span>Imported: <strong id="imported">—</strong></span>
        <span>Groups: <strong id="group-count">—</strong></span>
        <span>Domains: <strong id="domain-count">—</strong></span>
        <button id="export" type="button" style="width:auto">Export retiremx.md</button>
        <button id="publish" type="button" style="width:auto" disabled>Save</button>
      </div>
      <div id="notice" class="notice" role="status"></div>
    </section>
    <section class="card" style="margin-top:1rem">
      <h2>Blocked senders</h2>
      <form id="blocked-form" class="actions">
        <input id="blocked-pattern" required placeholder="sender@example.com, @example.com, or *@spam.example">
        <button type="submit">Add block rule</button>
      </form>
      <div id="blocked-list" style="margin-top:.8rem"></div>
    </section>
    <div class="grid" style="margin-top:1rem">
      <section class="card">
        <h2 id="form-title">Add recipient group</h2>
        <form id="editor">
          <label for="source-address">Source address</label>
          <input id="source-address" required placeholder="oldaddress@moyville.net">
          <label for="members">Replaced by (one address per line)</label>
          <textarea id="members" required placeholder="new@example.net"></textarea>
          <label><input id="pass-through" type="checkbox" style="width:auto; margin-right:.45rem"> Pass through to Postfix</label>
          <label for="message">Optional message</label>
          <textarea id="message" style="min-height:80px" placeholder="This address has moved."></textarea>
          <div class="actions"><button type="submit">Save group</button><button id="clear" class="secondary" type="button">Clear</button></div>
        </form>
      </section>
      <section>
        <input id="search" class="search" placeholder="Search recipient groups…">
        <div id="groups" class="table-wrap"></div>
      </section>
    </div>
  </main>
  <script>
    const editor = document.querySelector('#editor');
    const source = document.querySelector('#source-address');
    const members = document.querySelector('#members');
    const passThrough = document.querySelector('#pass-through');
    const message = document.querySelector('#message');
    const groups = document.querySelector('#groups');
    const notice = document.querySelector('#notice');
    const search = document.querySelector('#search');
    const blockedForm = document.querySelector('#blocked-form');
    const blockedPattern = document.querySelector('#blocked-pattern');
    const blockedList = document.querySelector('#blocked-list');
    const exportButton = document.querySelector('#export');
    const publishButton = document.querySelector('#publish');
    const state = { recipients: [], blocked: [] };
    let configDirty = false;

    function showNotice(text, error = false) { notice.textContent = text; notice.style.color = error ? '#ff9e9e' : '#f0c674'; }
    function markConfigDirty() { configDirty = true; publishButton.disabled = false; }
    function clearForm() { editor.reset(); document.querySelector('#form-title').textContent = 'Add recipient group'; source.readOnly = false; }
    function editGroup(group) {
      source.value = group.source_address; source.readOnly = true;
      members.value = group.members.join('\n'); passThrough.checked = group.pass_through; message.value = group.message || '';
      document.querySelector('#form-title').textContent = `Edit ${group.source_address}`;
      window.scrollTo({top: 0, behavior: 'smooth'});
    }
    async function load() {
      const response = await fetch('/api/management', {cache: 'no-store'});
      if (!response.ok) throw new Error('Unable to load management configuration');
      const data = await response.json(); state.recipients = data.recipients; state.blocked = data.blocked_senders;
      document.querySelector('#source').textContent = data.source_path || 'Not imported';
      document.querySelector('#imported').textContent = data.imported_at || '—';
      document.querySelector('#group-count').textContent = data.recipients.length;
      document.querySelector('#domain-count').textContent = data.managed_domains.length;
      render();
      renderBlocked();
    }
    function render() {
      const term = search.value.trim().toLowerCase();
      const visible = state.recipients.filter(group => group.source_address.includes(term) || group.members.some(member => member.includes(term)));
      groups.replaceChildren();
      if (!visible.length) { groups.textContent = 'No recipient groups found.'; groups.className = 'table-wrap empty'; return; }
      groups.className = 'table-wrap';
      const table = document.createElement('table'); table.innerHTML = '<thead><tr><th>Source</th><th>Replaced by</th><th>Mode</th><th>Action</th></tr></thead>';
      const body = document.createElement('tbody');
      for (const group of visible) {
        const row = document.createElement('tr');
        const sourceCell = document.createElement('td'); sourceCell.textContent = group.source_address;
        if (group.message) { const note = document.createElement('small'); note.textContent = group.message; sourceCell.append(note); }
        const membersCell = document.createElement('td'); membersCell.textContent = group.members.join('\n'); membersCell.style.whiteSpace = 'pre-line';
        const modeCell = document.createElement('td'); modeCell.textContent = group.pass_through ? 'Pass through' : '550 replacement';
        const actionCell = document.createElement('td');
        const edit = document.createElement('button'); edit.textContent = 'Edit'; edit.onclick = () => editGroup(group);
        const remove = document.createElement('button'); remove.textContent = 'Delete'; remove.className = 'danger'; remove.style.marginLeft = '.4rem'; remove.onclick = () => removeGroup(group.source_address);
        actionCell.append(edit, remove); row.append(sourceCell, membersCell, modeCell, actionCell); body.append(row);
      }
      table.append(body); groups.append(table);
    }
    function renderBlocked() {
      blockedList.replaceChildren();
      if (!state.blocked.length) { blockedList.textContent = 'No blocked sender rules.'; return; }
      for (const pattern of state.blocked) {
        const item = document.createElement('span'); item.style.display = 'inline-flex'; item.style.alignItems = 'center'; item.style.gap = '.4rem'; item.style.margin = '0 .5rem .5rem 0'; item.style.padding = '.4rem .55rem'; item.style.border = '1px solid #7b444d'; item.style.borderRadius = '999px'; item.textContent = pattern;
        const remove = document.createElement('button'); remove.textContent = '×'; remove.className = 'danger'; remove.style.width = 'auto'; remove.style.padding = '.15rem .4rem'; remove.onclick = () => removeBlocked(pattern);
        item.append(remove); blockedList.append(item);
      }
    }
    async function removeBlocked(pattern) {
      const response = await fetch(`/api/management/blocked-senders?pattern=${encodeURIComponent(pattern)}`, {method: 'DELETE'});
      if (!response.ok) { showNotice('Unable to remove block rule', true); return; }
      showNotice(`Removed blocked sender rule: ${pattern}`); markConfigDirty(); await load();
    }
    async function removeGroup(address) {
      if (!confirm(`Delete ${address}?`)) return;
      const response = await fetch(`/api/management/recipients?source=${encodeURIComponent(address)}`, {method: 'DELETE'});
      if (!response.ok) { showNotice('Unable to delete group', true); return; }
      showNotice(`Deleted ${address}`); markConfigDirty(); clearForm(); await load();
    }
    editor.addEventListener('submit', async event => {
      event.preventDefault();
      const response = await fetch('/api/management/recipients', {method: 'POST', headers: {'content-type': 'application/json'}, body: JSON.stringify({source_address: source.value, members: members.value.split('\n').map(value => value.trim()).filter(Boolean), pass_through: passThrough.checked, message: message.value})});
      if (!response.ok) { const error = await response.json().catch(() => ({})); showNotice(error.error || 'Unable to save group', true); return; }
      showNotice(`Saved ${source.value.toLowerCase()}`); markConfigDirty(); clearForm(); await load();
    });
    document.querySelector('#clear').addEventListener('click', clearForm);
    blockedForm.addEventListener('submit', async event => {
      event.preventDefault();
      const response = await fetch('/api/management/blocked-senders', {method: 'POST', headers: {'content-type': 'application/json'}, body: JSON.stringify({pattern: blockedPattern.value})});
      if (!response.ok) { const error = await response.json().catch(() => ({})); showNotice(error.error || 'Unable to add block rule', true); return; }
      showNotice(`Added blocked sender rule: ${blockedPattern.value.toLowerCase()}`); markConfigDirty(); blockedPattern.value = ''; await load();
    });
    exportButton.addEventListener('click', async () => {
      const response = await fetch('/api/management/export', {cache: 'no-store'});
      if (!response.ok) { showNotice('Unable to export configuration', true); return; }
      const blob = await response.blob();
      const link = document.createElement('a'); link.href = URL.createObjectURL(blob); link.download = 'retiremx.md'; link.click();
      URL.revokeObjectURL(link.href); showNotice('Configuration exported');
    });
    publishButton.addEventListener('click', async () => {
      if (!configDirty) return;
      publishButton.disabled = true;
      const response = await fetch('/api/management/publish', {method: 'POST'});
      const data = await response.json().catch(() => ({}));
      publishButton.disabled = false;
      if (!response.ok) { showNotice(data.error || 'Unable to publish configuration', true); return; }
      configDirty = false;
      publishButton.disabled = true;
      showNotice(data.message || 'Configuration published; RetireMX will reload it automatically');
    });
    search.addEventListener('input', render);
    load().catch(error => { groups.className = 'table-wrap error'; groups.textContent = error.message; });
  </script>
</body>
</html>"#
    .to_owned()
}
