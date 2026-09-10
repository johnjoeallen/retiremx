use serde_json::{Map, Value};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use std::{
    fs::{File, OpenOptions},
    io::{BufWriter, Write},
    path::Path,
    sync::{Mutex, OnceLock},
};
use uuid::Uuid;

static NEXT_SESSION_ID: AtomicU64 = AtomicU64::new(1);
static EVENT_LOG: OnceLock<Mutex<BufWriter<File>>> = OnceLock::new();

pub fn next_session_id() -> u64 {
    NEXT_SESSION_ID.fetch_add(1, Ordering::Relaxed)
}

pub fn event(name: &str, fields: impl IntoIterator<Item = (&'static str, Value)>) {
    let line = render_event(name, fields);
    eprintln!("{line}");
    if let Some(log) = EVENT_LOG.get()
        && let Ok(mut log) = log.lock()
        && let Err(error) = writeln!(log, "{line}").and_then(|_| log.flush())
    {
        eprintln!("retiremx event log write failed: {error}");
    }
}

pub fn init_event_log(path: &Path) -> std::io::Result<()> {
    let file = OpenOptions::new().create(true).append(true).open(path)?;
    EVENT_LOG
        .set(Mutex::new(BufWriter::new(file)))
        .map_err(|_| std::io::Error::other("event log already initialized"))
}

pub fn render_event(name: &str, fields: impl IntoIterator<Item = (&'static str, Value)>) -> String {
    let mut object = Map::new();
    object.insert("event".into(), Value::String(name.into()));
    object.insert("event_id".into(), Value::String(Uuid::new_v4().to_string()));
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    object.insert("timestamp".into(), Value::from(timestamp));
    for (key, value) in fields {
        object.insert(key.into(), value);
    }
    Value::Object(object).to_string()
}

#[cfg(test)]
mod tests {
    use super::render_event;
    use serde_json::json;
    use uuid::Uuid;

    #[test]
    fn renders_structured_event_json() {
        let event: serde_json::Value = serde_json::from_str(&render_event(
            "recipient_rejected",
            [("smtp_code", json!(550))],
        ))
        .unwrap();
        assert_eq!(event["event"], "recipient_rejected");
        assert_eq!(event["smtp_code"], 550);
        assert!(Uuid::parse_str(event["event_id"].as_str().unwrap()).is_ok());
    }
}
