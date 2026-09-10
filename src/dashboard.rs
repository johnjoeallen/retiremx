use anyhow::{Context, Result};
use serde_json::Value;
use std::{
    collections::BTreeMap,
    fs::File,
    io::{self, BufRead, BufReader},
    path::PathBuf,
};

#[derive(Debug, Eq, Ord, PartialEq, PartialOrd)]
struct Key {
    hour: u64,
    recipient: String,
    sender: String,
    decision: String,
    replacement: String,
}

pub fn run(input: Option<PathBuf>) -> Result<()> {
    let reader: Box<dyn BufRead> = match input {
        Some(path) => {
            Box::new(BufReader::new(File::open(&path).with_context(|| {
                format!("opening log input {}", path.display())
            })?))
        }
        None => Box::new(BufReader::new(io::stdin().lock())),
    };
    let mut counts = BTreeMap::<Key, u64>::new();
    for line in reader.lines() {
        let line = line.context("reading log input")?;
        let Ok(event) = serde_json::from_str::<Value>(&line) else {
            continue;
        };
        if event.get("event").and_then(Value::as_str) != Some("recipient_decision") {
            continue;
        }
        let Some(timestamp) = event.get("timestamp").and_then(Value::as_u64) else {
            continue;
        };
        let Some(recipient) = event.get("recipient").and_then(Value::as_str) else {
            continue;
        };
        let Some(decision) = event.get("decision").and_then(Value::as_str) else {
            continue;
        };
        let key = Key {
            hour: timestamp / 3600 * 3600,
            recipient: recipient.to_owned(),
            sender: event
                .get("mail_from")
                .and_then(Value::as_str)
                .unwrap_or("<>")
                .to_owned(),
            decision: decision.to_owned(),
            replacement: event
                .get("replacement")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_owned(),
        };
        *counts.entry(key).or_default() += 1;
    }

    println!(
        "Hour (UTC)          Recipient                    Decision       Sender                         Replacement                         Count"
    );
    println!("{}", "-".repeat(145));
    for (key, count) in counts {
        println!(
            "{:<19} {:<28} {:<14} {:<30} {:<35} {}",
            format_hour(key.hour),
            key.recipient,
            key.decision,
            key.sender,
            if key.replacement.is_empty() {
                "-"
            } else {
                &key.replacement
            },
            count
        );
    }
    Ok(())
}

fn format_hour(timestamp: u64) -> String {
    let days = timestamp / 86_400;
    let hour = (timestamp % 86_400) / 3_600;
    let (year, month, day) = civil_from_days(days as i64);
    format!("{year:04}-{month:02}-{day:02} {hour:02}:00")
}

// Howard Hinnant's public-domain civil-from-days conversion.
fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = mp + if mp < 10 { 3 } else { -9 };
    let year = y + if month <= 2 { 1 } else { 0 };
    (year, month, day)
}

#[cfg(test)]
mod tests {
    use super::format_hour;

    #[test]
    fn formats_unix_hour_as_utc() {
        assert_eq!(format_hour(0), "1970-01-01 00:00");
        assert_eq!(format_hour(1_735_689_600), "2025-01-01 00:00");
    }
}
