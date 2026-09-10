use serde::Serialize;
use std::collections::HashMap;
use thiserror::Error;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AddressDefinition {
    Group {
        members: Vec<String>,
        pass_through: bool,
        message: Option<String>,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum UnknownAction {
    Reject,
    PassThrough,
}

#[derive(Clone, Debug, Serialize)]
#[serde(tag = "status", rename_all = "lowercase")]
pub enum Resolution {
    Retired {
        requested_address: String,
        replacements: Vec<String>,
        message: String,
        pass_through: bool,
    },
    Unknown {
        requested_address: String,
        message: String,
        action: UnknownAction,
    },
}

#[derive(Debug, Error)]
pub enum ResolveError {
    #[error("address cycle detected: {0}")]
    Cycle(String),
    #[error("ambiguous normalized address {normalized}: {first} and {second}")]
    AmbiguousNormalized {
        normalized: String,
        first: String,
        second: String,
    },
}

#[derive(Clone, Debug)]
pub struct Resolver {
    definitions: HashMap<String, AddressDefinition>,
    normalized: HashMap<String, String>,
    wildcards: Vec<(String, String)>,
    unknown_message: String,
    retired_message: String,
    unknown_action: UnknownAction,
}

impl Resolver {
    pub fn new(
        definitions: HashMap<String, AddressDefinition>,
        unknown_message: String,
        retired_message: String,
        unknown_action: UnknownAction,
    ) -> Result<Self, ResolveError> {
        let mut normalized: HashMap<String, String> = HashMap::new();
        let mut wildcards = Vec::new();
        for address in definitions.keys() {
            let key = match_key(address);
            let domain = key.split_once('@').map_or("", |(_, domain)| domain);
            if domain.is_empty() || domain.ends_with(".*") {
                wildcards.push((key, address.clone()));
                continue;
            }
            if let Some(first) = normalized.get(&key) {
                if definitions[first] != definitions[address] {
                    return Err(ResolveError::AmbiguousNormalized {
                        normalized: key,
                        first: first.clone(),
                        second: address.clone(),
                    });
                }
            } else {
                normalized.insert(key, address.clone());
            }
        }
        let resolver = Self {
            definitions,
            normalized,
            wildcards,
            unknown_message,
            retired_message,
            unknown_action,
        };
        for address in resolver.definitions.keys() {
            resolver.walk(address, &mut Vec::new())?;
        }
        Ok(resolver)
    }

    pub fn resolve(&self, address: &str) -> Resolution {
        let requested = normalize(address);
        let definition_address = self
            .definitions
            .get_key_value(&requested)
            .map(|(address, _)| address.clone())
            .or_else(|| self.normalized.get(&match_key(&requested)).cloned())
            .or_else(|| self.wildcard_match(&requested));
        let Some(definition_address) = definition_address else {
            return Resolution::Unknown {
                requested_address: requested,
                message: self.unknown_message.clone(),
                action: self.unknown_action,
            };
        };
        let definition = self.definitions.get(&definition_address).unwrap();
        match definition {
            AddressDefinition::Group {
                members,
                pass_through,
                message,
            } => Resolution::Retired {
                requested_address: requested.clone(),
                replacements: preserve_plus_tag(&requested, members),
                message: message
                    .clone()
                    .unwrap_or_else(|| self.retired_message.clone()),
                pass_through: *pass_through,
            },
        }
    }

    fn wildcard_match(&self, address: &str) -> Option<String> {
        let key = match_key(address);
        let (local, domain) = key.split_once('@')?;
        let mut matches = self
            .wildcards
            .iter()
            .filter(|(pattern, _)| {
                let (pattern_local, pattern_domain) =
                    pattern.split_once('@').unwrap_or((pattern, ""));
                pattern_local == local
                    && (pattern_domain.is_empty()
                        || (pattern_domain.ends_with(".*")
                            && domain
                                .strip_prefix(pattern_domain.trim_end_matches(".*"))
                                .is_some_and(|suffix| suffix.starts_with('.'))))
            })
            .collect::<Vec<_>>();
        matches.sort_by_key(|(pattern, _)| pattern.split_once('@').map_or(0, |(_, d)| d.len()));
        let best = matches.last()?;
        if matches
            .iter()
            .filter(|(p, _)| {
                p.split_once('@').map_or(0, |(_, d)| d.len())
                    == best.0.split_once('@').map_or(0, |(_, d)| d.len())
            })
            .count()
            > 1
        {
            return None;
        }
        Some(best.1.clone())
    }

    fn walk(&self, address: &str, path: &mut Vec<String>) -> Result<(), ResolveError> {
        let key = normalize(address);
        if let Some(index) = path.iter().position(|item| item == &key) {
            let mut cycle = path[index..].to_vec();
            cycle.push(key);
            return Err(ResolveError::Cycle(cycle.join(" -> ")));
        }
        let Some(definition) = self.definitions.get(&key) else {
            return Ok(());
        };
        let refs: Vec<&str> = match definition {
            AddressDefinition::Group { members, .. } => {
                members.iter().map(String::as_str).collect()
            }
        };
        path.push(key);
        for reference in refs {
            if self.definitions.contains_key(&normalize(reference)) {
                self.walk(reference, path)?;
            }
        }
        path.pop();
        Ok(())
    }
}

pub fn normalize(address: &str) -> String {
    address.trim().to_ascii_lowercase()
}

fn match_key(address: &str) -> String {
    let normalized = normalize(address);
    let Some((local, domain)) = normalized.split_once('@') else {
        return normalized;
    };
    let local = local.split_once('+').map_or(local, |(base, _)| base);
    format!("{}@{}", local.replace('.', ""), domain)
}

fn preserve_plus_tag(requested: &str, replacements: &[String]) -> Vec<String> {
    let Some((local, _)) = requested.split_once('@') else {
        return replacements.to_vec();
    };
    let Some((_, tag)) = local.split_once('+') else {
        return replacements.to_vec();
    };
    replacements
        .iter()
        .map(|replacement| {
            let Some((replacement_local, domain)) = replacement.split_once('@') else {
                return replacement.clone();
            };
            format!("{replacement_local}+{tag}@{domain}")
        })
        .collect()
}

#[allow(dead_code)]
pub fn format_replacements(items: &[String]) -> String {
    match items {
        [] => String::new(),
        [one] => one.clone(),
        [a, b] => format!("{a} and {b}"),
        _ => {
            let last = items.last().unwrap();
            format!(
                "{}, {} {}",
                items[..items.len() - 1].join(", "),
                "and",
                last
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn formatting() {
        let a = vec!["a".into(), "b".into(), "c".into()];
        assert_eq!(format_replacements(&a), "a, b, and c");
    }
    #[test]
    fn nested_groups_deduplicate() {
        let mut d = HashMap::new();
        d.insert(
            "g".into(),
            AddressDefinition::Group {
                members: vec!["a".into(), "a".into()],
                pass_through: false,
                message: None,
            },
        );
        let r =
            Resolver::new(d, "unknown".into(), "retired".into(), UnknownAction::Reject).unwrap();
        assert!(matches!(r.resolve("G"), Resolution::Retired { .. }));
    }
    #[test]
    fn cycles_are_rejected() {
        let mut d = HashMap::new();
        d.insert(
            "a".into(),
            AddressDefinition::Group {
                members: vec!["b".into()],
                pass_through: false,
                message: None,
            },
        );
        d.insert(
            "b".into(),
            AddressDefinition::Group {
                members: vec!["a".into()],
                pass_through: false,
                message: None,
            },
        );
        assert!(Resolver::new(d, "u".into(), "r".into(), UnknownAction::Reject).is_err());
    }

    #[test]
    fn dot_and_plus_variants_match() {
        let mut d = HashMap::new();
        d.insert(
            "john.allen@moyville.net".into(),
            AddressDefinition::Group {
                members: vec!["replacement@example.net".into()],
                pass_through: false,
                message: None,
            },
        );
        let r =
            Resolver::new(d, "unknown".into(), "retired".into(), UnknownAction::Reject).unwrap();
        for address in [
            "john.allen@moyville.net",
            "johnallen@moyville.net",
            "johnallen+rcmag@moyville.net",
            "john.allen+rc.mag@moyville.net",
        ] {
            assert!(matches!(r.resolve(address), Resolution::Retired { .. }));
        }
        match r.resolve("john.allen+rc.mag@moyville.net") {
            Resolution::Retired { replacements, .. } => {
                assert_eq!(replacements, vec!["replacement+rc.mag@example.net"]);
            }
            _ => panic!("expected retired resolution"),
        }
    }

    #[test]
    fn wildcard_domains_match() {
        let mut d = HashMap::new();
        d.insert(
            "john.allen@classesarecode.*".into(),
            AddressDefinition::Group {
                members: vec!["replacement@example.net".into()],
                pass_through: false,
                message: None,
            },
        );
        d.insert(
            "jane@".into(),
            AddressDefinition::Group {
                members: vec!["jane@example.net".into()],
                pass_through: false,
                message: None,
            },
        );
        let r =
            Resolver::new(d, "unknown".into(), "retired".into(), UnknownAction::Reject).unwrap();
        assert!(matches!(
            r.resolve("johnallen+rcmag@classesarecode.org"),
            Resolution::Retired { .. }
        ));
        assert!(matches!(
            r.resolve("jane@any-domain.example"),
            Resolution::Retired { .. }
        ));
        assert!(matches!(
            r.resolve("johnallen@classesarecode2.org"),
            Resolution::Unknown { .. }
        ));
    }

    #[test]
    fn ambiguous_normalized_sources_are_rejected() {
        let mut definitions = HashMap::new();
        for (address, replacement) in [
            ("john.allen@example.com", "first@example.net"),
            ("johnallen@example.com", "second@example.net"),
        ] {
            definitions.insert(
                address.to_string(),
                AddressDefinition::Group {
                    members: vec![replacement.into()],
                    pass_through: false,
                    message: None,
                },
            );
        }
        assert!(matches!(
            Resolver::new(
                definitions,
                "unknown".into(),
                "retired".into(),
                UnknownAction::Reject
            ),
            Err(ResolveError::AmbiguousNormalized { .. })
        ));
    }
}
