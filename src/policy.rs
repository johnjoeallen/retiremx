use regex::{Regex, RegexBuilder};
use serde::Serialize;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum SenderAction {
    MigrationRules,
    PassThrough,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum SenderVerification {
    None,
    Mx,
}

#[derive(Clone, Debug)]
pub struct SenderRule {
    pub pattern: String,
    pub action: SenderAction,
    pub verification: SenderVerification,
}

#[derive(Clone, Debug)]
pub struct BlockedSenderRule {
    pub pattern: String,
    matcher: BlockedSenderMatcher,
}

#[derive(Clone, Debug)]
enum BlockedSenderMatcher {
    Exact(String),
    Domain(String),
    Regex(Regex),
}

impl BlockedSenderRule {
    pub fn new(pattern: &str) -> Result<Self, regex::Error> {
        let pattern = pattern.trim().to_ascii_lowercase();
        let matcher = if pattern.starts_with('/') && pattern.ends_with('/') {
            let expression = &pattern[1..pattern.len() - 1];
            RegexBuilder::new(&format!("^(?:{expression})$"))
                .case_insensitive(true)
                .build()
                .map(BlockedSenderMatcher::Regex)?
        } else if pattern.starts_with('@') && !pattern.contains('*') && !pattern.contains('?') {
            BlockedSenderMatcher::Domain(pattern[1..].to_string())
        } else if pattern.contains('*') || pattern.contains('?') {
            let glob = if pattern.starts_with('@') {
                format!("*{pattern}")
            } else {
                pattern.clone()
            };
            BlockedSenderMatcher::Regex(glob_regex(&glob)?)
        } else {
            BlockedSenderMatcher::Exact(pattern.clone())
        };
        Ok(Self { pattern, matcher })
    }

    pub fn matches(&self, sender: &str) -> bool {
        let sender = sender.trim().to_ascii_lowercase();
        match &self.matcher {
            BlockedSenderMatcher::Exact(pattern) => &sender == pattern,
            BlockedSenderMatcher::Domain(domain) => sender
                .split_once('@')
                .is_some_and(|(_, value)| value == domain),
            BlockedSenderMatcher::Regex(regex) => regex.is_match(&sender),
        }
    }
}

fn glob_regex(pattern: &str) -> Result<Regex, regex::Error> {
    let mut expression = String::from("^");
    for character in pattern.chars() {
        match character {
            '*' => expression.push_str(".*"),
            '?' => expression.push('.'),
            character => expression.push_str(&regex::escape(&character.to_string())),
        }
    }
    expression.push('$');
    RegexBuilder::new(&expression)
        .case_insensitive(true)
        .build()
}

#[derive(Clone, Debug, Default)]
pub struct SenderPolicy {
    rules: Vec<SenderRule>,
    blocked: Vec<BlockedSenderRule>,
}

impl SenderPolicy {
    pub fn new(rules: Vec<SenderRule>, blocked: Vec<BlockedSenderRule>) -> Self {
        Self { rules, blocked }
    }

    pub fn match_sender(&self, sender: &str) -> Option<&SenderRule> {
        let sender = sender.trim().to_ascii_lowercase();
        let domain = sender.split_once('@').map(|(_, domain)| domain);
        self.rules
            .iter()
            .find(|rule| rule.pattern == sender)
            .or_else(|| {
                domain.and_then(|domain| self.rules.iter().find(|rule| rule.pattern == domain))
            })
    }

    pub fn blocked_sender(&self, sender: &str) -> Option<&BlockedSenderRule> {
        self.blocked.iter().find(|rule| rule.matches(sender))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_sender_rule_precedes_domain_rule() {
        let policy = SenderPolicy::new(
            vec![
                SenderRule {
                    pattern: "example.com".into(),
                    action: SenderAction::MigrationRules,
                    verification: SenderVerification::None,
                },
                SenderRule {
                    pattern: "alerts@example.com".into(),
                    action: SenderAction::PassThrough,
                    verification: SenderVerification::Mx,
                },
            ],
            vec![],
        );
        let rule = policy.match_sender("Alerts@Example.COM").unwrap();
        assert_eq!(rule.pattern, "alerts@example.com");
        assert_eq!(rule.action, SenderAction::PassThrough);
    }

    #[test]
    fn domain_rule_matches_sender_without_exact_rule() {
        let policy = SenderPolicy::new(
            vec![SenderRule {
                pattern: "example.com".into(),
                action: SenderAction::PassThrough,
                verification: SenderVerification::None,
            }],
            vec![],
        );
        assert_eq!(
            policy.match_sender("sender@example.com").unwrap().action,
            SenderAction::PassThrough
        );
    }

    #[test]
    fn unmatched_sender_has_no_policy() {
        let policy = SenderPolicy::new(vec![], vec![]);
        assert!(policy.match_sender("sender@example.com").is_none());
    }

    #[test]
    fn blocked_sender_matches_exact_domain_glob_and_regex() {
        let policy = SenderPolicy::new(
            vec![],
            vec![
                BlockedSenderRule::new("jobs@moyville.net").unwrap(),
                BlockedSenderRule::new("@mail.gl1pro.shop").unwrap(),
                BlockedSenderRule::new("@*.strickteam.com").unwrap(),
                BlockedSenderRule::new("*@spam.example").unwrap(),
                BlockedSenderRule::new("/^alerts[0-9]+@bad.example$/").unwrap(),
            ],
        );
        assert!(policy.blocked_sender("JOBS@moyville.net").is_some());
        assert!(policy.blocked_sender("anything@mail.gl1pro.shop").is_some());
        assert!(
            policy
                .blocked_sender("anything@eu.strickteam.com")
                .is_some()
        );
        assert!(
            policy
                .blocked_sender("7475-297-8316-1342-john.allen=dublinux.net@mail.gl1pro.shop")
                .is_some()
        );
        assert!(policy.blocked_sender("x@spam.example").is_some());
        assert!(policy.blocked_sender("alerts42@bad.example").is_some());
        assert!(policy.blocked_sender("alerts@bad.example").is_none());
    }
}
