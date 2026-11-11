//! The vendored gitleaks rules (`rules/ai/gitleaks`), run on the content the
//! content check reads and on each MCP server entry of an AI client config.
//! Only the ids of the rules that matched leave this module: never the
//! secret, the match, the line or a hash of any of them.
//!
//! A match follows gitleaks `detect`: the rule's keywords prefilter the
//! content, the secret is its `secretGroup` (else the first non-empty group,
//! else the whole match), a secret at or below the rule's entropy is not a
//! finding, and neither is one the global or the rule's allowlists allow.
//! The regexes run with Rust's `regex`, which is linear in the content, as
//! Go's is.

use std::sync::OnceLock;

use aho_corasick::AhoCorasick;
use regex::bytes::{Regex, RegexBuilder};

use crate::manifest::{GITLEAKS_ALLOWLIST, GITLEAKS_RULES, GitleaksAllowlist, GitleaksRule};

/// Rule ids one finding reports at most; the server accepts no more.
pub(crate) const MAX_MATCHED_RULES: usize = 32;

struct Allowlist {
    list: &'static GitleaksAllowlist,
    regexes: Vec<Regex>,
}

struct Rule {
    rule: &'static GitleaksRule,
    regex: Regex,
    allowlists: Vec<Allowlist>,
}

struct Engine {
    rules: Vec<Rule>,
    global: Allowlist,
    /// Every rule keyword, matched without case in one pass.
    keywords: AhoCorasick,
    /// The keywords in `keywords` order.
    keyword_text: Vec<&'static str>,
}

/// Go RE2's `\w`, `\d` and `\s` are ASCII, as these are with Unicode off.
fn compile(pattern: &str) -> Result<Regex, regex::Error> {
    RegexBuilder::new(pattern).unicode(false).build()
}

fn compile_allowlist(list: &'static GitleaksAllowlist) -> Result<Allowlist, regex::Error> {
    Ok(Allowlist {
        list,
        regexes: list
            .regexes
            .iter()
            .map(|pattern| compile(pattern))
            .collect::<Result<_, _>>()?,
    })
}

fn build() -> Result<Engine, String> {
    let rules = GITLEAKS_RULES
        .iter()
        .map(|rule| {
            Ok(Rule {
                rule,
                regex: compile(rule.regex)?,
                allowlists: rule
                    .allowlists
                    .iter()
                    .map(compile_allowlist)
                    .collect::<Result<_, _>>()?,
            })
        })
        .collect::<Result<Vec<_>, regex::Error>>()
        .map_err(|error| error.to_string())?;
    let mut keyword_text: Vec<&'static str> = GITLEAKS_RULES
        .iter()
        .flat_map(|rule| rule.keywords.iter().copied())
        .collect();
    keyword_text.sort_unstable();
    keyword_text.dedup();
    let keywords = AhoCorasick::builder()
        .ascii_case_insensitive(true)
        .build(&keyword_text)
        .map_err(|error| error.to_string())?;
    Ok(Engine {
        rules,
        global: compile_allowlist(&GITLEAKS_ALLOWLIST).map_err(|error| error.to_string())?,
        keywords,
        keyword_text,
    })
}

/// The compiled rules, built once per process. `None` when they fail to
/// compile, which a test rules out; nothing is then reported.
fn engine() -> Option<&'static Engine> {
    static ENGINE: OnceLock<Option<Engine>> = OnceLock::new();
    ENGINE
        .get_or_init(|| match build() {
            Ok(engine) => Some(engine),
            Err(error) => {
                log::warn!("gitleaks rules did not compile: {error}");
                None
            }
        })
        .as_ref()
}

/// The ids of the gitleaks rules `text` matches, sorted, distinct and at
/// most `MAX_MATCHED_RULES`.
pub(crate) fn secret_rule_ids(text: &[u8]) -> Vec<String> {
    let Some(engine) = engine() else {
        return Vec::new();
    };
    let mut present = vec![false; engine.keyword_text.len()];
    for found in engine.keywords.find_overlapping_iter(text) {
        present[found.pattern().as_usize()] = true;
    }
    let has_keyword = |keyword: &str| {
        engine
            .keyword_text
            .binary_search(&keyword)
            .is_ok_and(|index| present[index])
    };
    let mut ids: Vec<String> = engine
        .rules
        .iter()
        .filter(|rule| {
            rule.rule.keywords.is_empty() || rule.rule.keywords.iter().any(|k| has_keyword(k))
        })
        .filter(|rule| {
            rule.regex
                .find_iter(text)
                .any(|found| is_finding(engine, rule, text, found.start(), found.end()))
        })
        .map(|rule| rule.rule.id.to_string())
        .collect();
    ids.sort();
    ids.dedup();
    ids.truncate(MAX_MATCHED_RULES);
    ids
}

fn is_finding(engine: &Engine, rule: &Rule, text: &[u8], start: usize, end: usize) -> bool {
    let matched = trim_newlines(&text[start..end]);
    // gitleaks finds the secret group by matching the rule again on the
    // trimmed match.
    let secret = match rule.regex.captures(matched) {
        Some(groups) if groups.len() >= 2 => {
            if rule.rule.secret_group > 0 {
                let Ok(index) = usize::try_from(rule.rule.secret_group) else {
                    return false;
                };
                if index >= groups.len() {
                    return false;
                }
                groups.get(index).map_or(&b""[..], |group| group.as_bytes())
            } else {
                groups
                    .iter()
                    .skip(1)
                    .flatten()
                    .map(|group| group.as_bytes())
                    .find(|group| !group.is_empty())
                    .unwrap_or(matched)
            }
        }
        _ => matched,
    };
    if rule.rule.entropy != 0.0 && shannon_entropy(secret) <= rule.rule.entropy {
        return false;
    }
    let line_start = text[..start]
        .iter()
        .rposition(|&byte| byte == b'\n')
        .map_or(0, |index| index + 1);
    let line_end = text[end..]
        .iter()
        .position(|&byte| byte == b'\n')
        .map_or(text.len(), |index| end + index);
    let line = &text[line_start..line_end];
    !allowed(&engine.global, secret, matched, line)
        && !rule
            .allowlists
            .iter()
            .any(|list| allowed(list, secret, matched, line))
}

fn allowed(allowlist: &Allowlist, secret: &[u8], matched: &[u8], line: &[u8]) -> bool {
    let list = allowlist.list;
    let target = match list.target {
        "match" => matched,
        "line" => line,
        _ => secret,
    };
    let regex = allowlist.regexes.iter().any(|regex| regex.is_match(target));
    let lower = secret.to_ascii_lowercase();
    let stopword = !secret.is_empty()
        && list
            .stopwords
            .iter()
            .any(|word| contains(&lower, word.as_bytes()));
    if list.all {
        // Paths and commits never hold for content without a repository.
        let mut checks = Vec::new();
        if list.has_paths {
            checks.push(false);
        }
        if !list.regexes.is_empty() {
            checks.push(regex);
        }
        if !list.stopwords.is_empty() {
            checks.push(stopword);
        }
        checks.iter().all(|check| *check)
    } else {
        regex || stopword
    }
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    needle.is_empty()
        || haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

fn trim_newlines(bytes: &[u8]) -> &[u8] {
    let start = bytes
        .iter()
        .position(|&b| b != b'\n')
        .unwrap_or(bytes.len());
    let end = bytes
        .iter()
        .rposition(|&b| b != b'\n')
        .map_or(start, |i| i + 1);
    &bytes[start..end]
}

/// Shannon entropy as gitleaks computes it: character counts over the byte
/// length.
fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = std::collections::HashMap::new();
    for ch in String::from_utf8_lossy(data).chars() {
        *counts.entry(ch).or_insert(0usize) += 1;
    }
    let length = data.len() as f64;
    counts
        .values()
        .map(|&count| {
            let frequency = count as f64 / length;
            -frequency * frequency.log2()
        })
        .sum()
}

#[cfg(test)]
mod tests;
