// SPDX-License-Identifier: AGPL-3.0-only
//! Localized mail templates (account and legal mails, app token expiry notices).
//!
//! Every mail is a template `templates/mail/<language>/<name>.txt` compiled into the node for `en` (the fallback) and
//! `de`. The first line is `Subject: …`, the second is empty, the rest is the plain-text body. `{variable}` is replaced
//! by its value (values are inserted once, never read as templates themselves); every template knows the variables of
//! [`TEMPLATES`] plus `node` (the node's name), `domain` and `public_url`.
//!
//! The language is the recipient's (`users.locale`, set by the client; reporters of legal notices: the
//! `Accept-Language` of the notice): `de-AT` tries `de-at`, then `de`, then `en`. Operators override any template per
//! language with a file of the same name under `TAVRN_MAIL_TEMPLATES_DIR` (`<dir>/<language>/<name>.txt`, also for
//! languages the node has no built-in texts for); `check-config` validates that directory, and an override that is
//! invalid when a mail is sent is skipped (logged) in favour of the built-in text.

use std::path::{Path, PathBuf};

/// Built-in languages; `en` is the fallback.
pub const LANGUAGES: &[&str] = &["en", "de"];
pub const FALLBACK: &str = "en";
/// Variables every template may use.
pub const COMMON_VARS: &[&str] = &["node", "domain", "public_url"];
/// Largest override file.
pub const MAX_TEMPLATE_BYTES: u64 = 64 * 1024;

/// The templates and the variables each one may use (besides [`COMMON_VARS`]).
pub const TEMPLATES: &[(&str, &[&str])] = &[
    ("verify_email", &["name", "link"]),
    ("password_reset", &["name", "link"]),
    ("account_deleted", &["address", "purge_after"]),
    ("account_deleted_by_admin", &["address", "purge_after"]),
    ("account_restored", &["address"]),
    ("notice_received", &["case", "link"]),
    ("notice_forwarded_in", &["case", "origin"]),
    ("notice_content_removed", &["case", "reason"]),
    ("notice_account_disabled", &["case", "reason"]),
    ("notice_rejected", &["case", "reason"]),
    ("notice_forwarded", &["case", "nodes"]),
    ("counter_notice_received", &["case", "statement", "signature"]),
    ("counter_restored", &["case", "reason"]),
    ("counter_upheld", &["case", "reason"]),
    ("statement_content_removed", &["case", "basis", "statement", "deadline"]),
    ("statement_account_disabled", &["case", "basis", "statement", "deadline"]),
    ("app_token_expiring_week", &["name", "application", "expires_at", "link"]),
    ("app_token_expiring_day", &["name", "application", "expires_at", "link"]),
];

/// The compiled-in text of a template.
fn builtin(lang: &str, name: &str) -> Option<&'static str> {
    macro_rules! texts {
        ($($n:literal),* $(,)?) => {
            match (lang, name) {
                $(
                    ("en", $n) => Some(include_str!(concat!("../templates/mail/en/", $n, ".txt"))),
                    ("de", $n) => Some(include_str!(concat!("../templates/mail/de/", $n, ".txt"))),
                )*
                _ => None,
            }
        };
    }
    texts!(
        "verify_email",
        "password_reset",
        "account_deleted",
        "account_deleted_by_admin",
        "account_restored",
        "notice_received",
        "notice_forwarded_in",
        "notice_content_removed",
        "notice_account_disabled",
        "notice_rejected",
        "notice_forwarded",
        "counter_notice_received",
        "counter_restored",
        "counter_upheld",
        "statement_content_removed",
        "statement_account_disabled",
        "app_token_expiring_week",
        "app_token_expiring_day",
    )
}

/// A rendered mail (the subject without the node's name, which [`crate::mail::Mailer`] puts in front).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rendered {
    pub subject: String,
    pub body: String,
    /// The language whose template was used.
    pub language: String,
}

fn vars_of(name: &str) -> Option<&'static [&'static str]> {
    TEMPLATES.iter().find(|(n, _)| *n == name).map(|(_, v)| *v)
}

/// A language tag as the node stores it: lowercase, `xx`, `xxx` or with subtags (`de-at`, `zh-hant-tw`), at most 35
/// characters; `None` for anything else.
pub fn normalize_locale(raw: &str) -> Option<String> {
    let tag = raw.trim().replace('_', "-").to_ascii_lowercase();
    let mut parts = tag.split('-');
    let primary = parts.next()?;
    let ok = tag.len() <= 35
        && (2..=3).contains(&primary.len())
        && primary.chars().all(|c| c.is_ascii_lowercase())
        && parts.all(|p| (1..=8).contains(&p.len()) && p.chars().all(|c| c.is_ascii_alphanumeric()));
    ok.then_some(tag)
}

/// The first language of an `Accept-Language` header, normalized (`None` without a usable one).
pub fn from_accept_language(header: Option<&str>) -> Option<String> {
    let first = header?.split(',').next()?.split(';').next()?.trim();
    normalize_locale(first)
}

/// Languages to try for `locale`, most specific first, ending with the fallback.
fn candidates(locale: Option<&str>) -> Vec<String> {
    let mut out = Vec::new();
    if let Some(tag) = locale.and_then(normalize_locale) {
        let parts: Vec<&str> = tag.split('-').collect();
        for n in (1..=parts.len()).rev() {
            out.push(parts[..n].join("-"));
        }
    }
    if !out.iter().any(|l| l == FALLBACK) {
        out.push(FALLBACK.into());
    }
    out
}

/// Splits a template into (subject, body) and checks its variables against those of `name`.
pub fn parse(name: &str, text: &str) -> Result<(String, String), String> {
    let vars = vars_of(name).ok_or_else(|| format!("unknown template \"{name}\""))?;
    let text = text.strip_prefix('\u{feff}').unwrap_or(text).replace("\r\n", "\n");
    let (first, rest) = text.split_once('\n').unwrap_or((&text, ""));
    let subject = first.strip_prefix("Subject:").map(str::trim).filter(|s| !s.is_empty());
    let Some(subject) = subject else { return Err("the first line must be \"Subject: …\"".into()) };
    let Some(body) = rest.strip_prefix('\n') else {
        return Err("an empty line must follow the subject".into());
    };
    let body = body.trim_end().to_string();
    if body.trim().is_empty() {
        return Err("the body is empty".into());
    }
    for var in placeholders(subject).into_iter().chain(placeholders(&body)) {
        if !vars.contains(&var.as_str()) && !COMMON_VARS.contains(&var.as_str()) {
            let mut known: Vec<&str> = vars.iter().chain(COMMON_VARS).copied().collect();
            known.sort_unstable();
            return Err(format!("unknown variable {{{var}}} (known: {})", known.join(", ")));
        }
    }
    Ok((subject.to_string(), body))
}

/// The `{variable}` names of a text (lowercase letters and `_`).
fn placeholders(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = text;
    while let Some(start) = rest.find('{') {
        let after = &rest[start + 1..];
        match after.find('}') {
            Some(end) if end > 0 && after[..end].chars().all(|c| c.is_ascii_lowercase() || c == '_') => {
                out.push(after[..end].to_string());
                rest = &after[end + 1..];
            }
            _ => rest = after,
        }
    }
    out
}

/// Replaces every known `{variable}` in one pass (values are never scanned again).
fn fill(template: &str, vars: &[(&str, &str)]) -> String {
    let mut out = String::with_capacity(template.len());
    let mut rest = template;
    while let Some(start) = rest.find('{') {
        out.push_str(&rest[..start]);
        let after = &rest[start + 1..];
        let value = after.find('}').and_then(|end| {
            let key = &after[..end];
            vars.iter().find(|(k, _)| *k == key).map(|(_, v)| (end, *v))
        });
        match value {
            Some((end, v)) => {
                out.push_str(v);
                rest = &after[end + 1..];
            }
            None => {
                out.push('{');
                rest = after;
            }
        }
    }
    out.push_str(rest);
    out
}

/// The operator's override of `name` in `lang`, if there is a valid one.
fn override_text(dir: &Path, lang: &str, name: &str) -> Option<(String, String)> {
    let path = dir.join(lang).join(format!("{name}.txt"));
    let meta = std::fs::metadata(&path).ok()?;
    if meta.len() > MAX_TEMPLATE_BYTES {
        tracing::warn!(path = %path.display(), "mail template too large, the built-in text is used");
        return None;
    }
    let text = std::fs::read_to_string(&path)
        .map_err(|e| tracing::warn!(path = %path.display(), error = %e, "mail template not readable"))
        .ok()?;
    parse(name, &text)
        .map_err(|e| tracing::warn!(path = %path.display(), problem = %e, "mail template invalid, the built-in text is used"))
        .ok()
}

/// Renders the template `name` for `locale` (see the module documentation for the order). `vars` must include the
/// common variables; [`crate::mail::Mailer::render`] adds them.
pub fn render(dir: Option<&Path>, locale: Option<&str>, name: &str, vars: &[(&str, &str)]) -> Rendered {
    for lang in candidates(locale) {
        let text = dir
            .and_then(|d| override_text(d, &lang, name))
            .or_else(|| builtin(&lang, name).and_then(|t| parse(name, t).ok()));
        if let Some((subject, body)) = text {
            // A subject is one header line: values (display names, application names) never break it.
            let subject: String = fill(&subject, vars).chars().map(|c| if c.is_control() { ' ' } else { c }).collect();
            return Rendered { subject, body: fill(&body, vars), language: lang };
        }
    }
    // Unreachable for the names of TEMPLATES (the English texts exist and are tested).
    Rendered { subject: name.into(), body: String::new(), language: FALLBACK.into() }
}

/// `check-config`: every file under `dir` must be `<language>/<known name>.txt` and a valid template.
pub fn check_dir(dir: &Path) -> Vec<String> {
    let mut problems = Vec::new();
    let Ok(langs) = std::fs::read_dir(dir) else {
        return vec![format!("{} is not a readable directory", dir.display())];
    };
    for lang in langs.flatten() {
        let path = lang.path();
        let lang_name = lang.file_name().to_string_lossy().to_string();
        if !path.is_dir() || normalize_locale(&lang_name).as_deref() != Some(lang_name.as_str()) {
            problems.push(format!(
                "{}: expected a directory named by a lowercase language tag (en, de, de-at)",
                path.display()
            ));
            continue;
        }
        let Ok(files) = std::fs::read_dir(&path) else {
            problems.push(format!("{} is not readable", path.display()));
            continue;
        };
        for file in files.flatten() {
            let file_path = file.path();
            let name = file.file_name().to_string_lossy().to_string();
            let Some(stem) = name.strip_suffix(".txt").filter(|s| vars_of(s).is_some()) else {
                let known: Vec<&str> = TEMPLATES.iter().map(|(n, _)| *n).collect();
                problems.push(format!("{}: unknown template (known: {})", file_path.display(), known.join(", ")));
                continue;
            };
            let text = match std::fs::metadata(&file_path) {
                Ok(m) if m.len() > MAX_TEMPLATE_BYTES => Err(format!("larger than {} KiB", MAX_TEMPLATE_BYTES / 1024)),
                _ => std::fs::read_to_string(&file_path).map_err(|e| e.to_string()),
            };
            if let Err(e) = text.and_then(|t| parse(stem, &t).map(|_| ())) {
                problems.push(format!("{}: {e}", file_path.display()));
            }
        }
    }
    problems
}

/// The override directory of a configuration (`TAVRN_MAIL_TEMPLATES_DIR`, default `<TAVRN_DATA_DIR>/templates/mail`).
pub fn dir_of(config: &crate::config::Config) -> PathBuf {
    match config.mail_templates_dir.as_deref().map(str::trim).filter(|d| !d.is_empty()) {
        Some(d) => PathBuf::from(d),
        None => Path::new(&config.data_dir).join("templates").join("mail"),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn every_builtin_template_exists_in_every_language_and_parses() {
        for (name, _) in TEMPLATES {
            for lang in LANGUAGES {
                let text = builtin(lang, name).unwrap_or_else(|| panic!("{lang}/{name} missing"));
                let (subject, body) = parse(name, text).unwrap_or_else(|e| panic!("{lang}/{name}: {e}"));
                assert!(!subject.contains('\n') && !body.is_empty(), "{lang}/{name}");
            }
        }
        assert!(builtin("en", "nonexistent").is_none());
    }

    #[test]
    fn languages_fall_back_from_specific_to_english() {
        assert_eq!(candidates(Some("de-AT")), vec!["de-at", "de", "en"]);
        assert_eq!(candidates(Some("fr")), vec!["fr", "en"]);
        assert_eq!(candidates(None), vec!["en"]);
        assert_eq!(candidates(Some("<script>")), vec!["en"]);
        let r = render(None, Some("de-AT"), "password_reset", &[("name", "Anna"), ("link", "https://x/r")]);
        assert_eq!((r.language.as_str(), r.subject.as_str()), ("de", "Setze dein Passwort zurück"));
        assert!(r.body.starts_with("Hallo Anna,") && r.body.contains("https://x/r"), "{}", r.body);
        let r = render(None, Some("fr"), "password_reset", &[("name", "Anne"), ("link", "l")]);
        assert_eq!((r.language.as_str(), r.subject.as_str()), ("en", "Reset your password"));
    }

    #[test]
    fn locales_are_normalized() {
        assert_eq!(normalize_locale("de-AT").as_deref(), Some("de-at"));
        assert_eq!(normalize_locale("pt_BR").as_deref(), Some("pt-br"));
        assert_eq!(normalize_locale(" en ").as_deref(), Some("en"));
        for bad in ["", "e", "english", "de-", "d1", "de-AT-xxxxxxxxx", "*", "de;q=0.9"] {
            assert_eq!(normalize_locale(bad), None, "{bad}");
        }
        assert_eq!(from_accept_language(Some("de-DE,de;q=0.9,en;q=0.8")).as_deref(), Some("de-de"));
        assert_eq!(from_accept_language(Some("*")), None);
        assert_eq!(from_accept_language(None), None);
    }

    #[test]
    fn subjects_stay_one_line_whatever_the_values() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("en")).unwrap();
        std::fs::write(dir.path().join("en/verify_email.txt"), "Subject: Hi {name}\n\nHello {name}\n").unwrap();
        let r = render(Some(dir.path()), None, "verify_email", &[("name", "Eve\r\nBcc: x@y.z\tok")]);
        assert_eq!(r.subject, "Hi Eve  Bcc: x@y.z ok");
        assert_eq!(r.body, "Hello Eve\r\nBcc: x@y.z\tok", "bodies keep the value");
    }

    fn values_are_inserted_once_and_unknown_braces_stay() {
        assert_eq!(fill("a {x} b {y} {x}", &[("x", "{y}"), ("y", "Y")]), "a {y} b Y {y}");
        assert_eq!(fill("{unknown} {} {", &[("x", "1")]), "{unknown} {} {");
        assert_eq!(placeholders("{a} {B} {} {c_d} {e"), vec!["a", "c_d"]);
    }

    #[test]
    fn templates_are_validated() {
        let ok = "Subject: Hi {name}\n\nHello {name}, {link} on {node}\n";
        assert_eq!(parse("verify_email", ok).unwrap(), ("Hi {name}".into(), "Hello {name}, {link} on {node}".into()));
        assert!(parse("verify_email", "Hello").unwrap_err().contains("Subject"));
        assert!(parse("verify_email", "Subject: x\nbody").unwrap_err().contains("empty line"));
        assert!(parse("verify_email", "Subject: x\n\n  \n").unwrap_err().contains("empty"));
        assert!(parse("verify_email", "Subject: x\n\n{case}").unwrap_err().contains("unknown variable {case}"));
        assert!(parse("nope", ok).unwrap_err().contains("unknown template"));
    }

    #[test]
    fn operator_overrides_win_per_language_and_invalid_ones_are_skipped() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("de")).unwrap();
        std::fs::create_dir_all(dir.path().join("fr")).unwrap();
        std::fs::write(
            dir.path().join("de/password_reset.txt"),
            "Subject: Neues Passwort\r\n\r\nServus {name}: {link}\n",
        )
        .unwrap();
        std::fs::write(dir.path().join("fr/password_reset.txt"), "Subject: Mot de passe\n\nBonjour {name}\n").unwrap();
        std::fs::write(dir.path().join("de/verify_email.txt"), "Subject: x\n\n{unknown}").unwrap();
        let vars = [("name", "Anna"), ("link", "L")];
        let r = render(Some(dir.path()), Some("de"), "password_reset", &vars);
        assert_eq!((r.subject.as_str(), r.body.as_str()), ("Neues Passwort", "Servus Anna: L"));
        assert_eq!(render(Some(dir.path()), Some("fr-CA"), "password_reset", &vars).subject, "Mot de passe");
        assert_eq!(render(Some(dir.path()), Some("en"), "password_reset", &vars).subject, "Reset your password");
        let r = render(Some(dir.path()), Some("de"), "verify_email", &vars);
        assert_eq!(r.subject, "Bestätige deine E-Mail-Adresse", "an invalid override falls back");

        let problems = check_dir(dir.path());
        assert_eq!(problems.len(), 1, "{problems:?}");
        assert!(problems[0].contains("verify_email.txt") && problems[0].contains("{unknown}"), "{problems:?}");
        std::fs::write(dir.path().join("de/nope.txt"), "Subject: x\n\ny").unwrap();
        std::fs::create_dir_all(dir.path().join("German")).unwrap();
        let problems = check_dir(dir.path());
        assert!(problems.iter().any(|p| p.contains("nope.txt") && p.contains("unknown template")), "{problems:?}");
        assert!(problems.iter().any(|p| p.contains("German")), "{problems:?}");
        assert!(!check_dir(&dir.path().join("missing")).is_empty());
    }
}
