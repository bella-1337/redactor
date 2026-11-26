//! Reading and changing `settings.env`, the file the engine reads its
//! settings from (see `read_settings_file` in app/pii_review/desktop.py).
//!
//! The file is `KEY=VALUE` lines with `#` comments. The menu changes single
//! keys and keeps everything else as the user wrote it: the comments, other
//! settings, and the order of the lines.

/// The value of `key`, as the engine reads it: the last uncommented
/// `KEY=VALUE` line, with spaces and quotes around the value removed.
pub fn get(content: &str, key: &str) -> Option<String> {
    let mut found = None;
    for line in content.lines() {
        let line = line.trim();
        if line.starts_with('#') {
            continue;
        }
        if let Some((name, value)) = line.split_once('=') {
            if name.trim() == key {
                found = Some(value.trim().trim_matches('"').trim_matches('\'').to_owned());
            }
        }
    }
    found
}

fn is_active(line: &str, key: &str) -> bool {
    let line = line.trim();
    !line.starts_with('#') && line.split_once('=').is_some_and(|(name, _)| name.trim() == key)
}

/// A commented-out example of the setting, as in the template: `#KEY=...`.
fn is_example(line: &str, key: &str) -> bool {
    line.trim_start()
        .strip_prefix('#')
        .and_then(|rest| rest.trim_start().split_once('='))
        .is_some_and(|(name, _)| name.trim() == key)
}

/// `content` with `key` set to `value`, or with the setting removed for
/// `None` (the engine then uses its default). A new line goes right below the
/// template's commented example of the setting, or at the end.
pub fn set(content: &str, key: &str, value: Option<&str>) -> String {
    let mut lines: Vec<&str> = content.lines().filter(|line| !is_active(line, key)).collect();
    let new_line = value.map(|value| format!("{key}={value}"));
    if let Some(new_line) = &new_line {
        match lines.iter().position(|line| is_example(line, key)) {
            Some(index) => lines.insert(index + 1, new_line),
            None => lines.push(new_line),
        }
    }
    let mut text = lines.join("\n");
    text.push('\n');
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    const FILE: &str = "# Language: en, de, or fr.\n#PII_REVIEW_LANGUAGE=en\n\n# Model.\n#PII_REVIEW_ASSIST_URL=http://a\n#PII_REVIEW_ASSIST_URL=http://b\nPII_REVIEW_GATEWAYS=https://g\n";

    #[test]
    fn get_reads_the_last_uncommented_line() {
        assert_eq!(get(FILE, "PII_REVIEW_LANGUAGE"), None);
        assert_eq!(get(FILE, "PII_REVIEW_GATEWAYS").as_deref(), Some("https://g"));
        let file = "PII_REVIEW_LANGUAGE = \"de\"\n# PII_REVIEW_LANGUAGE=en\nPII_REVIEW_LANGUAGE='fr'\r\n";
        assert_eq!(get(file, "PII_REVIEW_LANGUAGE").as_deref(), Some("fr"));
        assert_eq!(get(file, "PII_REVIEW_LANGUAGES"), None);
    }

    #[test]
    fn set_goes_below_the_example_and_keeps_the_rest() {
        let changed = set(FILE, "PII_REVIEW_LANGUAGE", Some("de"));
        assert_eq!(
            changed,
            "# Language: en, de, or fr.\n#PII_REVIEW_LANGUAGE=en\nPII_REVIEW_LANGUAGE=de\n\n# Model.\n#PII_REVIEW_ASSIST_URL=http://a\n#PII_REVIEW_ASSIST_URL=http://b\nPII_REVIEW_GATEWAYS=https://g\n"
        );
        // Setting it again replaces the line instead of adding one.
        let again = set(&changed, "PII_REVIEW_LANGUAGE", Some("fr"));
        assert_eq!(again.matches("PII_REVIEW_LANGUAGE=").count(), 2);
        assert_eq!(get(&again, "PII_REVIEW_LANGUAGE").as_deref(), Some("fr"));
        // The first of two examples gets it.
        let model = set(FILE, "PII_REVIEW_ASSIST_URL", Some("http://c"));
        assert!(model.contains("#PII_REVIEW_ASSIST_URL=http://a\nPII_REVIEW_ASSIST_URL=http://c\n#PII_REVIEW_ASSIST_URL=http://b"));
    }

    #[test]
    fn set_without_an_example_appends_and_none_removes() {
        let added = set("A=1\n", "PII_REVIEW_DEVICE", Some("cpu"));
        assert_eq!(added, "A=1\nPII_REVIEW_DEVICE=cpu\n");
        let removed = set(&added, "PII_REVIEW_DEVICE", None);
        assert_eq!(removed, "A=1\n");
        // Every uncommented line of the key goes, the commented ones stay.
        let file = "PII_REVIEW_DEVICE=cpu\n#PII_REVIEW_DEVICE=auto\nPII_REVIEW_DEVICE=auto\n";
        assert_eq!(set(file, "PII_REVIEW_DEVICE", None), "#PII_REVIEW_DEVICE=auto\n");
    }
}
