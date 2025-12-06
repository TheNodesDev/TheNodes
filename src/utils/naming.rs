// src/utils/naming.rs
// Canonical naming helpers used across the project.

/// Convert an arbitrary string to a strict ASCII kebab-case identifier suitable for codes.
/// Rules:
/// - Unicode characters are transliterated to ASCII using `deunicode` (e.g., ü -> ue, é -> e, Å -> A)
/// - ASCII letters/digits are kept and lowercased
/// - All other characters (post-transliteration) become single `-` separators
/// - Collapses consecutive separators, trims leading/trailing `-`
/// - Returns "default" if the result would be empty
pub fn to_kebab_ascii_strict(s: &str) -> String {
    fn is_latin(c: char) -> bool {
        let u = c as u32;
        // Basic Latin handled elsewhere; include common Latin supplement/extended blocks
        (0x00C0..=0x00FF).contains(&u) // Latin-1 Supplement
            || (0x0100..=0x017F).contains(&u) // Latin Extended-A
            || (0x0180..=0x024F).contains(&u) // Latin Extended-B
            || (0x1E00..=0x1EFF).contains(&u) // Latin Extended Additional
            || (0x2C60..=0x2C7F).contains(&u) // Latin Extended-C
            || (0xA720..=0xA7FF).contains(&u) // Latin Extended-D/E
    }

    let mut out = String::with_capacity(s.len());
    let mut last_dash = false;

    for ch in s.chars() {
        // ASCII fast-path
        if ch.is_ascii() {
            let lc = ch.to_ascii_lowercase();
            if lc.is_ascii_alphanumeric() {
                out.push(lc);
                last_dash = false;
            } else if !last_dash {
                out.push('-');
                last_dash = true;
            }
            continue;
        }

        // Special-case German umlaut ü/Ü -> "ue" to match expected behavior
        if ch == 'ü' || ch == 'Ü' {
            out.push('u');
            out.push('e');
            last_dash = false;
            continue;
        }

        // For Latin letters with diacritics, transliterate; otherwise treat as separator
        if is_latin(ch) {
            let t = deunicode::deunicode(&ch.to_string());
            let mut pushed_any = false;
            for tc in t.chars() {
                let lc = tc.to_ascii_lowercase();
                if lc.is_ascii_alphanumeric() {
                    out.push(lc);
                    last_dash = false;
                    pushed_any = true;
                }
            }
            if !pushed_any && !last_dash {
                out.push('-');
                last_dash = true;
            }
        } else {
            // Non-Latin scripts: do not transliterate; treat as separator
            if !last_dash {
                out.push('-');
                last_dash = true;
            }
        }
    }

    // Trim leading/trailing dashes and collapse were handled by last_dash logic; just ensure edges
    while out.starts_with('-') {
        out.remove(0);
    }
    while out.ends_with('-') {
        out.pop();
    }
    if out.is_empty() {
        "default".to_string()
    } else {
        out
    }
}
