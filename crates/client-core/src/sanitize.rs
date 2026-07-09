//! Decrypted-metadata sanitization (DESIGN §8.1 line 353 / §13 / D24, Phase 3).
//!
//! A file's `metadata` stream (filename, attributes) is authenticated to its
//! author — but the author may be a *malicious sharer* (D11): **authenticated ≠
//! benign**. Before a decrypted filename reaches the downloader's filesystem on
//! export it is untrusted input and a path-traversal / overwrite vector
//! (CWE-22). This module is the sole gate between such a name and a real path.
//!
//! Policy (fail-closed, no silent rewrite): a name is *validated*, never quietly
//! mangled. A rewrite could collide with another file or hide the fact that the
//! sharer supplied something hostile; instead we reject and let the caller
//! surface that to the user (who then picks a name). The accepted set is exactly
//! a bare basename with no separators, no control characters, no `..`/`.`, not
//! absolute, not a Windows reserved device name, no trailing dot/space, and no
//! `:` (NTFS alternate-data-stream / drive syntax).
//!
//! Pure and platform-agnostic: the rules are the *union* of POSIX and Windows
//! hazards so an export is safe regardless of where the downloader runs (a name
//! safe on Linux can still be hostile if that user later copies it to Windows).

use std::ffi::OsStr;
use std::path::{Component, Path, PathBuf};

/// Why an untrusted metadata filename was rejected for filesystem use. Each
/// variant is a distinct, fail-closed reason; none is recoverable by rewriting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SanitizeError {
    /// The name was empty.
    Empty,
    /// Contained a C0/C1 control character (`\0`, `\n`, `\t`, DEL, …).
    ControlCharacter,
    /// Root-anchored or drive-qualified (`/x`, `\x`, `\\unc`, `C:\x`).
    AbsolutePath,
    /// Contained `:` — NTFS alternate-data-stream (`name:stream`) syntax.
    AlternateDataStream,
    /// Contained a path separator `/` or `\` (a basename has none).
    PathSeparator,
    /// The whole name is `.` or `..` — a current/parent-directory reference.
    ParentTraversal,
    /// Ends in `.` or ` ` — Windows silently trims these, changing the target.
    TrailingDotOrSpace,
    /// A Windows reserved device name (`CON`, `NUL`, `COM1`, `LPT1`, … — with or
    /// without an extension, e.g. `NUL.txt`), case-insensitively.
    ReservedName,
    /// Defense in depth: a sanitized name still did not resolve to a direct child
    /// of the chosen export directory (should be unreachable after the checks
    /// above — a structural guard, never an adversarial-input path).
    EscapesExportDir,
}

/// Windows reserved device basenames (without extension), upper-cased. Reserved
/// even with an extension (`CON.txt`) and even on POSIX exports (the file may be
/// moved to Windows later), so we reject them everywhere.
const RESERVED_STEMS: &[&str] = &[
    "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8",
    "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
];

/// Validate an untrusted (authenticated-but-adversarial, D24) metadata filename
/// for use as a basename on export. Returns the name unchanged when safe, else a
/// fail-closed [`SanitizeError`]. Checks are ordered most-specific-first so each
/// hostile form maps to one deterministic reason.
pub fn sanitize_filename(raw: &str) -> Result<String, SanitizeError> {
    if raw.is_empty() {
        return Err(SanitizeError::Empty);
    }
    // Control characters anywhere (C0/C1, DEL): a name embedding `\0`/`\n`/`\t`
    // can break path APIs, logs, or terminals — reject outright.
    if raw.chars().any(|c| c.is_control()) {
        return Err(SanitizeError::ControlCharacter);
    }
    // Root-anchored or drive-qualified: leading separator, UNC `\\`, or a
    // `<letter>:` drive prefix. Checked before the generic `:`/separator rules so
    // an absolute path reports as such.
    let bytes = raw.as_bytes();
    let drive_qualified = bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':';
    if raw.starts_with('/') || raw.starts_with('\\') || drive_qualified {
        return Err(SanitizeError::AbsolutePath);
    }
    // Any other `:` is NTFS alternate-data-stream syntax (`name:stream`).
    if raw.contains(':') {
        return Err(SanitizeError::AlternateDataStream);
    }
    // A basename has no interior separators; presence of one is adversarial
    // (we reject rather than basename-strip — see the module note).
    if raw.contains('/') || raw.contains('\\') {
        return Err(SanitizeError::PathSeparator);
    }
    // Whole-name current/parent reference.
    if raw == "." || raw == ".." {
        return Err(SanitizeError::ParentTraversal);
    }
    // Windows trims trailing dots/spaces, which would silently retarget the file.
    if raw.ends_with('.') || raw.ends_with(' ') {
        return Err(SanitizeError::TrailingDotOrSpace);
    }
    // Reserved device name (with or without extension), case-insensitively.
    let stem = raw.split('.').next().unwrap_or(raw);
    let stem_upper = stem.to_ascii_uppercase();
    if RESERVED_STEMS.contains(&stem_upper.as_str()) {
        return Err(SanitizeError::ReservedName);
    }
    Ok(raw.to_string())
}

/// Join a validated untrusted filename under a chosen export directory, with a
/// final lexical containment check (defense in depth). On success the result is
/// guaranteed a direct child of `export_dir`; the function touches no disk.
pub fn safe_export_path(export_dir: &Path, raw_name: &str) -> Result<PathBuf, SanitizeError> {
    let name = sanitize_filename(raw_name)?;
    let joined = export_dir.join(&name);
    // Defense in depth: a validated name has no separators/`..`/anchor, so the
    // join must be `export_dir` plus exactly one normal component equal to it.
    // If that invariant ever fails to hold we refuse rather than write outside.
    match joined.strip_prefix(export_dir) {
        Ok(rest) => {
            let mut comps = rest.components();
            match (comps.next(), comps.next()) {
                (Some(Component::Normal(c)), None) if c == OsStr::new(name.as_str()) => Ok(joined),
                _ => Err(SanitizeError::EscapesExportDir),
            }
        }
        Err(_) => Err(SanitizeError::EscapesExportDir),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Names that are safe basenames and must pass through unchanged.
    const BENIGN: &[&str] = &[
        "report.pdf",
        "vacation.MP4",
        "archive.tar.gz",
        "my file (1).txt",
        "résumé.docx", // non-ASCII letters are fine
        "data-2026_06_28.csv",
        ".gitignore",    // leading dot is a normal hidden file, not traversal
        "COMmunity.txt", // not a reserved name (COM + letters)
        "NULlable.rs",   // starts with NUL but is not the device name
        "a.b.c.d",
    ];

    /// (input, expected rejection reason). The union of POSIX + Windows hazards.
    const HOSTILE: &[(&str, SanitizeError)] = &[
        ("", SanitizeError::Empty),
        ("with\nnewline.txt", SanitizeError::ControlCharacter),
        ("tab\there.txt", SanitizeError::ControlCharacter),
        ("nul\0byte.txt", SanitizeError::ControlCharacter),
        ("del\x7f.txt", SanitizeError::ControlCharacter),
        ("/etc/passwd", SanitizeError::AbsolutePath),
        ("\\Windows\\System32", SanitizeError::AbsolutePath),
        ("\\\\server\\share", SanitizeError::AbsolutePath),
        ("C:\\Windows\\evil.exe", SanitizeError::AbsolutePath),
        ("z:relative", SanitizeError::AbsolutePath),
        ("name:stream", SanitizeError::AlternateDataStream),
        (
            "photo.jpg:Zone.Identifier",
            SanitizeError::AlternateDataStream,
        ),
        ("sub/dir/file.txt", SanitizeError::PathSeparator),
        ("sub\\dir\\file.txt", SanitizeError::PathSeparator),
        ("..", SanitizeError::ParentTraversal),
        (".", SanitizeError::ParentTraversal),
        ("trailingdot.", SanitizeError::TrailingDotOrSpace),
        ("trailingspace ", SanitizeError::TrailingDotOrSpace),
        ("...", SanitizeError::TrailingDotOrSpace),
        ("CON", SanitizeError::ReservedName),
        ("nul", SanitizeError::ReservedName),
        ("Com1", SanitizeError::ReservedName),
        ("LPT9.txt", SanitizeError::ReservedName),
        ("AUX.tar.gz", SanitizeError::ReservedName),
    ];

    #[test]
    fn benign_names_pass_through_unchanged() {
        for &name in BENIGN {
            assert_eq!(
                sanitize_filename(name),
                Ok(name.to_string()),
                "name={name:?}"
            );
        }
    }

    #[test]
    fn hostile_names_are_rejected_with_the_expected_reason() {
        for &(name, expected) in HOSTILE {
            assert_eq!(sanitize_filename(name), Err(expected), "name={name:?}");
        }
    }

    #[test]
    fn traversal_with_separators_is_rejected_even_if_basename_would_be_safe() {
        // The classic CWE-22 payload: its basename is "passwd" (benign) but the
        // separators make it hostile, so we reject rather than basename-strip.
        assert!(sanitize_filename("../../etc/passwd").is_err());
        assert!(sanitize_filename("..\\..\\Windows\\win.ini").is_err());
    }

    #[test]
    fn safe_export_path_places_a_benign_name_directly_under_the_dir() {
        let dir = Path::new("/exports/user");
        let p = safe_export_path(dir, "report.pdf").expect("benign name joins");
        assert_eq!(p, Path::new("/exports/user/report.pdf"));
        // The result is a direct child: parent is the export dir exactly.
        assert_eq!(p.parent(), Some(dir));
    }

    #[test]
    fn safe_export_path_rejects_every_hostile_name() {
        let dir = Path::new("/exports/user");
        for &(name, _) in HOSTILE {
            assert!(
                safe_export_path(dir, name).is_err(),
                "hostile name escaped containment: {name:?}"
            );
        }
        // And the canonical traversal payload cannot escape the export dir.
        assert!(safe_export_path(dir, "../../etc/passwd").is_err());
    }
}
