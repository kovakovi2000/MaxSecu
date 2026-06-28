//! Honest placeholders for commands the UI will call in later phases. Each
//! returns the sanitized `not_implemented` shape rather than faking a result.

use crate::error::UiError;

#[tauri::command]
pub fn list_feed() -> Result<(), UiError> {
    Err(UiError::new(
        "not_implemented",
        "Browsing arrives in a later phase.",
    ))
}

#[tauri::command]
pub fn register_glassbreak() -> Result<(), UiError> {
    Err(UiError::new(
        "not_implemented",
        "Bootstrap arrives in a later phase.",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stub_reports_not_implemented() {
        assert_eq!(list_feed().unwrap_err().code, "not_implemented");
    }
}
