// src/realms/realm.rs
use crate::utils::to_kebab_ascii_strict;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RealmInfo {
    pub name: String,
    /// Canonical machine-safe code (kebab-case). If None, derive from name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
    pub version: String,
}

impl RealmInfo {
    #[allow(clippy::should_implement_trait)]
    pub fn default() -> Self {
        Self {
            name: "default".to_string(),
            code: Some("default".to_string()),
            version: "1.0".to_string(),
        }
    }

    /// Constructor deriving code from name.
    pub fn new(name: impl Into<String>, version: impl Into<String>) -> Self {
        let name_str = name.into();
        let code = Some(to_kebab_ascii_strict(&name_str));
        Self {
            name: name_str,
            code,
            version: version.into(),
        }
    }

    /// Constructor with explicit code.
    pub fn new_with_code(
        name: impl Into<String>,
        code: impl Into<String>,
        version: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            code: Some(code.into()),
            version: version.into(),
        }
    }

    /// Return the canonical code string (kebab). If code is None, derive from name.
    pub fn canonical_code(&self) -> String {
        self.code
            .clone()
            .unwrap_or_else(|| to_kebab_ascii_strict(&self.name))
    }

    pub fn matches(&self, other: &RealmInfo) -> bool {
        self.canonical_code() == other.canonical_code() && self.version == other.version
    }
}

// Provide std::default::Default so templates that call unwrap_or_default() compile.
impl Default for RealmInfo {
    fn default() -> Self {
        Self {
            name: "default".to_string(),
            code: Some("default".to_string()),
            version: "1.0".to_string(),
        }
    }
}

// kebab canonicalization moved to utils::naming::to_kebab_ascii_strict
