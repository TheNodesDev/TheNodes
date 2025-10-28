//! TheNodes public prelude (curated stable-intent exports).
//! Import with: `use thenodes::prelude::*;`
//!
//! Items here are considered *stable-intent* prior to 1.0.0. Their shape may
//! still adjust minimally until the first tagged release, but we aim to avoid
//! breaking renames or removals. Exclusions are deliberate.

pub use crate::config::{Config, ConfigDefaults};
pub use crate::network::message::{Message, MessageType, Payload};
pub use crate::realms::RealmInfo;

// NOTE: Plugin trait intentionally NOT re-exported yet (see STABILITY.md)
