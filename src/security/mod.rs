pub mod encryption;
pub mod secure_channel;
pub mod trust;

pub struct Security {
    pub enabled: bool,
}

impl Security {
    pub fn new(enabled: bool) -> Self {
        Self { enabled }
    }
}
