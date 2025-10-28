pub mod encryption;
pub mod trust;

pub struct Security {
    pub enabled: bool,
}

impl Security {
    pub fn new(enabled: bool) -> Self {
        Self { enabled }
    }
}
