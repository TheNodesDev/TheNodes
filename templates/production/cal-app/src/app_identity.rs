// Application identity for {{APP_NAME}}
// Hardcode values here that must not be user-overridable via config.toml

use thenodes::config::SimpleHardcoded;
use thenodes::realms::RealmInfo;

pub fn hardcoded() -> SimpleHardcoded {
    SimpleHardcoded::new()
        .realm(RealmInfo::new("{{APP_REALM}}", "1.0"), false)
        .app_name("{{APP_NAME}}", false)
}
