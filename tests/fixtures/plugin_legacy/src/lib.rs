//! A library shaped like a plugin built for an older plugin ABI.
//!
//! The host must reject it before calling `register_plugin`; calling it aborts
//! the process, which fails the test that loads it.

/// Reports the previous plugin ABI.
#[cfg(feature = "version-export")]
#[no_mangle]
pub extern "C" fn thenodes_plugin_abi_version() -> u32 {
    3
}

/// Old registration entry point with the old signature. Never safe to call.
#[no_mangle]
pub extern "C" fn register_plugin(_api: *const core::ffi::c_void) {
    std::process::abort();
}
