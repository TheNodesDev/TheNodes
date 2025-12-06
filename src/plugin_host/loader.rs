// Lets TheNodes host plugins (NEP mode).
// Dynamically loads platform libraries at runtime: .so (Linux), .dylib (macOS), .dll (Windows).

use std::ffi::c_void;
use std::fs;
use std::path::Path;

use libloading::{Library, Symbol};

use super::{Plugin, PluginRegistrar};

pub const PLUGIN_ABI_VERSION: u32 = 1;

/// Opaque handle representing a boxed plugin instance.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct PluginHandle {
    pub data: *mut c_void,
    pub vtable: *mut c_void,
}

impl PluginHandle {
    pub fn from_plugin(plugin: Box<dyn Plugin>) -> Self {
        let raw: *mut dyn Plugin = Box::into_raw(plugin);
        let parts: [*mut c_void; 2] = unsafe { std::mem::transmute(raw) };
        let data = parts[0];
        let vtable = parts[1];
        Self { data, vtable }
    }

    /// # Safety
    /// Caller must ensure the handle originated from `from_plugin` in the same process.
    pub unsafe fn into_plugin(self) -> Box<dyn Plugin> {
        let parts = [self.data, self.vtable];
        let raw: *mut dyn Plugin = std::mem::transmute(parts);
        Box::from_raw(raw)
    }
}

type RegisterPluginFn = unsafe extern "C" fn(api: *const PluginRegistrarApi);

type RegisterHandlerFn = unsafe extern "C" fn(ctx: *mut c_void, plugin: PluginHandle);

#[repr(C)]
pub struct PluginRegistrarApi {
    abi_version: u32,
    host_context: *mut c_void,
    register_handler: Option<RegisterHandlerFn>,
    reserved: [usize; 4],
}

impl PluginRegistrarApi {
    pub fn abi_version(&self) -> u32 {
        self.abi_version
    }

    pub fn register_plugin(&self, plugin: Box<dyn Plugin>) -> Result<(), PluginApiError> {
        if self.abi_version != PLUGIN_ABI_VERSION {
            return Err(PluginApiError::VersionMismatch {
                expected: PLUGIN_ABI_VERSION,
                received: self.abi_version,
            });
        }
        let handler = self
            .register_handler
            .ok_or(PluginApiError::MissingHandler)?;
        if self.host_context.is_null() {
            return Err(PluginApiError::NullContext);
        }
        let ctx = self.host_context;
        let handle = PluginHandle::from_plugin(plugin);
        unsafe {
            handler(ctx, handle);
        }
        Ok(())
    }

    /// # Safety
    /// The caller must ensure that `ptr` points to a valid `PluginRegistrarApi` instance
    /// with the expected ABI layout. Passing an invalid or dangling pointer is undefined behavior.
    pub unsafe fn from_raw<'a>(
        ptr: *const PluginRegistrarApi,
    ) -> Result<&'a PluginRegistrarApi, PluginApiError> {
        ptr.as_ref().ok_or(PluginApiError::NullApi)
    }

    fn for_host(handle: &mut PluginRegistrarHandle) -> Self {
        Self {
            abi_version: PLUGIN_ABI_VERSION,
            host_context: handle as *mut _ as *mut c_void,
            register_handler: Some(register_handler_thunk),
            reserved: [0; 4],
        }
    }
}

#[derive(Debug)]
pub enum PluginApiError {
    NullApi,
    VersionMismatch { expected: u32, received: u32 },
    MissingHandler,
    NullContext,
}

impl std::fmt::Display for PluginApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PluginApiError::NullApi => write!(f, "plugin registrar API pointer was null"),
            PluginApiError::VersionMismatch { expected, received } => write!(
                f,
                "plugin ABI version mismatch (expected {}, received {})",
                expected, received
            ),
            PluginApiError::MissingHandler => {
                write!(f, "host did not supply a register_handler callback")
            }
            PluginApiError::NullContext => {
                write!(f, "host context pointer missing for register_handler")
            }
        }
    }
}

impl std::error::Error for PluginApiError {}

#[repr(C)]
struct PluginRegistrarHandle {
    data: *mut c_void,
    vtable: *mut c_void,
}

impl PluginRegistrarHandle {
    fn from_registrar(registrar: &mut dyn PluginRegistrar) -> Self {
        let raw: *mut dyn PluginRegistrar = registrar as *mut dyn PluginRegistrar;
        let parts: [*mut c_void; 2] = unsafe { std::mem::transmute(raw) };
        Self {
            data: parts[0],
            vtable: parts[1],
        }
    }

    unsafe fn as_mut(&mut self) -> &mut dyn PluginRegistrar {
        let parts = [self.data, self.vtable];
        let raw: *mut dyn PluginRegistrar = std::mem::transmute(parts);
        &mut *raw
    }
}

unsafe extern "C" fn register_handler_thunk(ctx: *mut c_void, handle: PluginHandle) {
    if ctx.is_null() {
        return;
    }
    let registrar_handle = &mut *(ctx as *mut PluginRegistrarHandle);
    let registrar = unsafe { registrar_handle.as_mut() };
    let plugin = unsafe { handle.into_plugin() };
    registrar.register_handler(plugin);
}

pub struct PluginLoader {
    loaded: Vec<Library>,
}

impl Default for PluginLoader {
    fn default() -> Self {
        Self::new()
    }
}

impl PluginLoader {
    pub fn new() -> Self {
        Self { loaded: Vec::new() }
    }

    fn is_dynamic_lib(path: &Path) -> bool {
        match path.extension().and_then(|e| e.to_str()) {
            Some(ext) => {
                let ext = ext.to_ascii_lowercase();
                ext == "so" || ext == "dylib" || ext == "dll"
            }
            None => false,
        }
    }

    pub fn load_plugins<P: AsRef<Path>>(
        &mut self,
        plugin_dir: P,
        registrar: &mut dyn PluginRegistrar,
    ) -> anyhow::Result<()> {
        for entry in fs::read_dir(plugin_dir)? {
            let path = entry?.path();
            if Self::is_dynamic_lib(&path) {
                unsafe {
                    let lib = Library::new(&path).map_err(|e| anyhow::anyhow!(e))?;
                    let register: Symbol<RegisterPluginFn> = lib
                        .get(b"register_plugin")
                        .map_err(|e| anyhow::anyhow!(e))?;
                    let mut handle = PluginRegistrarHandle::from_registrar(registrar);
                    let api = PluginRegistrarApi::for_host(&mut handle);
                    register(&api as *const PluginRegistrarApi);
                    println!("🔌 Loaded plugin: {}", path.display());
                    self.loaded.push(lib);
                }
            }
        }
        Ok(())
    }
}

/// Convenience helper used by some templates. Creates a temporary PluginLoader,
/// loads all dynamic libraries from the directory, and returns their paths.
pub fn load_plugins_from_dir<P: AsRef<Path>>(
    plugin_dir: P,
    registrar: &mut dyn PluginRegistrar,
) -> anyhow::Result<Vec<String>> {
    let mut loader = PluginLoader::new();
    let dir = plugin_dir.as_ref();
    let mut loaded_paths: Vec<String> = Vec::new();
    for entry in fs::read_dir(dir)? {
        let path = entry?.path();
        if PluginLoader::is_dynamic_lib(&path) {
            unsafe {
                let lib = Library::new(&path).map_err(|e| anyhow::anyhow!(e))?;
                let register: Symbol<RegisterPluginFn> = lib
                    .get(b"register_plugin")
                    .map_err(|e| anyhow::anyhow!(e))?;
                let mut handle = PluginRegistrarHandle::from_registrar(registrar);
                let api = PluginRegistrarApi::for_host(&mut handle);
                register(&api as *const PluginRegistrarApi);
                println!("🔌 Loaded plugin: {}", path.display());
                loaded_paths.push(path.display().to_string());
                loader.loaded.push(lib);
            }
        }
    }
    Ok(loaded_paths)
}
