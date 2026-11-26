//! Plugin hosting: the `Plugin` trait, plugin contexts, lifecycle management,
//! and native library loading.
//!
//! The plugin manager owns each plugin's lifecycle: `on_start`, host activation,
//! bounded per-plugin inboxes, managed background tasks, `on_stop`, and one
//! cleanup path. Native plugins run on their library's own runtime and reach
//! host functionality only through host services; see `runtime` for the
//! execution boundary.

pub mod lifecycle;
pub mod loader;
pub mod manager;
pub(crate) mod runtime;

pub use lifecycle::{
    ActivationError, DispatchReport, FailureCause, FailurePhase, HostPhase, LifecycleError,
    PluginError, PluginFailure, PluginHostOptions, PluginRegistrationError, PluginStartOutcome,
    PluginState, PluginStopReport, PromptError, QuiescePhase, Rejection, ShutdownMode,
    ShutdownReport, SpawnError, StartPolicy, StartReport, StartResult, StopResult, TaskCancelled,
    TaskExit, DEFAULT_INBOX_CAPACITY, DEFAULT_PROMPT_CAPACITY, DEFAULT_RUNTIME_WORKERS,
    DEFAULT_TASK_LIMIT,
};
#[doc(hidden)]
pub use loader::register_library;
pub use loader::{
    pinned_library_count, LoadedLibrary, NativeRegistrar, PluginLoadError, PluginLoader,
    PluginRegistrarApi, RegistrationStatus, PLUGIN_ABI_VERSION,
};
pub use manager::{
    PluginFailureSubscription, PluginManager, PluginRegistrar, PromptTarget, ShutdownHandle,
};
pub use runtime::{TaskContext, TaskHandle};

use crate::config::Config;
use crate::events::dispatcher::EventHandle;
use crate::network::delivery::{DeliveryFailureReason, DeliveryOptions, DeliveryOutcome};
use crate::network::message::Message;
use crate::network::peer_manager::PeerManager;
use crate::network::PeerStore;
use runtime::{HostServices, TaskScope};
use std::future::Future;
use std::io;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::oneshot;

/// Runtime-bound host objects. Only contexts that share the host's code copy
/// carry them. Kept behind an `Arc` so the context layout does not depend on
/// these types.
struct HostObjects {
    peer_manager: Arc<PeerManager>,
    peer_store: PeerStore,
}

/// Context passed to plugins for host interaction.
///
/// A plugin-bound context carries data (node identity, final configuration,
/// plugin ID) and host services. Official operations such as
/// [`send_message`](Self::send_message) run in host code on the host runtime.
///
/// Low-level access to the `PeerManager` and `PeerStore` is available only in
/// contexts that share the host's code copy: the host's base context and
/// statically registered (CAL) plugins. Native plugin contexts return `None`.
#[derive(Clone)]
pub struct PluginContext {
    pub events: EventHandle,
    pub local_node_id: String,
    pub config: Config,
    pub allow_console: bool,
    host_objects: Option<Arc<HostObjects>>,
    plugin_id: Option<String>,
    pub(crate) services: Option<Arc<dyn HostServices>>,
    pub(crate) scope: Option<Arc<TaskScope>>,
}

impl PluginContext {
    /// Create the host's base context. The plugin manager derives one
    /// plugin-bound context per plugin from it when startup begins.
    pub fn new(
        peer_manager: Arc<PeerManager>,
        peer_store: PeerStore,
        events: EventHandle,
        local_node_id: String,
        config: Config,
        allow_console: bool,
    ) -> Self {
        Self {
            events,
            local_node_id,
            config,
            allow_console,
            host_objects: Some(Arc::new(HostObjects {
                peer_manager,
                peer_store,
            })),
            plugin_id: None,
            services: None,
            scope: None,
        }
    }

    /// Low-level peer manager access. CAL-only: `None` in native plugin contexts.
    pub fn peer_manager(&self) -> Option<&Arc<PeerManager>> {
        self.host_objects
            .as_ref()
            .map(|objects| &objects.peer_manager)
    }

    /// Low-level peer store access. CAL-only: `None` in native plugin contexts.
    pub fn peer_store(&self) -> Option<&PeerStore> {
        self.host_objects
            .as_ref()
            .map(|objects| &objects.peer_store)
    }

    /// Replace the peer store, for hosts that finalize it after plugin
    /// registration.
    pub fn set_peer_store(&mut self, peer_store: PeerStore) {
        if let Some(objects) = self.host_objects.as_mut() {
            *objects = Arc::new(HostObjects {
                peer_manager: objects.peer_manager.clone(),
                peer_store,
            });
        }
    }

    /// Bind a copy of this context to a validated plugin ID. The copy has no
    /// host services; the plugin manager creates fully bound contexts itself.
    pub fn for_plugin(&self, plugin_id: &str) -> io::Result<Self> {
        Self::validate_plugin_id(plugin_id)?;
        let mut ctx = self.clone();
        ctx.plugin_id = Some(plugin_id.to_string());
        ctx.services = None;
        ctx.scope = None;
        Ok(ctx)
    }

    pub(crate) fn bind(
        &self,
        plugin_id: &str,
        services: Arc<dyn HostServices>,
        native: bool,
    ) -> Self {
        let mut ctx = self.clone();
        ctx.plugin_id = Some(plugin_id.to_string());
        ctx.services = Some(services.clone());
        ctx.scope = None;
        if native {
            ctx.host_objects = None;
            ctx.events = EventHandle::host_bound(services);
        }
        ctx
    }

    pub fn plugin_id(&self) -> Option<&str> {
        self.plugin_id.as_deref()
    }

    pub async fn plugin_data_dir(&self) -> io::Result<PathBuf> {
        let plugin_id = self.plugin_id.as_deref().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                "plugin data dir requires a plugin-bound context",
            )
        })?;
        let dir = self.node_data_dir().join("plugins").join(plugin_id);
        tokio::fs::create_dir_all(&dir).await?;
        Ok(dir)
    }

    fn node_data_dir(&self) -> PathBuf {
        self.config
            .node
            .as_ref()
            .and_then(|node| node.state_dir.as_ref())
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("data"))
    }

    pub(crate) fn validate_plugin_id(plugin_id: &str) -> io::Result<()> {
        if plugin_id.is_empty() || plugin_id.len() > 128 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "plugin IDs must be 1-128 characters long",
            ));
        }
        if matches!(plugin_id, "." | "..")
            || !plugin_id
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "plugin IDs may only contain ASCII letters, numbers, '.', '-' or '_'",
            ));
        }
        Ok(())
    }

    /// Deliver a message through the host's delivery runtime.
    ///
    /// The delivery, including reliable-delivery retries, runs on the host
    /// runtime. Before host activation this returns a `NotReady` failure; after
    /// shutdown has drained admitted messages it returns `Stopping`.
    pub async fn deliver_message(
        &self,
        message: Message,
        options: DeliveryOptions,
    ) -> DeliveryOutcome {
        let unavailable = DeliveryOutcome::DeliveryFailed {
            reason: DeliveryFailureReason::Unavailable,
        };
        let Some(services) = &self.services else {
            return unavailable;
        };
        let (tx, rx) = oneshot::channel();
        services.deliver(
            message,
            options,
            Box::new(move |outcome| {
                let _ = tx.send(outcome);
            }),
        );
        rx.await.unwrap_or(unavailable)
    }

    pub async fn send_message(
        &self,
        to: &str,
        message: Message,
        options: DeliveryOptions,
    ) -> DeliveryOutcome {
        let mut outbound = message;
        outbound.from = self.local_node_id.clone();
        outbound.to = to.to_string();
        self.deliver_message(outbound, options).await
    }

    /// Send a message to every connected peer. Subject to the same lifecycle
    /// checks as [`deliver_message`](Self::deliver_message).
    pub async fn broadcast(&self, message: Message) -> Result<(), Rejection> {
        let Some(services) = &self.services else {
            return Err(Rejection::Unavailable);
        };
        let (tx, rx) = oneshot::channel();
        services.broadcast(
            message,
            Box::new(move |result| {
                let _ = tx.send(result);
            }),
        );
        rx.await.unwrap_or(Err(Rejection::Unavailable))
    }

    /// Node IDs of currently connected peers.
    pub async fn connected_peer_ids(&self) -> Result<Vec<String>, Rejection> {
        let Some(services) = &self.services else {
            return Err(Rejection::Unavailable);
        };
        let (tx, rx) = oneshot::channel();
        services.connected_peer_ids(Box::new(move |result| {
            let _ = tx.send(result);
        }));
        rx.await.unwrap_or(Err(Rejection::Unavailable))
    }

    /// Spawn a managed background task in this plugin's task scope.
    ///
    /// The task runs on the plugin's runtime, counts against the plugin's task
    /// limit, and stays accounted for until its completion is observed. It
    /// receives a [`TaskContext`] for cooperative cancellation and for waiting
    /// on host activation. Returning an error or panicking reports a plugin
    /// failure to the host. Only contexts passed to plugin callbacks carry a
    /// task scope.
    pub fn spawn_task<F, Fut>(&self, name: &str, task: F) -> Result<TaskHandle, SpawnError>
    where
        F: FnOnce(TaskContext) -> Fut,
        Fut: Future<Output = Result<(), PluginError>> + Send + 'static,
    {
        let Some(scope) = &self.scope else {
            return Err(SpawnError::NotReady);
        };
        scope.spawn(name, task)
    }
}

/// Trait that all plugins implement.
///
/// The host calls `plugin_id`, `subscribed_extension_kinds`, `prompt_prefix`,
/// `early_config_defaults`, and `max_managed_tasks` once, at registration.
/// Keep them lightweight and pure. Async callbacks run as tasks on the
/// plugin's runtime: the host runtime for statically linked plugins, and the
/// library's own runtime for native plugins.
#[async_trait::async_trait]
pub trait Plugin: Send + Sync {
    fn plugin_id(&self) -> &'static str;

    /// Finish bounded local initialization. Runs once, before host activation,
    /// with the final plugin-bound context.
    ///
    /// Do not wait for plugin messages or activation-dependent sends here; spawn
    /// a managed task that waits for [`TaskContext::activated`] instead.
    async fn on_start(&self, _ctx: &PluginContext) -> Result<(), PluginError> {
        Ok(())
    }

    /// Handle one admitted message. Messages for this plugin are handled one at
    /// a time in admission order. Do not await a message that only this
    /// plugin's own inbox can deliver; forward it to a managed task instead.
    async fn on_message(&self, message: &Message, ctx: &PluginContext);

    /// Release plugin resources. Runs once if `on_start` was entered, including
    /// after a failed or cancelled start, so it must tolerate incomplete
    /// initialization.
    async fn on_stop(&self, _ctx: &PluginContext) -> Result<(), PluginError> {
        Ok(())
    }

    /// Extension kinds this plugin wants to receive.
    ///
    /// `None` preserves the default behavior of receiving every extension kind.
    /// `Some(&[])` opts out of all extension messages.
    fn subscribed_extension_kinds(&self) -> Option<&[&str]> {
        None
    }

    /// Called when the user enters a prompt for this plugin.
    async fn on_prompt(&self, _input: &str, _ctx: &PluginContext) -> Option<String> {
        None
    }

    fn prompt_prefix(&self) -> Option<&str> {
        None
    }

    /// Optional early configuration defaults hook.
    ///
    /// Lets a plugin supply default values (realm, port, app name, and other
    /// config fields) before networking is initialized. Only used when the
    /// operator has not set those fields. Must be pure: do not create a
    /// runtime, spawn tasks, or access the network here. Two plugins supplying
    /// different values for the same single-valued field is a registration
    /// error.
    fn early_config_defaults(&self) -> Option<crate::config::ConfigDefaults> {
        None
    }

    /// Limit of live managed background tasks for this plugin.
    fn max_managed_tasks(&self) -> usize {
        DEFAULT_TASK_LIMIT
    }
}
