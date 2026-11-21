//! Lifecycle states, outcomes, options, and reports for hosted plugins.
//!
//! These types describe what the plugin manager observed. They carry bounded
//! operational metadata only: plugin IDs, phases, result categories, and
//! truncated error text. They never carry message payloads or configuration.

use std::fmt;
use std::time::Duration;

/// Maximum length of free-form error text kept in failures and reports.
pub(crate) const MAX_REPORT_TEXT: usize = 256;

/// Default number of admitted messages per plugin inbox, including the message
/// in progress.
pub const DEFAULT_INBOX_CAPACITY: usize = 32;
/// Default number of concurrent prompt calls admitted per plugin.
pub const DEFAULT_PROMPT_CAPACITY: usize = 4;
/// Default limit of live managed background tasks per plugin.
pub const DEFAULT_TASK_LIMIT: usize = 128;
/// Default number of worker threads in a native plugin library's runtime.
pub const DEFAULT_RUNTIME_WORKERS: usize = 2;

/// Error returned by plugin lifecycle hooks and managed tasks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PluginError {
    message: String,
}

impl PluginError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for PluginError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for PluginError {}

impl From<std::io::Error> for PluginError {
    fn from(error: std::io::Error) -> Self {
        Self::new(error.to_string())
    }
}

impl From<String> for PluginError {
    fn from(message: String) -> Self {
        Self::new(message)
    }
}

impl From<&str> for PluginError {
    fn from(message: &str) -> Self {
        Self::new(message)
    }
}

/// State of one hosted plugin.
///
/// `Running` means the plugin's `on_start` completed. It does not by itself
/// open message admission; that also requires host activation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PluginState {
    Registered,
    Starting,
    Running,
    Stopping,
    Stopped,
    Failed,
}

/// Host-level lifecycle phase of a plugin manager.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum HostPhase {
    /// Plugins may still be registered; nothing has started.
    Registering,
    /// `start_all` is running plugin start hooks.
    Starting,
    /// Every start hook has returned; admission waits for activation.
    Ready,
    /// The host activated normal plugin admission.
    Active,
    /// Shutdown has begun; no new inbound work is admitted.
    Stopping,
    /// Shutdown finished and produced a report.
    Stopped,
}

/// Whether `start_all` continues after a plugin fails to start.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StartPolicy {
    /// Stop starting further plugins after the first failure.
    StopOnFirstFailure,
    /// Start every plugin and report each outcome.
    ContinueOnFailure,
}

/// How shutdown treats messages that were admitted but not yet handled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShutdownMode {
    /// Let each plugin finish its admitted messages before cancellation.
    /// Admitted messages are only drained after activation; before activation
    /// they are discarded because no ordinary callback may run.
    Drain,
    /// Discard queued messages and cancel the message in progress.
    Discard,
}

/// Why a lifecycle-checked operation was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rejection {
    /// The plugin or host has not reached the state that permits the operation.
    NotReady,
    /// A finite admission bound is exhausted.
    Overloaded,
    /// The host or plugin is stopping.
    Stopping,
    /// The plugin failed, was never started, or the host no longer exists.
    Unavailable,
}

impl fmt::Display for Rejection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            Rejection::NotReady => "not ready",
            Rejection::Overloaded => "overloaded",
            Rejection::Stopping => "stopping",
            Rejection::Unavailable => "unavailable",
        };
        f.write_str(text)
    }
}

impl std::error::Error for Rejection {}

/// Where a plugin failure happened.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailurePhase {
    Start,
    Message,
    Prompt,
    Task,
    Stop,
}

impl FailurePhase {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            FailurePhase::Start => "start",
            FailurePhase::Message => "message",
            FailurePhase::Prompt => "prompt",
            FailurePhase::Task => "task",
            FailurePhase::Stop => "stop",
        }
    }
}

/// What a plugin failure consisted of. Text is truncated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FailureCause {
    /// A hook or managed task returned an error.
    Error(String),
    /// Plugin code panicked; the panic was caught in the plugin's code copy.
    Panic(String),
    /// The plugin could not be executed, for example because its runtime
    /// could not be created.
    Unavailable(String),
}

impl FailureCause {
    pub(crate) fn category(&self) -> &'static str {
        match self {
            FailureCause::Error(_) => "error",
            FailureCause::Panic(_) => "panic",
            FailureCause::Unavailable(_) => "unavailable",
        }
    }
}

/// A plugin failure reported to the host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PluginFailure {
    pub plugin_id: String,
    pub phase: FailurePhase,
    pub cause: FailureCause,
}

impl fmt::Display for PluginFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let detail = match &self.cause {
            FailureCause::Error(text)
            | FailureCause::Panic(text)
            | FailureCause::Unavailable(text) => text,
        };
        write!(
            f,
            "plugin '{}' failed during {} ({}): {}",
            self.plugin_id,
            self.phase.as_str(),
            self.cause.category(),
            detail
        )
    }
}

/// Outcome of starting one plugin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StartResult {
    Started,
    Failed(PluginFailure),
    /// A shutdown request cancelled initialization.
    Cancelled,
    /// The plugin was not started, for example after an earlier failure.
    NotStarted,
}

/// Start outcome for one plugin, in registration order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PluginStartOutcome {
    pub plugin_id: String,
    pub result: StartResult,
    pub elapsed: Option<Duration>,
}

/// Per-plugin outcomes of `PluginManager::start_all`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StartReport {
    pub outcomes: Vec<PluginStartOutcome>,
}

impl StartReport {
    /// True when every registered plugin started.
    pub fn all_started(&self) -> bool {
        self.outcomes
            .iter()
            .all(|outcome| outcome.result == StartResult::Started)
    }

    pub fn failures(&self) -> impl Iterator<Item = &PluginFailure> {
        self.outcomes
            .iter()
            .filter_map(|outcome| match &outcome.result {
                StartResult::Failed(failure) => Some(failure),
                _ => None,
            })
    }
}

/// Shutdown step during which work was not observed to complete.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuiescePhase {
    Start,
    Drain,
    Callbacks,
    Cleanup,
    Stop,
    Tasks,
}

impl QuiescePhase {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            QuiescePhase::Start => "start",
            QuiescePhase::Drain => "drain",
            QuiescePhase::Callbacks => "callbacks",
            QuiescePhase::Cleanup => "cleanup",
            QuiescePhase::Stop => "stop",
            QuiescePhase::Tasks => "tasks",
        }
    }
}

/// Result of a plugin's cleanup path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StopResult {
    /// `on_stop` returned successfully and managed work was observed to end.
    Stopped,
    /// `on_stop` returned an error.
    HookFailed(String),
    /// `on_stop` panicked.
    Panicked(String),
    /// The stop hook was cancelled before it completed.
    Cancelled,
    /// The plugin's start hook was never entered, so no stop hook ran.
    NotStarted,
    /// Escalation stopped the host from waiting during the given phase.
    /// The plugin's code and runtime are retained.
    FailedToQuiesce(QuiescePhase),
}

/// Shutdown outcome for one plugin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PluginStopReport {
    pub plugin_id: String,
    pub final_state: PluginState,
    /// The execution failure that isolated the plugin, kept separate from
    /// its cleanup result.
    pub failure: Option<PluginFailure>,
    pub stop: StopResult,
    pub discarded_messages: u64,
    pub aborted_tasks: usize,
}

/// Structured report produced by `PluginManager::shutdown`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShutdownReport {
    pub mode: ShutdownMode,
    pub plugins: Vec<PluginStopReport>,
    /// True when escalation ended waiting before every step completed.
    pub escalated: bool,
    /// Native library runtimes released after their handlers stopped.
    /// Release does not wait for threads that plugins created outside the
    /// managed task scope.
    pub runtimes_released: usize,
    /// Native library runtimes kept alive because work was not observed to end.
    pub runtimes_retained: usize,
    pub elapsed: Duration,
}

impl ShutdownReport {
    /// True when every plugin stopped cleanly and no failure was recorded.
    pub fn is_clean(&self) -> bool {
        !self.escalated
            && self.plugins.iter().all(|plugin| {
                plugin.failure.is_none()
                    && matches!(plugin.stop, StopResult::Stopped | StopResult::NotStarted)
            })
    }

    pub fn failed_to_quiesce(&self) -> impl Iterator<Item = &PluginStopReport> {
        self.plugins
            .iter()
            .filter(|plugin| matches!(plugin.stop, StopResult::FailedToQuiesce(_)))
    }
}

/// Result of offering one message to the subscribed plugins.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DispatchReport {
    /// Number of plugin inboxes that admitted the message.
    pub admitted: usize,
    /// Plugins that are subscribed but refused the message.
    pub rejected: Vec<(String, Rejection)>,
}

/// Errors from lifecycle transitions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LifecycleError {
    /// The operation is not valid in the current host phase.
    InvalidState {
        phase: HostPhase,
        operation: &'static str,
    },
    /// Plugins are registered but no host context was configured.
    MissingContext,
    /// The operation needs a Tokio runtime context and none is available.
    NoRuntime,
    /// No plugin with this ID is registered.
    UnknownPlugin(String),
    /// The lifecycle operation ended without producing a result.
    Interrupted,
    /// Host options are invalid.
    InvalidOptions(String),
}

impl fmt::Display for LifecycleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LifecycleError::InvalidState { phase, operation } => {
                write!(f, "cannot {operation} while the plugin host is {phase:?}")
            }
            LifecycleError::MissingContext => {
                write!(
                    f,
                    "plugins are registered but no plugin context is configured"
                )
            }
            LifecycleError::NoRuntime => write!(f, "no Tokio runtime context is available"),
            LifecycleError::UnknownPlugin(id) => write!(f, "no plugin '{id}' is registered"),
            LifecycleError::Interrupted => write!(f, "lifecycle operation was interrupted"),
            LifecycleError::InvalidOptions(reason) => write!(f, "invalid host options: {reason}"),
        }
    }
}

impl std::error::Error for LifecycleError {}

/// Errors from `PluginManager::activate`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ActivationError {
    /// Activation requires every start hook to have returned.
    InvalidState(HostPhase),
    /// These failed plugins have not been acknowledged by the host.
    UnacknowledgedFailures(Vec<String>),
}

impl fmt::Display for ActivationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ActivationError::InvalidState(phase) => {
                write!(f, "cannot activate while the plugin host is {phase:?}")
            }
            ActivationError::UnacknowledgedFailures(ids) => write!(
                f,
                "activation refused; failed plugins are not acknowledged: {}",
                ids.join(", ")
            ),
        }
    }
}

impl std::error::Error for ActivationError {}

/// Errors from `PluginManager::dispatch_prompt`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PromptError {
    Rejected(Rejection),
    Cancelled,
    Failed(PluginFailure),
}

impl fmt::Display for PromptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PromptError::Rejected(reason) => write!(f, "prompt rejected: {reason}"),
            PromptError::Cancelled => write!(f, "prompt cancelled"),
            PromptError::Failed(failure) => write!(f, "{failure}"),
        }
    }
}

impl std::error::Error for PromptError {}

/// Errors from spawning a managed task.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpawnError {
    /// The context is not bound to a started plugin task scope.
    NotReady,
    /// The plugin's task scope is cancelled or shutting down.
    Stopping,
    /// The plugin already has `limit` live managed tasks.
    Overloaded { limit: usize },
}

impl fmt::Display for SpawnError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SpawnError::NotReady => write!(f, "plugin task scope is not ready"),
            SpawnError::Stopping => write!(f, "plugin task scope is stopping"),
            SpawnError::Overloaded { limit } => {
                write!(f, "plugin task limit of {limit} live tasks reached")
            }
        }
    }
}

impl std::error::Error for SpawnError {}

/// Returned when a managed task waits for activation but its scope is
/// cancelled first.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TaskCancelled;

impl fmt::Display for TaskCancelled {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("managed task scope was cancelled")
    }
}

impl std::error::Error for TaskCancelled {}

/// Observed end of a managed task.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TaskExit {
    Completed,
    Failed(PluginError),
    Panicked(String),
    Cancelled,
}

/// Errors returned while registering plugins.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PluginRegistrationError {
    InvalidId {
        plugin_id: String,
        reason: String,
    },
    DuplicateId {
        plugin_id: String,
    },
    DuplicatePromptPrefix {
        plugin_id: String,
        prefix: String,
    },
    /// Two plugins supply different defaults for the same single-valued field.
    ConflictingDefaults {
        plugin_id: String,
        other_plugin_id: String,
        field: &'static str,
    },
    InvalidRuntimeConfig(String),
    /// A native library registered no plugins.
    NoPlugins,
    /// Registration closed when startup began.
    RegistrationClosed,
    /// The plugin's own registration function failed.
    Plugin(String),
    /// A native registration failed with this status and no further detail.
    Native(super::loader::RegistrationStatus),
}

impl PluginRegistrationError {
    pub(crate) fn status(&self) -> super::loader::RegistrationStatus {
        use super::loader::RegistrationStatus;
        match self {
            PluginRegistrationError::InvalidId { .. } => RegistrationStatus::InvalidPluginId,
            PluginRegistrationError::DuplicateId { .. } => RegistrationStatus::DuplicatePluginId,
            PluginRegistrationError::DuplicatePromptPrefix { .. } => {
                RegistrationStatus::DuplicatePromptPrefix
            }
            PluginRegistrationError::ConflictingDefaults { .. } => {
                RegistrationStatus::ConflictingDefaults
            }
            PluginRegistrationError::InvalidRuntimeConfig(_) => {
                RegistrationStatus::InvalidRuntimeConfig
            }
            PluginRegistrationError::NoPlugins => RegistrationStatus::NoPlugins,
            PluginRegistrationError::RegistrationClosed => RegistrationStatus::RegistrationClosed,
            PluginRegistrationError::Plugin(_) => RegistrationStatus::PluginError,
            PluginRegistrationError::Native(status) => *status,
        }
    }
}

impl fmt::Display for PluginRegistrationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PluginRegistrationError::InvalidId { plugin_id, reason } => {
                write!(f, "invalid plugin id '{plugin_id}': {reason}")
            }
            PluginRegistrationError::DuplicateId { plugin_id } => write!(
                f,
                "duplicate plugin id '{plugin_id}': another registered plugin owns this id and its data directory"
            ),
            PluginRegistrationError::DuplicatePromptPrefix { plugin_id, prefix } => write!(
                f,
                "plugin '{plugin_id}' uses prompt prefix '{prefix}', which another plugin already uses"
            ),
            PluginRegistrationError::ConflictingDefaults {
                plugin_id,
                other_plugin_id,
                field,
            } => write!(
                f,
                "plugin '{plugin_id}' supplies a default for '{field}' that conflicts with plugin '{other_plugin_id}'"
            ),
            PluginRegistrationError::InvalidRuntimeConfig(reason) => {
                write!(f, "invalid plugin runtime configuration: {reason}")
            }
            PluginRegistrationError::NoPlugins => write!(f, "the library registered no plugins"),
            PluginRegistrationError::RegistrationClosed => {
                write!(f, "plugin registration is closed")
            }
            PluginRegistrationError::Plugin(reason) => {
                write!(f, "plugin registration function failed: {reason}")
            }
            PluginRegistrationError::Native(status) => {
                write!(f, "native plugin registration failed: {status:?}")
            }
        }
    }
}

impl std::error::Error for PluginRegistrationError {}

/// Host-facing options. Plugin-facing settings such as the task limit and
/// native runtime size are declared by plugins at registration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PluginHostOptions {
    /// Admitted messages per plugin inbox, including the message in progress.
    pub inbox_capacity: usize,
    /// Concurrent prompt calls admitted per plugin.
    pub prompt_capacity: usize,
}

impl Default for PluginHostOptions {
    fn default() -> Self {
        Self {
            inbox_capacity: DEFAULT_INBOX_CAPACITY,
            prompt_capacity: DEFAULT_PROMPT_CAPACITY,
        }
    }
}

impl PluginHostOptions {
    pub fn validate(&self) -> Result<(), LifecycleError> {
        if self.inbox_capacity == 0 {
            return Err(LifecycleError::InvalidOptions(
                "inbox_capacity must be at least 1".to_string(),
            ));
        }
        if self.prompt_capacity == 0 {
            return Err(LifecycleError::InvalidOptions(
                "prompt_capacity must be at least 1".to_string(),
            ));
        }
        Ok(())
    }
}

/// Truncate free-form text and replace control characters so it stays on one line.
pub(crate) fn bounded_text(text: &str) -> String {
    let single: String = text
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    if single.len() <= MAX_REPORT_TEXT {
        return single;
    }
    let mut end = MAX_REPORT_TEXT;
    while !single.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}...", &single[..end])
}
