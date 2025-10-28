use crate::{
    constants::ICON_PLACEHOLDER,
    events::model::{EventMeta, LogEvent, LogLevel},
};
use async_trait::async_trait;
use tokio::io::AsyncWriteExt;

#[async_trait]
pub trait LogSink: Send + Sync {
    async fn handle(&self, event: &LogEvent);
    async fn flush(&self) {}
}

pub struct ConsoleSink {
    #[allow(dead_code)]
    level_filter: Option<LogLevel>,
}
impl ConsoleSink {
    pub fn new(level_filter: Option<LogLevel>) -> Self {
        Self { level_filter }
    }
}

fn level_rank(level: LogLevel) -> u8 {
    match level {
        LogLevel::Trace => 0,
        LogLevel::Debug => 1,
        LogLevel::Info => 2,
        LogLevel::Warn => 3,
        LogLevel::Error => 4,
    }
}

fn event_meta(event: &LogEvent) -> &EventMeta {
    match event {
        LogEvent::TrustDecision(e) => &e.meta,
        LogEvent::Promotion(e) => &e.meta,
        LogEvent::Network(e) => &e.meta,
        LogEvent::Plugin(e) => &e.meta,
        LogEvent::System(e) => &e.meta,
    }
}

#[async_trait]
impl LogSink for ConsoleSink {
    async fn handle(&self, event: &LogEvent) {
        let meta = event_meta(event);
        if meta.suppress_console {
            return;
        }
        if let Some(min) = self.level_filter {
            if level_rank(meta.level) < level_rank(min) {
                return;
            }
        }
        match event {
            LogEvent::TrustDecision(td) => {
                println!(
                    "{}TRUST role={:?} decision={} mode={} fp={:?} reason={} corr={:?}",
                    ICON_PLACEHOLDER,
                    td.role,
                    td.decision,
                    td.mode,
                    td.fingerprint,
                    td.reason,
                    td.meta.corr_id
                );
            }
            LogEvent::Promotion(p) => {
                println!(
                    "{}PROMOTE fp={} from={} to={} ok={} corr={:?}",
                    ICON_PLACEHOLDER,
                    p.fingerprint,
                    p.from_store,
                    p.to_store,
                    p.success,
                    p.meta.corr_id
                );
            }
            LogEvent::Network(n) => {
                println!(
                    "{}NET action={} addr={:?} detail={:?} corr={:?}",
                    ICON_PLACEHOLDER, n.action, n.addr, n.detail, n.meta.corr_id
                );
            }
            LogEvent::Plugin(p) => {
                println!(
                    "{}PLUGIN name={} action={} detail={:?} corr={:?}",
                    ICON_PLACEHOLDER, p.plugin, p.action, p.detail, p.meta.corr_id
                );
            }
            LogEvent::System(s) => {
                println!(
                    "{}SYS action={} detail={:?} corr={:?}",
                    ICON_PLACEHOLDER, s.action, s.detail, s.meta.corr_id
                );
            }
        }
    }
}

pub struct JsonFileSink {
    path: std::path::PathBuf,
    rotate: bool,
    max_size_bytes: u64,
    max_backups: u32,
    writer: tokio::sync::Mutex<Option<tokio::fs::File>>,
}

impl JsonFileSink {
    pub async fn new<P: Into<std::path::PathBuf>>(
        path: P,
        rotate: bool,
        max_size_bytes: u64,
        max_backups: u32,
    ) -> std::io::Result<Self> {
        let pb = path.into();
        if let Some(parent) = pb.parent() {
            tokio::fs::create_dir_all(parent).await.ok();
        }
        let file = tokio::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&pb)
            .await
            .ok();
        Ok(Self {
            path: pb,
            rotate,
            max_size_bytes,
            max_backups,
            writer: tokio::sync::Mutex::new(file),
        })
    }
    async fn rotate_if_needed(&self) {
        if !self.rotate {
            return;
        }
        if let Ok(meta) = tokio::fs::metadata(&self.path).await {
            if meta.len() >= self.max_size_bytes {
                let _ = self.perform_rotation().await;
            }
        }
    }
    async fn perform_rotation(&self) -> std::io::Result<()> {
        {
            let mut guard = self.writer.lock().await;
            *guard = None;
        }
        for idx in (1..=self.max_backups).rev() {
            let from = self.path.with_extension(format!("jsonl.{}", idx));
            let to = self.path.with_extension(format!("jsonl.{}", idx + 1));
            if from.exists() {
                let _ = std::fs::rename(&from, &to);
            }
        }
        let rotated = self.path.with_extension("jsonl.1");
        std::fs::rename(&self.path, rotated)?;
        let file = tokio::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .await?;
        let mut guard = self.writer.lock().await;
        *guard = Some(file);
        Ok(())
    }
}

#[async_trait]
impl LogSink for JsonFileSink {
    async fn handle(&self, event: &LogEvent) {
        self.rotate_if_needed().await;
        if let Ok(json) = serde_json::to_string(event) {
            let mut guard = self.writer.lock().await;
            if let Some(f) = guard.as_mut() {
                let _ = f.write_all(json.as_bytes()).await;
                let _ = f.write_all(b"\n").await;
            }
        }
    }
    async fn flush(&self) {
        let guard = self.writer.lock().await;
        if let Some(f) = guard.as_ref() {
            let _ = f.sync_all().await;
        }
    }
}
