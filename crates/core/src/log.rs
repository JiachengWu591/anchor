//! 后台进程的日志：追加写入一个文件，超过 1 MB 轮换一次；可同时输出到 stderr。

use crate::util::now_rfc3339;
use std::io::Write;
use std::path::PathBuf;
use std::sync::Mutex;

struct Sink {
    path: Option<PathBuf>,
    stderr: bool,
}

static SINK: Mutex<Sink> = Mutex::new(Sink { path: None, stderr: true });
const MAX_BYTES: u64 = 1 << 20;

pub fn init(path: Option<PathBuf>, stderr: bool) {
    let mut s = SINK.lock().unwrap_or_else(|e| e.into_inner());
    s.path = path;
    s.stderr = stderr;
}

pub fn line(msg: &str) {
    let text = format!("[{}] {msg}\n", now_rfc3339());
    let s = SINK.lock().unwrap_or_else(|e| e.into_inner());
    if s.stderr {
        eprint!("{text}");
    }
    if let Some(p) = &s.path {
        if std::fs::metadata(p).map(|m| m.len() > MAX_BYTES).unwrap_or(false) {
            let _ = std::fs::rename(p, p.with_extension("log.1"));
        }
        if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(p) {
            let _ = f.write_all(text.as_bytes());
        }
    }
}
