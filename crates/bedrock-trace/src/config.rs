use std::path::PathBuf;

#[derive(Debug, Clone)]
pub enum WorkloadKind {
    Script(PathBuf),
    Http(PathBuf),
    Duration(std::time::Duration),
}

#[derive(Debug, Clone)]
pub struct TraceConfig {
    pub workload: WorkloadKind,
    pub ready_port: Option<u16>,
    pub ready_log_pattern: Option<String>,
}
