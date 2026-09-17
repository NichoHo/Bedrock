use crate::trace::config::WorkloadKind;
use anyhow::Result;

pub struct WorkloadRunner {
    kind: WorkloadKind,
}

impl WorkloadRunner {
    pub fn new(kind: WorkloadKind) -> Self {
        Self { kind }
    }

    pub fn run(&self) -> Result<()> {
        match &self.kind {
            WorkloadKind::Script(path) => {
                println!("Running workload script: {}", path.display());
            }
            WorkloadKind::Http(path) => {
                println!("Replaying HTTP requests from: {}", path.display());
            }
            WorkloadKind::Duration(d) => {
                println!("Waiting for duration: {:?}", d);
                std::thread::sleep(*d);
            }
        }
        Ok(())
    }
}
