use crate::{config::WorkloadKind, Result};

pub struct WorkloadRunner {
    kind: WorkloadKind,
}

impl WorkloadRunner {
    pub fn new(kind: WorkloadKind) -> Self {
        Self { kind }
    }
    
    pub async fn run(&self) -> Result<()> {
        match &self.kind {
            WorkloadKind::Script(path) => {
                println!("Running workload script: {}", path.display());
            },
            WorkloadKind::Http(path) => {
                println!("Replaying HTTP requests from: {}", path.display());
            },
            WorkloadKind::Duration(d) => {
                println!("Waiting for duration: {:?}", d);
                tokio::time::sleep(*d).await;
            }
        }
        Ok(())
    }
}
