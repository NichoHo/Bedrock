use std::path::PathBuf;

#[derive(thiserror::Error, Debug)]
pub enum VerifyError {
    #[error("Workload failed on pruned image")]
    WorkloadFailed,
}

pub type Result<T> = std::result::Result<T, VerifyError>;

pub struct Verifier {
    pruned_image_dir: PathBuf,
}

impl Verifier {
    pub fn new(pruned_image_dir: PathBuf) -> Self {
        Self { pruned_image_dir }
    }
    
    pub async fn verify(&self, workload: bedrock_trace::config::WorkloadKind) -> Result<()> {
        println!("Verifying pruned image at {} with workload...", self.pruned_image_dir.display());
        let runner = bedrock_trace::workload::WorkloadRunner::new(workload);
        
        if runner.run().await.is_err() {
            return Err(VerifyError::WorkloadFailed);
        }
        
        println!("Verification passed!");
        Ok(())
    }
}
