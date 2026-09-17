use crate::Result;

pub struct Signer {
    keyless: bool,
}

impl Signer {
    pub fn new(keyless: bool) -> Self {
        Self { keyless }
    }

    pub fn sign_payload(&self, payload: &[u8]) -> Result<String> {
        if self.keyless {
            println!("Requesting keyless signing certificate via OIDC...");
            // Stub for Phase 5: Fulcio/Rekor interactions
        } else {
            println!("Using local key for signing...");
        }

        let b64_payload =
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, payload);

        // Dummy signature for Phase 5 stub
        let signature = format!("sig:{}", b64_payload.chars().take(10).collect::<String>());

        Ok(signature)
    }
}
