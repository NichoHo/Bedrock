//! Signing keys. Accepts what `cosign generate-key-pair` writes (an
//! `ENCRYPTED SIGSTORE PRIVATE KEY`: scrypt plus NaCl secretbox around a PKCS#8
//! ECDSA P-256 key) and plain `PRIVATE KEY` (PKCS#8) or `EC PRIVATE KEY` PEM.
//! Bedrock never stores or generates keys: key custody is yours.
use anyhow::{bail, Context, Result};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use p256::ecdsa::signature::{Signer, Verifier};
use p256::ecdsa::{Signature, SigningKey as EcKey};
use p256::pkcs8::{DecodePrivateKey, EncodePublicKey};
use serde::Deserialize;
use sha2::{Digest, Sha256};

pub struct SigningKey {
    key: EcKey,
}

#[derive(Deserialize)]
struct Envelope {
    kdf: Kdf,
    cipher: Cipher,
    ciphertext: String,
}
#[derive(Deserialize)]
struct Kdf {
    name: String,
    params: KdfParams,
    salt: String,
}
#[derive(Deserialize)]
struct KdfParams {
    #[serde(rename = "N")]
    n: u64,
    r: u32,
    p: u32,
}
#[derive(Deserialize)]
struct Cipher {
    name: String,
    nonce: String,
}

/// `(label, bytes)` of the first PEM block in `text`.
fn pem_block(text: &str) -> Option<(String, Vec<u8>)> {
    let start = text.find("-----BEGIN ")?;
    let rest = &text[start + 11..];
    let (label, rest) = rest.split_once("-----")?;
    let (body, _) = rest.split_once("-----END ")?;
    let joined: String = body.split_whitespace().collect();
    Some((label.to_string(), B64.decode(joined).ok()?))
}

impl SigningKey {
    pub fn parse(pem: &str, password: &str) -> Result<Self> {
        let (label, der) = pem_block(pem).context("not a PEM-encoded key")?;
        let key = match label.as_str() {
            "ENCRYPTED SIGSTORE PRIVATE KEY" => {
                let pkcs8 = decrypt_sigstore(&der, password)?;
                EcKey::from_pkcs8_der(&pkcs8).context("decrypted key is not an ECDSA P-256 key")?
            }
            "PRIVATE KEY" => {
                EcKey::from_pkcs8_der(&der).context("not an ECDSA P-256 PKCS#8 key")?
            }
            "EC PRIVATE KEY" => {
                let secret =
                    p256::SecretKey::from_sec1_der(&der).context("not a P-256 SEC1 key")?;
                EcKey::from(secret)
            }
            other => bail!(
                "unsupported key type {other:?}; use a cosign key pair or an ECDSA P-256 PEM key"
            ),
        };
        Ok(Self { key })
    }

    pub fn load(path: &std::path::Path, password: &str) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read key {}", path.display()))?;
        Self::parse(&text, password)
    }

    /// ECDSA over SHA-256, DER-encoded: what Sigstore verifiers expect.
    /// Deterministic (RFC 6979), so the same input signs to the same bytes.
    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        let sig: Signature = self.key.sign(message);
        sig.to_der().as_bytes().to_vec()
    }

    pub fn verify(&self, message: &[u8], der_signature: &[u8]) -> bool {
        Signature::from_der(der_signature)
            .is_ok_and(|s| self.key.verifying_key().verify(message, &s).is_ok())
    }

    /// DER `SubjectPublicKeyInfo`.
    pub fn public_der(&self) -> Vec<u8> {
        self.key.verifying_key().to_public_key_der().expect("P-256 key encodes").as_bytes().to_vec()
    }

    /// The Sigstore bundle `publicKey.hint`: base64 of the SHA-256 of the public key DER.
    pub fn hint(&self) -> String {
        B64.encode(Sha256::digest(self.public_der()))
    }
}

fn decrypt_sigstore(der: &[u8], password: &str) -> Result<Vec<u8>> {
    use crypto_secretbox::aead::{Aead, KeyInit};
    use crypto_secretbox::{Key, Nonce, XSalsa20Poly1305};
    let env: Envelope = serde_json::from_slice(der).context("malformed encrypted key")?;
    if env.kdf.name != "scrypt" || env.cipher.name != "nacl/secretbox" {
        bail!("unsupported key encryption ({} / {})", env.kdf.name, env.cipher.name);
    }
    if !env.kdf.params.n.is_power_of_two() || env.kdf.params.n < 2 {
        bail!("invalid scrypt cost N={}", env.kdf.params.n);
    }
    let salt = B64.decode(&env.kdf.salt)?;
    let nonce = B64.decode(&env.cipher.nonce)?;
    let ciphertext = B64.decode(&env.ciphertext)?;
    if nonce.len() != 24 {
        bail!("bad secretbox nonce length");
    }
    let params = scrypt::Params::new(
        env.kdf.params.n.trailing_zeros() as u8,
        env.kdf.params.r,
        env.kdf.params.p,
    )
    .map_err(|e| anyhow::anyhow!("invalid scrypt parameters: {e}"))?;
    let mut derived = [0u8; 32];
    scrypt::scrypt(password.as_bytes(), &salt, &params, &mut derived)
        .map_err(|e| anyhow::anyhow!("scrypt failed: {e}"))?;
    XSalsa20Poly1305::new(Key::from_slice(&derived))
        .decrypt(Nonce::from_slice(&nonce), ciphertext.as_ref())
        .map_err(|_| {
            anyhow::anyhow!("could not decrypt the key: wrong password? (set COSIGN_PASSWORD)")
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::pkcs8::EncodePrivateKey;

    fn fresh() -> (EcKey, String) {
        // A fixed scalar keeps the test deterministic without an RNG dependency.
        let secret = p256::SecretKey::from_slice(&[7u8; 32]).unwrap();
        let key = EcKey::from(secret);
        let pem = key.to_pkcs8_pem(Default::default()).unwrap().to_string();
        (key, pem)
    }

    #[test]
    fn plain_pkcs8_signs_and_verifies_deterministically() {
        let (_, pem) = fresh();
        let k = SigningKey::parse(&pem, "").unwrap();
        let sig = k.sign(b"message");
        assert!(k.verify(b"message", &sig));
        assert!(!k.verify(b"other", &sig));
        assert_eq!(sig, k.sign(b"message"));
        assert_eq!(k.hint().len(), 44);
    }

    #[test]
    fn cosign_encrypted_format_round_trips() {
        use crypto_secretbox::aead::{Aead, KeyInit};
        use crypto_secretbox::{Key, Nonce, XSalsa20Poly1305};
        let (key, _) = fresh();
        let pkcs8 = key.to_pkcs8_der().unwrap();
        // Same layout cosign writes, with a cheap scrypt cost for the test.
        let (salt, nonce) = ([1u8; 32], [2u8; 24]);
        let params = scrypt::Params::new(4, 8, 1).unwrap();
        let mut derived = [0u8; 32];
        scrypt::scrypt(b"pw", &salt, &params, &mut derived).unwrap();
        let ct = XSalsa20Poly1305::new(Key::from_slice(&derived))
            .encrypt(Nonce::from_slice(&nonce), pkcs8.as_bytes())
            .unwrap();
        let doc = serde_json::json!({
            "kdf": {"name": "scrypt", "params": {"N": 16, "r": 8, "p": 1}, "salt": B64.encode(salt)},
            "cipher": {"name": "nacl/secretbox", "nonce": B64.encode(nonce)},
            "ciphertext": B64.encode(ct),
        });
        let pem = format!(
            "-----BEGIN ENCRYPTED SIGSTORE PRIVATE KEY-----\n{}\n-----END ENCRYPTED SIGSTORE PRIVATE KEY-----\n",
            B64.encode(serde_json::to_vec(&doc).unwrap())
        );
        let k = SigningKey::parse(&pem, "pw").unwrap();
        assert_eq!(k.public_der(), SigningKey::parse(&fresh().1, "").unwrap().public_der());
        let wrong = SigningKey::parse(&pem, "nope").err().unwrap().to_string();
        assert!(wrong.contains("wrong password"), "{wrong}");
    }

    #[test]
    fn rejects_other_key_types() {
        let pem = "-----BEGIN RSA PRIVATE KEY-----\nAAAA\n-----END RSA PRIVATE KEY-----\n";
        assert!(SigningKey::parse(pem, "").is_err());
        assert!(SigningKey::parse("garbage", "").is_err());
    }
}
