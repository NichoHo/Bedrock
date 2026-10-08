//! One signed statement as an OCI artifact: the statement is wrapped in a DSSE
//! envelope, signed, placed in a Sigstore bundle (v0.3, public-key material),
//! and stored as a manifest whose `subject` is the attested image. This is the
//! layout `cosign` writes and reads with its default (bundle) format.
use super::key::SigningKey;
use crate::oci::manifest::Descriptor;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

pub const PAYLOAD_TYPE: &str = "application/vnd.in-toto+json";
pub const BUNDLE_TYPE: &str = "application/vnd.dev.sigstore.bundle.v0.3+json";
pub const MANIFEST_TYPE: &str = "application/vnd.oci.image.manifest.v1+json";
pub const INDEX_TYPE: &str = "application/vnd.oci.image.index.v1+json";
const EMPTY_TYPE: &str = "application/vnd.oci.empty.v1+json";

/// Everything to store for one artifact.
pub struct Artifact {
    pub predicate_type: String,
    /// (digest, bytes): the empty config and the bundle.
    pub blobs: Vec<(String, Vec<u8>)>,
    pub manifest: Vec<u8>,
    pub manifest_digest: String,
    /// How the referrers index lists it.
    pub descriptor: Value,
}

pub fn sha256_digest(data: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(data)))
}

/// DSSE pre-authentication encoding: what is actually signed.
pub fn pae(payload_type: &str, payload: &[u8]) -> Vec<u8> {
    let mut out =
        format!("DSSEv1 {} {} {} ", payload_type.len(), payload_type, payload.len()).into_bytes();
    out.extend_from_slice(payload);
    out
}

/// An in-toto Statement v1. `name` is omitted when `None`.
pub fn statement(
    name: Option<&str>,
    subject_sha256: &str,
    predicate_type: &str,
    predicate: Value,
) -> Value {
    let mut subject = json!({ "digest": { "sha256": subject_sha256 } });
    if let Some(n) = name {
        subject["name"] = json!(n);
    }
    json!({
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [subject],
        "predicateType": predicate_type,
        "predicate": predicate,
    })
}

/// Signs `statement` and builds the artifact attached to `subject`.
pub fn build(key: &SigningKey, subject: &Descriptor, statement: &Value) -> Artifact {
    let payload = serde_json::to_vec(statement).expect("statement serialises");
    let sig = key.sign(&pae(PAYLOAD_TYPE, &payload));
    let bundle = json!({
        "mediaType": BUNDLE_TYPE,
        "verificationMaterial": { "publicKey": { "hint": key.hint() } },
        "dsseEnvelope": {
            "payload": B64.encode(&payload),
            "payloadType": PAYLOAD_TYPE,
            "signatures": [{ "sig": B64.encode(sig) }],
        },
    });
    let bundle_bytes = serde_json::to_vec(&bundle).expect("bundle serialises");
    let empty = b"{}".to_vec();
    let predicate_type = statement["predicateType"].as_str().unwrap_or_default().to_string();

    let annotations = json!({
        "dev.sigstore.bundle.content": "dsse-envelope",
        "dev.sigstore.bundle.predicateType": predicate_type,
    });
    let manifest = json!({
        "schemaVersion": 2,
        "mediaType": MANIFEST_TYPE,
        "artifactType": BUNDLE_TYPE,
        "config": { "mediaType": EMPTY_TYPE, "digest": sha256_digest(&empty), "size": empty.len() },
        "layers": [{ "mediaType": BUNDLE_TYPE, "digest": sha256_digest(&bundle_bytes), "size": bundle_bytes.len() }],
        "subject": { "mediaType": subject.media_type, "digest": subject.digest, "size": subject.size },
        "annotations": annotations,
    });
    let manifest_bytes = serde_json::to_vec(&manifest).expect("manifest serialises");
    let manifest_digest = sha256_digest(&manifest_bytes);
    let descriptor = json!({
        "mediaType": MANIFEST_TYPE,
        "digest": manifest_digest,
        "size": manifest_bytes.len(),
        "artifactType": BUNDLE_TYPE,
        "annotations": annotations,
    });
    Artifact {
        predicate_type,
        blobs: vec![(sha256_digest(&empty), empty), (sha256_digest(&bundle_bytes), bundle_bytes)],
        manifest: manifest_bytes,
        manifest_digest,
        descriptor,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pae_matches_the_dsse_spec_example() {
        assert_eq!(
            pae("http://example.com/HelloWorld", b"hello world"),
            b"DSSEv1 29 http://example.com/HelloWorld 11 hello world"
        );
    }

    #[test]
    fn artifact_is_signed_deterministic_and_points_at_its_subject() {
        use p256::pkcs8::EncodePrivateKey;
        let secret = p256::SecretKey::from_slice(&[9u8; 32]).unwrap();
        let pem = p256::ecdsa::SigningKey::from(secret).to_pkcs8_pem(Default::default()).unwrap();
        let key = SigningKey::parse(&pem, "").unwrap();
        let subject = Descriptor {
            media_type: MANIFEST_TYPE.into(),
            digest: "sha256:abc".into(),
            size: 123,
            platform: None,
        };
        let st = statement(Some("reg/img"), "abc", "https://example.com/p/v1", json!({"k": 1}));
        let a = build(&key, &subject, &st);
        let b = build(&key, &subject, &st);
        assert_eq!(a.manifest_digest, b.manifest_digest);

        let manifest: Value = serde_json::from_slice(&a.manifest).unwrap();
        assert_eq!(manifest["subject"]["digest"], "sha256:abc");
        assert_eq!(
            manifest["annotations"]["dev.sigstore.bundle.predicateType"],
            "https://example.com/p/v1"
        );

        // The signature in the bundle verifies over the PAE of the payload.
        let bundle: Value = serde_json::from_slice(&a.blobs[1].1).unwrap();
        let env = &bundle["dsseEnvelope"];
        let payload = B64.decode(env["payload"].as_str().unwrap()).unwrap();
        let sig = B64.decode(env["signatures"][0]["sig"].as_str().unwrap()).unwrap();
        assert!(key.verify(&pae(PAYLOAD_TYPE, &payload), &sig));
        assert_eq!(serde_json::from_slice::<Value>(&payload).unwrap(), st);
    }
}
