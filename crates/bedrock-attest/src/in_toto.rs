use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct Statement<T> {
    #[serde(rename = "_type")]
    pub _type: String,
    pub subject: Vec<Subject>,
    #[serde(rename = "predicateType")]
    pub predicate_type: String,
    pub predicate: T,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Subject {
    pub name: String,
    pub digest: Digest,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Digest {
    pub sha256: String,
}

impl<T> Statement<T> {
    pub fn new(
        subject_name: String,
        subject_digest: String,
        predicate_type: String,
        predicate: T,
    ) -> Self {
        Self {
            _type: "https://in-toto.io/Statement/v1".to_string(),
            subject: vec![Subject {
                name: subject_name,
                digest: Digest { sha256: subject_digest },
            }],
            predicate_type,
            predicate,
        }
    }
}
