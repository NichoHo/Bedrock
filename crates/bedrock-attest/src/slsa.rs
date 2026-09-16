use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct SlsaProvenance {
    pub buildDefinition: BuildDefinition,
    pub runDetails: RunDetails,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BuildDefinition {
    pub buildType: String,
    pub externalParameters: ExternalParameters,
    pub resolvedDependencies: Vec<ResolvedDependency>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ExternalParameters {
    pub sourceImage: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ResolvedDependency {
    pub uri: String,
    pub digest: std::collections::HashMap<String, String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RunDetails {
    pub builder: Builder,
    pub metadata: Metadata,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Builder {
    pub id: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Metadata {
    pub invocationId: String,
    pub startedOn: String,
    pub finishedOn: String,
}
