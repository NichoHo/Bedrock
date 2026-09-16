use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct SlsaProvenance {
    #[serde(rename = "buildDefinition")]
    pub build_definition: BuildDefinition,
    #[serde(rename = "runDetails")]
    pub run_details: RunDetails,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BuildDefinition {
    #[serde(rename = "buildType")]
    pub build_type: String,
    #[serde(rename = "externalParameters")]
    pub external_parameters: ExternalParameters,
    #[serde(rename = "resolvedDependencies")]
    pub resolved_dependencies: Vec<ResolvedDependency>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ExternalParameters {
    #[serde(rename = "sourceImage")]
    pub source_image: String,
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
    #[serde(rename = "invocationId")]
    pub invocation_id: String,
    #[serde(rename = "startedOn")]
    pub started_on: String,
    #[serde(rename = "finishedOn")]
    pub finished_on: String,
}
