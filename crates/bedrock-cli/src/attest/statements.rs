//! The predicates Bedrock attests (BEDROCK_SPEC.md 5.8).
use crate::report::Report;
use serde_json::{json, Value};

pub const SIGN_TYPE: &str = "https://sigstore.dev/cosign/sign/v1";
pub const SLSA_PROVENANCE: &str = "https://slsa.dev/provenance/v1";
pub const SPDX: &str = "https://spdx.dev/Document";
pub const REPORT: &str = "https://github.com/NichoHo/Bedrock/report/v1";
const BUILD_TYPE: &str = "https://github.com/NichoHo/Bedrock/blob/main/docs/slim.md";
const BUILDER_ID: &str = "https://github.com/NichoHo/Bedrock";

fn hex(digest: &str) -> &str {
    digest.strip_prefix("sha256:").unwrap_or(digest)
}

/// SLSA Provenance v1 for a `slim` run. The builder is Bedrock (version and
/// binary digest); the materials are the input image and the advisory
/// snapshot; the build config is the resolved command line with the digests
/// of the workload and keep-list files. `None` if the report has no build info
/// (it was not produced by `slim`).
pub fn provenance(report: &Report) -> Option<Value> {
    let b = report.build.as_ref()?;
    let digest_of = |d: &Option<String>| d.as_deref().map(|d| json!({ "sha256": hex(d) }));
    let mut dependencies = vec![json!({
        "uri": report.input.reference,
        "digest": { "sha256": hex(&report.input.digest) },
        "name": "input image config",
    })];
    if report.snapshot.digest != "none" {
        dependencies.push(json!({
            "uri": "bedrock:advisory-snapshot",
            "digest": { "sha256": report.snapshot.digest },
        }));
    }
    let mut builder_deps = vec![];
    if let Some(d) = digest_of(&b.bedrock_digest) {
        builder_deps.push(json!({ "uri": "bedrock:executable", "digest": d }));
    }
    Some(json!({
        "buildDefinition": {
            "buildType": BUILD_TYPE,
            "externalParameters": {
                "commandLine": b.command_line,
                "platform": report.input.platform,
                "workload": digest_of(&b.workload_digest),
                "keepList": digest_of(&b.keep_list_digest),
                "granularity": b.granularity,
                "preserveLayers": b.preserve_layers,
                "mandatoryList": b.mandatory,
                "verify": b.verify,
                "allowPartialTrace": b.allow_partial_trace,
            },
            "internalParameters": {},
            "resolvedDependencies": dependencies,
        },
        "runDetails": {
            "builder": {
                "id": BUILDER_ID,
                "version": { "bedrock": report.tool_version },
                "builderDependencies": builder_deps,
            },
            "metadata": { "finishedOn": report.timestamp },
        },
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report::{BuildInfo, ImageSummary, Report, SnapshotRef};

    fn report(build: Option<BuildInfo>) -> Report {
        let input = ImageSummary {
            reference: "py:3".into(),
            digest: "sha256:aaa".into(),
            platform: "linux/amd64".into(),
            size_bytes: 1,
            layers: 1,
            packages: 1,
            findings_by_severity: Default::default(),
        };
        let mut r = Report::new(
            input,
            SnapshotRef { digest: "snap".into(), updated_at: String::new() },
            vec![],
            vec![],
        );
        r.build = build;
        r
    }

    #[test]
    fn provenance_records_materials_builder_and_config() {
        let b = BuildInfo {
            command_line: vec!["bedrock".into(), "slim".into()],
            workload_digest: Some("sha256:w".into()),
            keep_list_digest: None,
            granularity: "package".into(),
            preserve_layers: false,
            mandatory: true,
            verify: true,
            allow_partial_trace: false,
            bedrock_digest: Some("sha256:bin".into()),
        };
        let p = provenance(&report(Some(b))).unwrap();
        let deps = &p["buildDefinition"]["resolvedDependencies"];
        assert_eq!(deps[0]["digest"]["sha256"], "aaa");
        assert_eq!(deps[1]["digest"]["sha256"], "snap");
        assert_eq!(p["buildDefinition"]["externalParameters"]["workload"]["sha256"], "w");
        assert!(p["buildDefinition"]["externalParameters"]["keepList"].is_null());
        assert_eq!(p["runDetails"]["builder"]["builderDependencies"][0]["digest"]["sha256"], "bin");
        assert!(provenance(&report(None)).is_none());
    }
}
