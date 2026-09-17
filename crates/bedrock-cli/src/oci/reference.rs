use crate::oci::layout::OciLayout;
use anyhow::{bail, Result};
use std::path::PathBuf;

#[derive(Debug, Clone)]
pub enum ImageReference {
    /// `reference` is a tag ("1.4.2") or a digest ("sha256:...").
    Registry {
        registry: String,
        repository: String,
        reference: String,
    },
    OciLayout(PathBuf),
    DockerArchive(PathBuf),
}

impl ImageReference {
    pub fn parse(input: &str) -> Result<Self> {
        let path = PathBuf::from(input);
        if path.exists() {
            if path.is_dir() {
                if OciLayout::looks_like_layout(&path) {
                    return Ok(ImageReference::OciLayout(path));
                }
                bail!(
                    "{} is a directory but has no `oci-layout` file, so it isn't a valid OCI image layout",
                    path.display()
                );
            } else if path.extension().is_some_and(|ext| ext == "tar") {
                return Ok(ImageReference::DockerArchive(path));
            }
            bail!(
                "{} exists but is neither an OCI layout directory nor a .tar archive",
                path.display()
            );
        }

        // registry/repository:tag or registry/repository@digest
        let parts: Vec<&str> = input.split('/').collect();
        let (registry, rest) = if parts.len() > 1
            && (parts[0].contains('.') || parts[0].contains(':') || parts[0] == "localhost")
        {
            (parts[0].to_string(), parts[1..].join("/"))
        } else {
            ("registry-1.docker.io".to_string(), input.to_string())
        };

        let (repository, reference) = if let Some(at_idx) = rest.find('@') {
            // A digest takes precedence over any accompanying tag: `repo:tag@sha256:...`
            // is fetched by digest, with the tag as documentation only.
            let repo_and_tag = &rest[..at_idx];
            let repository = repo_and_tag.split(':').next().unwrap_or(repo_and_tag);
            (repository.to_string(), rest[at_idx + 1..].to_string())
        } else if let Some(colon_idx) = rest.rfind(':') {
            (rest[..colon_idx].to_string(), rest[colon_idx + 1..].to_string())
        } else {
            (rest.clone(), "latest".to_string())
        };

        let repository = if registry == "registry-1.docker.io" && !repository.contains('/') {
            format!("library/{}", repository)
        } else {
            repository
        };

        Ok(ImageReference::Registry { registry, repository, reference })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_tag_defaults_to_docker_hub_library() {
        let r = ImageReference::parse("alpine").unwrap();
        match r {
            ImageReference::Registry { registry, repository, reference } => {
                assert_eq!(registry, "registry-1.docker.io");
                assert_eq!(repository, "library/alpine");
                assert_eq!(reference, "latest");
            }
            _ => panic!("expected Registry"),
        }
    }

    #[test]
    fn explicit_tag() {
        let r = ImageReference::parse("alpine:3.19").unwrap();
        match r {
            ImageReference::Registry { repository, reference, .. } => {
                assert_eq!(repository, "library/alpine");
                assert_eq!(reference, "3.19");
            }
            _ => panic!("expected Registry"),
        }
    }

    #[test]
    fn tag_and_digest_resolves_by_digest() {
        let r = ImageReference::parse("alpine:3.19@sha256:abcd1234").unwrap();
        match r {
            ImageReference::Registry { repository, reference, .. } => {
                assert_eq!(repository, "library/alpine");
                assert_eq!(reference, "sha256:abcd1234");
            }
            _ => panic!("expected Registry"),
        }
    }

    #[test]
    fn digest_only_no_tag() {
        let r = ImageReference::parse("library/alpine@sha256:abcd1234").unwrap();
        match r {
            ImageReference::Registry { repository, reference, .. } => {
                assert_eq!(repository, "library/alpine");
                assert_eq!(reference, "sha256:abcd1234");
            }
            _ => panic!("expected Registry"),
        }
    }

    #[test]
    fn custom_registry_with_port() {
        let r = ImageReference::parse("localhost:5000/myapp:dev").unwrap();
        match r {
            ImageReference::Registry { registry, repository, reference } => {
                assert_eq!(registry, "localhost:5000");
                assert_eq!(repository, "myapp");
                assert_eq!(reference, "dev");
            }
            _ => panic!("expected Registry"),
        }
    }

    #[test]
    fn directory_without_oci_layout_marker_is_rejected() {
        let dir =
            std::env::temp_dir().join(format!("bedrock-test-not-a-layout-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let result = ImageReference::parse(dir.to_str().unwrap());
        std::fs::remove_dir_all(&dir).ok();
        assert!(result.is_err());
    }
}
