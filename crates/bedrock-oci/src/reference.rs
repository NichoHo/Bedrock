use std::path::PathBuf;

#[derive(Debug, Clone)]
pub enum ImageReference {
    Registry { registry: String, repository: String, tag: String },
    OciLayout(PathBuf),
    DockerArchive(PathBuf),
}

impl ImageReference {
    pub fn parse(input: &str) -> Self {
        // Very basic parsing for Phase 0
        let path = PathBuf::from(input);
        if path.exists() {
            if path.is_dir() {
                return ImageReference::OciLayout(path);
            } else if path.extension().is_some_and(|ext| ext == "tar") {
                return ImageReference::DockerArchive(path);
            }
        }

        // registry/repository:tag
        let parts: Vec<&str> = input.split('/').collect();
        let (registry, rest) = if parts.len() > 1
            && (parts[0].contains('.') || parts[0].contains(':') || parts[0] == "localhost")
        {
            (parts[0].to_string(), parts[1..].join("/"))
        } else {
            ("registry-1.docker.io".to_string(), input.to_string())
        };

        let (repository, tag) = if let Some(idx) = rest.find('@') {
            (rest[..idx].to_string(), rest[idx + 1..].to_string())
        } else if let Some(idx) = rest.find(':') {
            (rest[..idx].to_string(), rest[idx + 1..].to_string())
        } else {
            (rest.to_string(), "latest".to_string())
        };

        let repository = if registry == "registry-1.docker.io" && !repository.contains('/') {
            format!("library/{}", repository)
        } else {
            repository
        };

        ImageReference::Registry { registry, repository, tag }
    }
}
