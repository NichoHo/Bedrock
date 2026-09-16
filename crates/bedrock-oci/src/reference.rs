use std::path::PathBuf;

#[derive(Debug, Clone)]
pub enum ImageReference {
    Registry {
        registry: String,
        repository: String,
        tag: String,
    },
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
            } else if path.extension().map_or(false, |ext| ext == "tar") {
                return ImageReference::DockerArchive(path);
            }
        }
        
        // registry/repository:tag
        let parts: Vec<&str> = input.split('/').collect();
        let (registry, rest) = if parts.len() > 1 && (parts[0].contains('.') || parts[0].contains(':') || parts[0] == "localhost") {
            (parts[0].to_string(), parts[1..].join("/"))
        } else {
            ("registry-1.docker.io".to_string(), input.to_string())
        };

        let repo_parts: Vec<&str> = rest.split(':').collect();
        let (repository, tag) = if repo_parts.len() == 2 {
            (repo_parts[0].to_string(), repo_parts[1].to_string())
        } else {
            (rest, "latest".to_string())
        };

        let repository = if registry == "registry-1.docker.io" && !repository.contains('/') {
            format!("library/{}", repository)
        } else {
            repository
        };

        ImageReference::Registry {
            registry,
            repository,
            tag,
        }
    }
}
