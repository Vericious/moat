use crate::checks::Check;
use crate::container::ContainerInfo;
use crate::finding::{Finding, Severity};

/// Check whether a container image is using the 'latest' tag (anti-pattern)
pub struct ImageFreshnessCheck;

impl ImageFreshnessCheck {
    pub fn new() -> Self {
        ImageFreshnessCheck
    }
}

impl Default for ImageFreshnessCheck {
    fn default() -> Self {
        Self::new()
    }
}

/// Returns true if the image name ends with ':latest'
fn is_latest_tag(image: &str) -> bool {
    // Handle cases like "nginx:latest", "my-registry.com/app:linux/latest"
    // We need to check if the tag part is specifically "latest"
    if let Some(colon_pos) = image.rfind(':') {
        let tag = &image[colon_pos + 1..];
        // "latest" tag or no explicit tag (defaults to latest)
        tag.eq_ignore_ascii_case("latest")
    } else {
        // No tag specified — Docker defaults to 'latest'
        true
    }
}

impl Check for ImageFreshnessCheck {
    fn name(&self) -> &str {
        "ImageFreshnessCheck"
    }

    fn run(&self, container: &ContainerInfo) -> Vec<Finding> {
        if is_latest_tag(&container.image) {
            vec![Finding::new(
                self.name().to_string(),
                container.name.clone(),
                Severity::Low,
                format!(
                    "Container '{}' is using the 'latest' tag for image '{}'",
                    container.name, container.image
                ),
                Some("Pin the image to a specific version tag (e.g., nginx:1.25.0) for reproducible deployments".to_string()),
            )]
        } else {
            Vec::new()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::container::ContainerInfo;

    fn make_container(image: &str) -> ContainerInfo {
        ContainerInfo {
            name: "test-container".to_string(),
            image: image.to_string(),
            ..Default::default()
        }
    }

    #[test]
    fn test_latest_tag_produces_finding() {
        let check = ImageFreshnessCheck::new();
        let findings = check.run(&make_container("nginx:latest"));
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Low);
    }

    #[test]
    fn test_version_tag_produces_no_finding() {
        let check = ImageFreshnessCheck::new();
        let findings = check.run(&make_container("nginx:1.25.0"));
        assert!(findings.is_empty());
    }

    #[test]
    fn test_no_tag_produces_finding() {
        let check = ImageFreshnessCheck::new();
        // No tag = defaults to latest in Docker
        let findings = check.run(&make_container("nginx"));
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn test_sha_reference_produces_no_finding() {
        let check = ImageFreshnessCheck::new();
        let findings = check.run(&make_container("nginx@sha256:abc123"));
        assert!(findings.is_empty());
    }

    #[test]
    fn test_case_insensitive_latest() {
        let check = ImageFreshnessCheck::new();
        let findings = check.run(&make_container("nginx:LATEST"));
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn test_registry_with_latest() {
        let check = ImageFreshnessCheck::new();
        let findings = check.run(&make_container("my-registry.com/app:latest"));
        assert_eq!(findings.len(), 1);
    }
}
