use bollard::Docker;
use bollard::container::ListContainersOptions;

use crate::checks;
use crate::models::Finding;

/// Run all security checks against running containers.
pub async fn run_scan(filter_container: Option<&str>) -> Result<Vec<Finding>, Box<dyn std::error::Error>> {
    let docker = Docker::connect_with_local_defaults()?;

    // Verify connection
    docker.ping().await?;

    let options = ListContainersOptions::<String> {
        all: false, // only running containers
        ..Default::default()
    };

    let containers = docker.list_containers(Some(options)).await?;
    let mut all_findings = Vec::new();

    for container in &containers {
        let name = container
            .names
            .as_ref()
            .and_then(|n| n.first())
            .map(|n| n.trim_start_matches('/').to_string())
            .unwrap_or_else(|| {
                container
                    .id
                    .as_ref()
                    .map(|id| id[..12].to_string())
                    .unwrap_or_else(|| "unknown".to_string())
            });

        // If filtering to a specific container, skip others
        if let Some(filter) = filter_container {
            if name != filter {
                if let Some(id) = &container.id {
                    if !id.starts_with(filter) {
                        continue;
                    }
                } else {
                    continue;
                }
            }
        }

        // Get detailed container inspection for richer data
        if let Some(id) = &container.id {
            match docker.inspect_container(id, None).await {
                Ok(info) => {
                    let mut findings = checks::run_all_checks(&name, &info);
                    all_findings.append(&mut findings);
                }
                Err(e) => {
                    eprintln!("Warning: could not inspect container {name}: {e}");
                }
            }
        }
    }

    Ok(all_findings)
}
