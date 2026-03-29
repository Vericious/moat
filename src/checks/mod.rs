mod privileged;
mod root_user;
mod socket_mount;

use bollard::models::ContainerInspectResponse;

use crate::models::Finding;

/// Run all registered checks against a single container.
pub fn run_all_checks(container_name: &str, info: &ContainerInspectResponse) -> Vec<Finding> {
    let mut findings = Vec::new();

    // Each check function takes (container_name, info) and returns Vec<Finding>
    findings.extend(privileged::check(container_name, info));
    findings.extend(root_user::check(container_name, info));
    findings.extend(socket_mount::check(container_name, info));

    // TODO: Add remaining checks as they're implemented:
    // - sensitive_mounts
    // - exposed_ports
    // - resource_limits
    // - env_secrets
    // - image_freshness
    // - health_check
    // - host_network

    findings
}
