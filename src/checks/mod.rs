use crate::container::ContainerInfo;
use crate::finding::Finding;

pub mod privileged;
pub mod root_user;
pub mod socket_mount;
pub mod host_mounts;
pub mod exposed_ports;
pub mod env_secrets;
pub mod resource_limits;
pub mod health_check;
pub mod host_network;
pub mod image_freshness;

/// Trait for security checks that can be run against containers
pub trait Check: Send + Sync {
    /// Return the name of this check
    fn name(&self) -> &str;

    /// Run the check against a container and return any findings
    fn run(&self, container: &ContainerInfo) -> Vec<Finding>;
}

/// Return all registered security checks
pub fn all_checks() -> Vec<Box<dyn Check>> {
    vec![
        Box::new(privileged::PrivilegedCheck::new()),
        Box::new(root_user::RootUserCheck::new()),
        Box::new(socket_mount::SocketMountCheck::new()),
        Box::new(host_mounts::HostMountsCheck::new()),
        Box::new(exposed_ports::ExposedPortsCheck::new()),
        Box::new(env_secrets::EnvSecretsCheck::new()),
        Box::new(resource_limits::ResourceLimitsCheck::new()),
        Box::new(health_check::HealthCheckCheck::new()),
        Box::new(host_network::HostNetworkCheck::new()),
        Box::new(image_freshness::ImageFreshnessCheck::new()),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    struct DummyCheck;

    impl Check for DummyCheck {
        fn name(&self) -> &str {
            "DummyCheck"
        }

        fn run(&self, _container: &ContainerInfo) -> Vec<Finding> {
            Vec::new()
        }
    }

    #[test]
    fn test_all_checks_returns_ten_checks() {
        let checks = all_checks();
        assert_eq!(checks.len(), 10, "all_checks() should return exactly 10 checks");
    }

    #[test]
    fn test_all_checks_have_unique_names() {
        let checks = all_checks();
        let names: Vec<_> = checks.iter().map(|c| c.name()).collect();
        let unique_names: std::collections::HashSet<_> = names.iter().collect();
        assert_eq!(
            unique_names.len(),
            names.len(),
            "All check names should be unique, got: {:?}",
            names
        );
    }

    #[test]
    fn test_check_trait_is_object_safe() {
        // Verify that Box<dyn Check> can be created - this tests object safety
        let dummy: Box<dyn Check> = Box::new(DummyCheck);
        assert_eq!(dummy.name(), "DummyCheck");
    }

    #[test]
    fn test_dummy_check_runs_without_panic() {
        let dummy: Box<dyn Check> = Box::new(DummyCheck);
        let container_info = ContainerInfo::default();
        let findings = dummy.run(&container_info);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_check_trait_object_safe_with_send() {
        // Verify Check can be used with Box<dyn Check> and is Send
        fn assert_send<T: Send>() {}
        assert_send::<Box<dyn Check>>();
    }

    #[test]
    fn test_check_trait_object_safe_with_sync() {
        // Verify Check can be used with Box<dyn Check> and is Sync
        fn assert_sync<T: Sync>() {}
        assert_sync::<Box<dyn Check>>();
    }
}
