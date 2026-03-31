use crate::container::ContainerInfo;
use crate::finding::Finding;

mod env_secrets;
mod exposed_ports;
mod host_mounts;
mod privileged;
mod resource_limits;
mod root_user;
mod socket_mount;

pub use env_secrets::EnvSecretsCheck;
pub use exposed_ports::ExposedPortsCheck;
pub use host_mounts::HostMountsCheck;
pub use privileged::PrivilegedCheck;
pub use resource_limits::ResourceLimitsCheck;
pub use root_user::RootUserCheck;
pub use socket_mount::SocketMountCheck;

/// Trait for security checks that can be run against containers
pub trait Check: Send + Sync {
    /// Return the name of this check
    fn name(&self) -> &str;

    /// Run this check against a container
    fn run(&self, container: &ContainerInfo) -> Vec<Finding>;
}

/// Return all registered security checks
pub fn all_checks() -> Vec<Box<dyn Check>> {
    vec![
        Box::new(PrivilegedCheck::new()),
        Box::new(RootUserCheck::new()),
        Box::new(SocketMountCheck::new()),
        Box::new(HostMountsCheck::new()),
        Box::new(ExposedPortsCheck::new()),
        Box::new(ResourceLimitsCheck::new()),
        Box::new(EnvSecretsCheck::new()),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_all_checks_returns_vec_with_all_checks() {
        let checks = all_checks();
        assert_eq!(checks.len(), 7);
        assert!(checks.iter().any(|c| c.name() == "PrivilegedCheck"));
        assert!(checks.iter().any(|c| c.name() == "RootUserCheck"));
        assert!(checks.iter().any(|c| c.name() == "SocketMountCheck"));
        assert!(checks.iter().any(|c| c.name() == "HostMountsCheck"));
        assert!(checks.iter().any(|c| c.name() == "ExposedPortsCheck"));
        assert!(checks.iter().any(|c| c.name() == "ResourceLimitsCheck"));
        assert!(checks.iter().any(|c| c.name() == "EnvSecretsCheck"));
    }

    #[test]
    fn test_check_trait_is_object_safe() {
        // Verify that Check can be used as Box<dyn Check>
        fn takes_check(_: Box<dyn Check>) {}
        // This compiles only if Check is object-safe
    }
}
