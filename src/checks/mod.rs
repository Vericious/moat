use crate::container::ContainerInfo;
use crate::finding::Finding;

mod host_mounts;
mod privileged;
mod root_user;
mod socket_mount;

pub use host_mounts::HostMountsCheck;
pub use privileged::PrivilegedCheck;
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
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_all_checks_returns_vec_with_all_checks() {
        let checks = all_checks();
        assert_eq!(checks.len(), 4);
        assert!(checks.iter().any(|c| c.name() == "PrivilegedCheck"));
        assert!(checks.iter().any(|c| c.name() == "RootUserCheck"));
        assert!(checks.iter().any(|c| c.name() == "SocketMountCheck"));
        assert!(checks.iter().any(|c| c.name() == "HostMountsCheck"));
    }

    #[test]
    fn test_check_trait_is_object_safe() {
        // Verify that Check can be used as Box<dyn Check>
        fn takes_check(_: Box<dyn Check>) {}
        // This compiles only if Check is object-safe
    }
}
