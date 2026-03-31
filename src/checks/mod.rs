use crate::container::ContainerInfo;
use crate::finding::Finding;

mod privileged;
mod root_user;

pub use privileged::PrivilegedCheck;
pub use root_user::RootUserCheck;

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
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_all_checks_returns_vec_with_all_checks() {
        let checks = all_checks();
        assert_eq!(checks.len(), 2);
        assert!(checks.iter().any(|c| c.name() == "PrivilegedCheck"));
        assert!(checks.iter().any(|c| c.name() == "RootUserCheck"));
    }

    #[test]
    fn test_check_trait_is_object_safe() {
        // Verify that Check can be used as Box<dyn Check>
        fn takes_check(_: Box<dyn Check>) {}
        // This compiles only if Check is object-safe
    }
}
