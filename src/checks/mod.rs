use crate::container::ContainerInfo;
use crate::finding::Finding;

mod privileged;

pub use privileged::PrivilegedCheck;

/// Trait for security checks that can be run against containers
pub trait Check: Send + Sync {
    /// Return the name of this check
    fn name(&self) -> &str;

    /// Run this check against a container
    fn run(&self, container: &ContainerInfo) -> Vec<Finding>;
}

/// Return all registered security checks
pub fn all_checks() -> Vec<Box<dyn Check>> {
    vec![Box::new(PrivilegedCheck::new())]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_all_checks_returns_vec_with_privileged_check() {
        let checks = all_checks();
        assert_eq!(checks.len(), 1);
        assert_eq!(checks[0].name(), "PrivilegedCheck");
    }

    #[test]
    fn test_check_trait_is_object_safe() {
        // Verify that Check can be used as Box<dyn Check>
        fn takes_check(_: Box<dyn Check>) {}
        // This compiles only if Check is object-safe
    }
}
