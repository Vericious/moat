use crate::container::ContainerInfo;
use crate::finding::Finding;

/// Trait for security checks that can be run against containers
pub trait Check: Send + Sync {
    /// Return the name of this check
    fn name(&self) -> &str;

    /// Run this check against a container
    fn run(&self, container: &ContainerInfo) -> Vec<Finding>;
}

/// Return all registered security checks
pub fn all_checks() -> Vec<Box<dyn Check>> {
    // Initially return empty - checks will be registered in future tasks
    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_all_checks_returns_vec() {
        let checks = all_checks();
        assert!(checks.is_empty());
    }

    #[test]
    fn test_check_trait_is_object_safe() {
        // Verify that Check can be used as Box<dyn Check>
        fn takes_check(_: Box<dyn Check>) {}
        // This compiles only if Check is object-safe
    }
}
