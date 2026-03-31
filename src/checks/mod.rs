use crate::container::ContainerInfo;
use crate::finding::Finding;

pub mod privileged;

/// Trait for security checks that can be run against containers
pub trait Check: Send + Sync {
    /// Return the name of this check
    fn name(&self) -> &str;

    /// Run the check against a container and return any findings
    fn run(&self, container: &ContainerInfo) -> Vec<Finding>;
}

/// Return all registered security checks
pub fn all_checks() -> Vec<Box<dyn Check>> {
    // Initially empty - checks will be registered here as they are implemented
    Vec::new()
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
    fn test_all_checks_returns_vec() {
        let checks = all_checks();
        assert!(checks.is_empty());
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
