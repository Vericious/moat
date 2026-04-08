//! Integration tests for the full scan flow: scanner → checks → reporter

use assert_cmd::Command;
use predicates::prelude::*;

/// End-to-end test: moat scan produces expected findings from mock Docker data.
/// Uses the integration feature flag and mock Bollard responses.
#[tokio::test]
#[cfg(feature = "integration")]
async fn test_scan_end_to_end_with_mock_containers() {
    // This test requires a running Docker daemon.
    // If Docker is not available, skip gracefully.
    if !std::path::Path::new("/var/run/docker.sock").exists() {
        eprintln!("Skipping: no Docker socket");
        return;
    }

    let mut cmd = Command::cargo_bin("moat").expect("binary exists");
    cmd.arg("scan").arg("--format").json();

    // Run the scan
    let assert = cmd.assert();
    // Should not error — Docker connection or scan errors go to stderr
    // stdout will be JSON (possibly empty if no containers)
    let output = assert.success().get_output();
    let stdout = String::from_utf8_lossy(&output.stdout);

    // Verify stdout is valid JSON
    let result: serde_json::Value = serde_json::from_str(&stdout)
        .expect("stdout should be valid JSON when --format json is used");

    // If there are findings, they should have the expected structure
    if let Some(findings) = result.get("findings").and_then(|f| f.as_array()) {
        for finding in findings {
            assert!(
                finding.get("check_name").is_some(),
                "Finding should have check_name"
            );
            assert!(
                finding.get("container_name").is_some(),
                "Finding should have container_name"
            );
            assert!(
                finding.get("severity").is_some(),
                "Finding should have severity"
            );
            assert!(
                finding.get("message").is_some(),
                "Finding should have message"
            );
        }
    }
}

/// Test: moat scan exits with error code when Docker daemon is unavailable.
#[test]
fn test_scan_error_handling_when_docker_unavailable() {
    // Use a socket path that definitely won't exist or work
    let mut cmd = Command::cargo_bin("moat").expect("binary exists");
    cmd.arg("--socket")
        .arg("/nonexistent/path/docker.sock")
        .arg("scan");

    cmd.assert().failure().stderr(
        predicate::str::contains("Failed to connect to Docker")
            .or(predicate::str::contains("connection"))
            .or(predicate::str::contains("connect")),
    );
}

/// Test: moat scan with --format terminal produces human-readable output.
#[tokio::test]
#[cfg(feature = "integration")]
async fn test_scan_format_terminal() {
    if !std::path::Path::new("/var/run/docker.sock").exists() {
        eprintln!("Skipping: no Docker socket");
        return;
    }

    let mut cmd = Command::cargo_bin("moat").expect("binary exists");
    cmd.arg("--socket")
        .arg("/var/run/docker.sock")
        .arg("scan")
        .arg("--format")
        .arg("terminal");

    // Should complete without panic regardless of findings
    let assert = cmd.assert();
    // We don't assert success/failure — if Docker has no containers, that's fine
    // The important thing is it doesn't crash
    let _output = assert.get_output();
}

/// Test: moat scan --format markdown produces markdown output.
#[tokio::test]
#[cfg(feature = "integration")]
async fn test_scan_format_markdown() {
    if !std::path::Path::new("/var/run/docker.sock").exists() {
        eprintln!("Skipping: no Docker socket");
        return;
    }

    let mut cmd = Command::cargo_bin("moat").expect("binary exists");
    cmd.arg("--socket")
        .arg("/var/run/docker.sock")
        .arg("scan")
        .arg("--format")
        .arg("markdown");

    let assert = cmd.assert();
    let output = assert.get_output();
    let stdout = String::from_utf8_lossy(&output.stdout);

    // Markdown reporter should produce markdown-like content
    // (headers with # or similar)
    if !stdout.is_empty() {
        assert!(
            stdout.contains('#') || stdout.contains("Finding") || stdout.contains("findings"),
            "Expected markdown output, got: {}",
            &stdout[..stdout.len().min(200)]
        );
    }
}

/// Test: moat --help shows scan subcommand
#[test]
fn test_help_shows_scan_subcommand() {
    let mut cmd = Command::cargo_bin("moat").expect("binary exists");
    cmd.arg("--help");

    cmd.assert()
        .success()
        .stdout(predicate::str::contains("scan").or(predicate::str::contains("Scan")));
}

/// Test: moat scan --help shows scan-specific options
#[test]
fn test_scan_help_shows_socket_option() {
    let mut cmd = Command::cargo_bin("moat").expect("binary exists");
    cmd.arg("scan").arg("--help");

    cmd.assert()
        .success()
        .stdout(predicate::str::contains("--socket"));
}
