#![cfg(windows)]

use std::process::Command;

/// This test is deliberately opt-in and does not modify WSL, the registry, or
/// any distribution. It verifies the host-side command contract used by the
/// provisioning CLI on a real WSL installation.
#[test]
#[ignore = "requires a local WSL installation and WINCRED_WSL_INTEGRATION=1"]
fn wsl_version_command_is_non_destructive() {
    assert_eq!(
        std::env::var("WINCRED_WSL_INTEGRATION").as_deref(),
        Ok("1"),
        "set WINCRED_WSL_INTEGRATION=1 to run this integration test"
    );
    let output = Command::new("wsl.exe")
        .arg("--version")
        .output()
        .expect("wsl.exe should be available");
    assert!(output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stdout)
            .to_ascii_lowercase()
            .contains("version")
    );
}
