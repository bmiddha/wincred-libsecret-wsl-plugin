//! Platform-independent planning and parsing for the management CLI.
//!
//! Windows registry and process operations live in the binary so this module
//! can be tested without a Windows installation or a real WSL distribution.

use std::cmp::Ordering;

use thiserror::Error;
use uuid::Uuid;

pub const DISTRIBUTION_ENABLEMENT_PREFIX: &str =
    r"Software\wincred-libsecret\WSLPlugin\Distributions\";
pub const DISTRIBUTION_ENABLEMENT_VALUE: &str = "Enabled";
pub const PLUGIN_REGISTRY_PATH: &str = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Lxss\Plugins";
pub const PLUGIN_VALUE_NAME: &str = "wincred-libsecret-wsl-plugin";
pub const PROJECT_MARKER: &str = "X-WinCred-Libsecret=1";
pub const MINIMUM_WSL_VERSION: WslVersion = WslVersion {
    major: 2,
    minor: 5,
    patch: 1,
};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct WslVersion {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
}

impl std::fmt::Display for WslVersion {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum ParseError {
    #[error("WSL version output did not contain a version")]
    NoWslVersion,
    #[error("invalid WSL version '{0}'")]
    InvalidWslVersion(String),
}

#[must_use]
pub fn distribution_registry_path(id: Uuid) -> String {
    format!("{DISTRIBUTION_ENABLEMENT_PREFIX}{{{}}}", id.hyphenated())
}

/// Extracts the `WSL version:` line, accepting localized output only when its
/// value can still be unambiguously recognized as a dotted numeric version.
pub fn parse_wsl_version(output: &str) -> Result<WslVersion, ParseError> {
    for line in output.lines() {
        let normalized_line = line.to_ascii_lowercase();
        if !normalized_line.contains("wsl") || !normalized_line.contains("version") {
            continue;
        }
        let candidate = line
            .split_once(':')
            .map_or(line, |(_, value)| value)
            .trim()
            .trim_start_matches('v');
        if !candidate
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_digit())
        {
            continue;
        }
        let numeric = candidate
            .split_whitespace()
            .next()
            .unwrap_or_default()
            .trim_end_matches(|character: char| !character.is_ascii_digit() && character != '.');
        let components: Vec<_> = numeric.split('.').collect();
        if !(2..=4).contains(&components.len()) {
            continue;
        }
        let parsed: Result<Vec<u32>, _> = components.iter().map(|part| part.parse()).collect();
        if let Ok(parsed) = parsed {
            return Ok(WslVersion {
                major: parsed[0],
                minor: parsed[1],
                patch: *parsed.get(2).unwrap_or(&0),
            });
        }
    }
    Err(ParseError::NoWslVersion)
}

/// Parses `wsl.exe --list --quiet` output without imposing shell token rules
/// on distribution names. A distribution name may contain spaces.
#[must_use]
pub fn parse_wsl_distribution_names(output: &str) -> Vec<String> {
    output
        .lines()
        .map(|line| line.trim_end_matches('\r').trim_start_matches('\u{feff}'))
        .filter(|line| !line.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Conflict {
    pub path: String,
    pub project_owned: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConflictDecision {
    Proceed,
    ReplaceAndBackup,
    Refuse,
}

#[must_use]
pub fn conflict_decision(conflicts: &[Conflict], replace: bool) -> ConflictDecision {
    if conflicts.iter().all(|conflict| conflict.project_owned) {
        ConflictDecision::Proceed
    } else if replace {
        ConflictDecision::ReplaceAndBackup
    } else {
        ConflictDecision::Refuse
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LifecycleState {
    pub enabled: bool,
    pub provisioned: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EnablePlan {
    NoChange,
    ProvisionAndEnable,
    EnableOnly,
}

#[must_use]
pub fn enable_plan(state: LifecycleState) -> EnablePlan {
    match state {
        LifecycleState {
            enabled: true,
            provisioned: true,
        } => EnablePlan::NoChange,
        LifecycleState {
            enabled: false,
            provisioned: true,
        } => EnablePlan::EnableOnly,
        LifecycleState {
            provisioned: false, ..
        } => EnablePlan::ProvisionAndEnable,
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DoctorFinding {
    pub check: &'static str,
    pub ok: bool,
    pub detail: String,
    pub remedy: Option<String>,
}

impl DoctorFinding {
    #[must_use]
    pub fn ok(check: &'static str, detail: impl Into<String>) -> Self {
        Self {
            check,
            ok: true,
            detail: detail.into(),
            remedy: None,
        }
    }

    #[must_use]
    pub fn fail(check: &'static str, detail: impl Into<String>, remedy: impl Into<String>) -> Self {
        Self {
            check,
            ok: false,
            detail: detail.into(),
            remedy: Some(remedy.into()),
        }
    }
}

/// A narrow seam for command, registry, and filesystem actions. Production
/// code implements this with Unicode `Command` arguments and the Windows
/// registry; tests use an in-memory fake.
pub trait ProvisioningSystem {
    type Error;

    fn run(&mut self, program: &str, args: &[String]) -> Result<CommandResult, Self::Error>;
    fn registry_dword(&self, key: &str, value: &str) -> Result<Option<u32>, Self::Error>;
    fn set_registry_dword(&mut self, key: &str, value: &str, data: u32) -> Result<(), Self::Error>;
    fn remove_registry_tree(&mut self, key: &str) -> Result<(), Self::Error>;
    fn file_exists(&self, path: &str) -> Result<bool, Self::Error>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommandResult {
    pub success: bool,
    pub stdout: String,
    pub stderr: String,
}

impl CommandResult {
    #[must_use]
    pub fn success(stdout: impl Into<String>) -> Self {
        Self {
            success: true,
            stdout: stdout.into(),
            stderr: String::new(),
        }
    }
}

#[derive(Debug, Error)]
pub enum ProvisioningError<E: std::error::Error + 'static> {
    #[error("command failed: {0}")]
    Command(String),
    #[error(transparent)]
    System(#[from] E),
}

/// Performs the idempotent final step shared by the Windows implementation:
/// provision first, and only enable the callback after it has succeeded.
pub fn enable_with<S>(
    system: &mut S,
    distribution: &str,
    distribution_id: Uuid,
    provision_args: &[String],
    provisioned_marker: &str,
) -> Result<EnablePlan, ProvisioningError<S::Error>>
where
    S: ProvisioningSystem,
    S::Error: std::error::Error + 'static,
{
    let registry_key = distribution_registry_path(distribution_id);
    let state = LifecycleState {
        enabled: system
            .registry_dword(&registry_key, DISTRIBUTION_ENABLEMENT_VALUE)?
            .is_some_and(|value| value != 0),
        provisioned: system.file_exists(provisioned_marker)?,
    };
    let plan = enable_plan(state);
    if matches!(plan, EnablePlan::ProvisionAndEnable) {
        let result = system.run("wsl.exe", provision_args)?;
        if !result.success {
            return Err(ProvisioningError::Command(format!(
                "could not provision '{distribution}': {}",
                result.stderr.trim()
            )));
        }
    }
    if !matches!(plan, EnablePlan::NoChange) {
        system.set_registry_dword(&registry_key, DISTRIBUTION_ENABLEMENT_VALUE, 1)?;
    }
    Ok(plan)
}

/// Performs the reverse ordering: remove project-owned Linux files first, then
/// remove the exact per-user callback key. Repeating this operation is safe.
pub fn disable_with<S>(
    system: &mut S,
    distribution: &str,
    distribution_id: Uuid,
    disable_args: &[String],
    provisioned_marker: &str,
) -> Result<(), ProvisioningError<S::Error>>
where
    S: ProvisioningSystem,
    S::Error: std::error::Error + 'static,
{
    if system.file_exists(provisioned_marker)? {
        let result = system.run("wsl.exe", disable_args)?;
        if !result.success {
            return Err(ProvisioningError::Command(format!(
                "could not disable '{distribution}': {}",
                result.stderr.trim()
            )));
        }
    }
    system.remove_registry_tree(&distribution_registry_path(distribution_id))?;
    Ok(())
}

#[must_use]
pub fn compare_versions(actual: WslVersion, minimum: WslVersion) -> Ordering {
    actual.cmp(&minimum)
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use super::*;

    #[derive(Debug, Error)]
    #[error("fake error")]
    struct FakeError;

    #[derive(Default)]
    struct FakeSystem {
        commands: Vec<(String, Vec<String>)>,
        registry: BTreeMap<(String, String), u32>,
        files: BTreeSet<String>,
    }

    impl ProvisioningSystem for FakeSystem {
        type Error = FakeError;

        fn run(&mut self, program: &str, args: &[String]) -> Result<CommandResult, Self::Error> {
            self.commands.push((program.to_owned(), args.to_vec()));
            Ok(CommandResult::success(""))
        }

        fn registry_dword(&self, key: &str, value: &str) -> Result<Option<u32>, Self::Error> {
            Ok(self
                .registry
                .get(&(key.to_owned(), value.to_owned()))
                .copied())
        }

        fn set_registry_dword(
            &mut self,
            key: &str,
            value: &str,
            data: u32,
        ) -> Result<(), Self::Error> {
            self.registry
                .insert((key.to_owned(), value.to_owned()), data);
            Ok(())
        }

        fn remove_registry_tree(&mut self, key: &str) -> Result<(), Self::Error> {
            self.registry.retain(|(existing, _), _| existing != key);
            Ok(())
        }

        fn file_exists(&self, path: &str) -> Result<bool, Self::Error> {
            Ok(self.files.contains(path))
        }
    }

    #[test]
    fn uses_the_exact_plugin_enablement_key() {
        let id = Uuid::parse_str("01234567-89ab-cdef-0123-456789abcdef").unwrap();
        assert_eq!(
            distribution_registry_path(id),
            r"Software\wincred-libsecret\WSLPlugin\Distributions\{01234567-89ab-cdef-0123-456789abcdef}"
        );
    }

    #[test]
    fn parses_versions_and_requires_the_plugin_minimum() {
        assert_eq!(
            parse_wsl_version("WSL version: 2.5.1.0\nKernel version: 6.6").unwrap(),
            MINIMUM_WSL_VERSION
        );
        assert_eq!(
            compare_versions(
                parse_wsl_version("WSL version: 2.5.0\n").unwrap(),
                MINIMUM_WSL_VERSION
            ),
            Ordering::Less
        );
        assert_eq!(
            parse_wsl_version("Kernel version: 6.6").unwrap_err(),
            ParseError::NoWslVersion
        );
    }

    #[test]
    fn preserves_names_with_spaces_from_wsl_output() {
        assert_eq!(
            parse_wsl_distribution_names("\u{feff}Ubuntu 24.04\r\nArch Linux\r\n\r\n"),
            ["Ubuntu 24.04", "Arch Linux"]
        );
    }

    #[test]
    fn conflict_replacement_requires_an_explicit_opt_in() {
        let other = [Conflict {
            path: "/usr/share/dbus-1/services/org.freedesktop.secrets.service".to_owned(),
            project_owned: false,
        }];
        assert_eq!(conflict_decision(&other, false), ConflictDecision::Refuse);
        assert_eq!(
            conflict_decision(&other, true),
            ConflictDecision::ReplaceAndBackup
        );
        assert_eq!(
            conflict_decision(
                &[Conflict {
                    path: "/usr/share/dbus-1/services/org.freedesktop.secrets.service".to_owned(),
                    project_owned: true,
                }],
                false,
            ),
            ConflictDecision::Proceed
        );
    }

    #[test]
    fn enable_is_idempotent_and_provisions_before_registry_enablement() {
        let id = Uuid::parse_str("01234567-89ab-cdef-0123-456789abcdef").unwrap();
        let key = distribution_registry_path(id);
        let arguments = vec![
            "-d".to_owned(),
            "Ubuntu with spaces".to_owned(),
            "-u".to_owned(),
            "root".to_owned(),
        ];
        let mut fake = FakeSystem::default();
        let result = enable_with(
            &mut fake,
            "Ubuntu with spaces",
            id,
            &arguments,
            "/installed",
        )
        .unwrap();
        assert_eq!(result, EnablePlan::ProvisionAndEnable);
        assert_eq!(fake.commands, [("wsl.exe".to_owned(), arguments.clone())]);
        assert_eq!(
            fake.registry
                .get(&(key.clone(), DISTRIBUTION_ENABLEMENT_VALUE.to_owned())),
            Some(&1)
        );

        fake.files.insert("/installed".to_owned());
        let result = enable_with(
            &mut fake,
            "Ubuntu with spaces",
            id,
            &arguments,
            "/installed",
        )
        .unwrap();
        assert_eq!(result, EnablePlan::NoChange);
        assert_eq!(fake.commands.len(), 1);
    }

    #[test]
    fn disable_is_idempotent_and_removes_the_exact_enablement_key() {
        let id = Uuid::parse_str("01234567-89ab-cdef-0123-456789abcdef").unwrap();
        let key = distribution_registry_path(id);
        let mut fake = FakeSystem::default();
        fake.files.insert("/installed".to_owned());
        fake.registry
            .insert((key.clone(), DISTRIBUTION_ENABLEMENT_VALUE.to_owned()), 1);
        let arguments = vec![
            "-d".to_owned(),
            "Ubuntu with spaces".to_owned(),
            "-u".to_owned(),
            "root".to_owned(),
            "--disable".to_owned(),
        ];

        disable_with(
            &mut fake,
            "Ubuntu with spaces",
            id,
            &arguments,
            "/installed",
        )
        .unwrap();
        assert_eq!(fake.commands, [("wsl.exe".to_owned(), arguments)]);
        assert!(
            !fake
                .registry
                .contains_key(&(key.clone(), DISTRIBUTION_ENABLEMENT_VALUE.to_owned()))
        );

        fake.files.clear();
        disable_with(
            &mut fake,
            "Ubuntu with spaces",
            id,
            &["--disable".to_owned()],
            "/installed",
        )
        .unwrap();
        assert_eq!(fake.commands.len(), 1);
    }

    #[test]
    fn doctor_findings_are_actionable_without_secrets() {
        let finding = DoctorFinding::fail(
            "systemd",
            "systemd is not PID 1",
            "Enable systemd in /etc/wsl.conf and restart the distribution.",
        );
        assert!(!finding.ok);
        assert!(finding.remedy.unwrap().contains("wsl.conf"));
        assert!(!finding.detail.contains("password"));
    }
}
