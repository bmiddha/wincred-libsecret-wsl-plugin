#![cfg_attr(not(windows), allow(dead_code))]

use std::{
    ffi::OsString,
    fmt::Write,
    fs, io,
    mem::size_of,
    path::{Path, PathBuf},
    process::{Command, Output},
};

use anyhow::{Context, Result, anyhow, bail, ensure};
use clap::{Args, Parser, Subcommand};
use sha2::{Digest, Sha256};
use uuid::Uuid;
use wincred_libsecret::{
    DISTRIBUTION_ENABLEMENT_VALUE, DoctorFinding, MINIMUM_WSL_VERSION, PLUGIN_REGISTRY_PATH,
    PLUGIN_VALUE_NAME, WslVersion, compare_versions, distribution_registry_path,
    parse_wsl_distribution_names, parse_wsl_version,
};
use wincred_libsecret_protocol::PROTOCOL_VERSION;

#[cfg(windows)]
use std::os::windows::ffi::{OsStrExt, OsStringExt};

#[cfg(windows)]
use windows::{
    Win32::{
        Foundation::HWND,
        Security::WinTrust::{
            WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_DATA, WINTRUST_DATA_0, WINTRUST_FILE_INFO,
            WTD_CHOICE_FILE, WTD_REVOKE_WHOLECHAIN, WTD_STATEACTION_CLOSE, WTD_STATEACTION_VERIFY,
            WTD_UI_NONE, WinVerifyTrustEx,
        },
    },
    core::PCWSTR,
};

#[cfg(windows)]
use winreg::{
    RegKey,
    enums::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_READ, KEY_WRITE},
};

const LINUX_PAYLOAD_MANIFEST: &str = "manifest.sha256";
const LINUX_BOOTSTRAP: &str = "wincred-libsecret-bootstrap.sh";
const LINUX_STATUS_HELPER: &str = "/usr/libexec/wincred-libsecret/wincred-libsecret-refresh";
const PLUGIN_DLL_NAME: &str = "wincred-libsecret-wsl-plugin.dll";

#[derive(Debug, Parser)]
#[command(
    name = "wincred-libsecret",
    about = "Install and diagnose the WinCred WSL Secret Service integration",
    version
)]
struct Cli {
    #[command(subcommand)]
    command: TopLevelCommand,
}

#[derive(Debug, Subcommand)]
enum TopLevelCommand {
    /// Manage the machine-wide WSL plugin registration.
    Plugin {
        #[command(subcommand)]
        command: PluginCommand,
    },
    /// Provision and enable the provider in a WSL distribution.
    Distro {
        #[command(subcommand)]
        command: DistroCommand,
    },
    /// Report non-secret readiness diagnostics.
    Doctor(DoctorArguments),
}

#[derive(Debug, Subcommand)]
enum PluginCommand {
    /// Add this project's DLL registry value without replacing another value.
    Install(PluginInstallArguments),
    /// Remove only this project's DLL registry value.
    Uninstall(PluginUninstallArguments),
    /// Show the project DLL registry value and its signature status.
    Status,
}

#[derive(Debug, Args)]
struct PluginUninstallArguments {
    /// Remove the value only when it still names this absolute DLL path.
    ///
    /// Package uninstall uses this guard so it cannot remove a value that was
    /// changed by another administrator after this product was installed.
    #[arg(long)]
    dll: Option<PathBuf>,
    #[command(flatten)]
    restart: RestartArguments,
}

#[derive(Debug, Args)]
struct PluginInstallArguments {
    /// Absolute path to wincred-libsecret-wsl-plugin.dll.
    #[arg(long)]
    dll: PathBuf,
    /// Permit a non-Valid Authenticode result for local development builds.
    #[arg(long)]
    allow_unsigned: bool,
    #[command(flatten)]
    restart: RestartArguments,
}

#[derive(Debug, Args, Default)]
struct RestartArguments {
    /// Stop and start wslservice after changing plugin registration.
    #[arg(long)]
    restart_wslservice: bool,
}

#[derive(Debug, Subcommand)]
enum DistroCommand {
    /// Verify prerequisites, atomically install the provider, then enable it.
    Enable(DistroEnableArguments),
    /// Disable the callback and remove only project-owned distribution files.
    Disable(DistroNameArguments),
    /// List registered distributions and their enablement/provisioning state.
    List,
}

#[derive(Debug, Args)]
struct DistroNameArguments {
    /// Exact WSL distribution name; names containing spaces are supported.
    name: String,
}

#[derive(Debug, Args)]
struct DistroEnableArguments {
    /// Exact WSL distribution name; names containing spaces are supported.
    name: String,
    /// Directory containing the versioned Linux payload and manifest.
    #[arg(long)]
    payload_root: Option<PathBuf>,
    /// Absolute Windows path to wincred-libsecret-broker.exe.
    #[arg(long)]
    broker: Option<PathBuf>,
    /// Back up and replace an existing Secret Service activation definition.
    #[arg(long)]
    replace_conflicts: bool,
}

#[derive(Debug, Args)]
struct DoctorArguments {
    /// Diagnose one distribution; otherwise diagnose all registered distributions.
    #[arg(long)]
    distro: Option<String>,
}

#[derive(Clone, Debug)]
struct Distribution {
    id: Uuid,
    name: String,
    version: Option<u32>,
}

#[cfg(windows)]
#[derive(Debug)]
struct DistributionDiagnostics {
    name: String,
    enabled: Option<bool>,
    wsl2: bool,
    runtime_ok: bool,
    findings: Vec<DoctorFinding>,
}

#[cfg(windows)]
impl DistributionDiagnostics {
    fn state(&self) -> &'static str {
        match self.enabled {
            Some(true) if self.wsl2 && self.runtime_ok => "enabled, working",
            Some(true) => "enabled, degraded",
            Some(false) => "disabled",
            None => "enablement unknown",
        }
    }
}

#[derive(Clone, Debug)]
struct ProcessResult {
    success: bool,
    stdout: String,
    stderr: String,
}

impl ProcessResult {
    fn display_error(&self) -> String {
        let text = if self.stderr.trim().is_empty() {
            self.stdout.trim()
        } else {
            self.stderr.trim()
        };
        if text.is_empty() {
            "command returned a non-zero exit status".to_owned()
        } else {
            text.to_owned()
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SignatureStatus {
    Valid,
    NotValid,
}

impl std::fmt::Display for SignatureStatus {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Valid => formatter.write_str("Valid"),
            Self::NotValid => formatter.write_str("not valid"),
        }
    }
}

fn main() {
    #[cfg(not(windows))]
    {
        eprintln!("wincred-libsecret is a Windows management CLI.");
        std::process::exit(1);
    }

    #[cfg(windows)]
    {
        if let Err(error) = run(Cli::parse()) {
            eprintln!("error: {error:#}");
            std::process::exit(1);
        }
    }
}

#[cfg(windows)]
fn run(cli: Cli) -> Result<()> {
    match cli.command {
        TopLevelCommand::Plugin { command } => match command {
            PluginCommand::Install(arguments) => plugin_install(&arguments),
            PluginCommand::Uninstall(arguments) => plugin_uninstall(&arguments),
            PluginCommand::Status => {
                print_plugin_status()?;
                Ok(())
            }
        },
        TopLevelCommand::Distro { command } => match command {
            DistroCommand::Enable(arguments) => distro_enable(&arguments),
            DistroCommand::Disable(arguments) => distro_disable(&arguments),
            DistroCommand::List => distro_list(),
        },
        TopLevelCommand::Doctor(arguments) => doctor(arguments),
    }
}

#[cfg(windows)]
fn plugin_install(arguments: &PluginInstallArguments) -> Result<()> {
    require_administrator()?;
    let dll = validate_plugin_dll(&arguments.dll)?;
    let signature = signature_status(&dll);
    if signature != SignatureStatus::Valid && !arguments.allow_unsigned {
        bail!(
            "DLL signature is {signature}; refuse to register it. Use a signed release or \
             pass --allow-unsigned only for a local development build."
        );
    }

    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let (plugins, _) = hklm
        .create_subkey(PLUGIN_REGISTRY_PATH)
        .context("could not open the WSL plugin registry key")?;
    let existing: Option<String> = registry_string(&plugins, PLUGIN_VALUE_NAME)?;
    let dll_text = dll
        .to_str()
        .ok_or_else(|| anyhow!("plugin DLL path is not valid Unicode"))?
        .to_owned();
    match existing {
        Some(existing) if windows_paths_equal(Path::new(&existing), &dll) => {
            if existing != dll_text {
                plugins
                    .set_value(PLUGIN_VALUE_NAME, &dll_text)
                    .context("could not normalize the WSL plugin DLL value")?;
            }
            println!("Plugin is already registered: {dll_text}");
        }
        Some(existing) => {
            bail!(
                "refusing to overwrite {PLUGIN_VALUE_NAME} at {}. Remove or inspect the \
                 existing project value first.",
                Path::new(&existing).display()
            );
        }
        None => {
            plugins
                .set_value(PLUGIN_VALUE_NAME, &dll_text)
                .context("could not write the WSL plugin DLL value")?;
            println!("Registered plugin DLL: {dll_text}");
        }
    }
    restart_or_instruct(&arguments.restart)
}

#[cfg(windows)]
fn plugin_uninstall(arguments: &PluginUninstallArguments) -> Result<()> {
    require_administrator()?;
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let plugins = match hklm.open_subkey_with_flags(PLUGIN_REGISTRY_PATH, KEY_READ | KEY_WRITE) {
        Ok(key) => key,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            println!("Project plugin registry value is already absent.");
            return restart_or_instruct(&arguments.restart);
        }
        Err(error) => return Err(error).context("could not open the WSL plugin registry key"),
    };
    match registry_string(&plugins, PLUGIN_VALUE_NAME)? {
        Some(value) => {
            if let Some(expected_dll) = &arguments.dll {
                let expected = expected_dll
                    .to_str()
                    .ok_or_else(|| anyhow!("expected plugin DLL path is not valid Unicode"))?;
                if !windows_paths_equal(Path::new(&value), Path::new(expected)) {
                    println!(
                        "Preserved plugin registration because it no longer points to this product DLL: {value}"
                    );
                    return restart_or_instruct(&arguments.restart);
                }
            }
            plugins
                .delete_value(PLUGIN_VALUE_NAME)
                .context("could not remove the project plugin value")?;
            println!("Removed project plugin registration: {value}");
        }
        None => println!("Project plugin registry value is already absent."),
    }
    restart_or_instruct(&arguments.restart)
}

#[cfg(windows)]
fn restart_or_instruct(arguments: &RestartArguments) -> Result<()> {
    if !arguments.restart_wslservice {
        println!(
            "Restart wslservice (or restart WSL) before opening a new distribution. \
             Re-run with --restart-wslservice to do this now."
        );
        return Ok(());
    }

    let stop = run_process("sc.exe", &["stop".into(), "wslservice".into()])?;
    if !stop.success && !stop.stdout.contains("1062") {
        bail!("could not stop wslservice: {}", stop.display_error());
    }
    let start = run_process("sc.exe", &["start".into(), "wslservice".into()])?;
    if !start.success && !start.stdout.contains("1056") {
        bail!("could not start wslservice: {}", start.display_error());
    }
    println!("Requested a safe wslservice restart.");
    Ok(())
}

#[cfg(windows)]
fn print_plugin_status() -> Result<()> {
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let plugins = match hklm.open_subkey_with_flags(PLUGIN_REGISTRY_PATH, KEY_READ) {
        Ok(key) => key,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            println!("plugin: not registered (WSL plugin registry key is absent)");
            return Ok(());
        }
        Err(error) => return Err(error).context("could not read the WSL plugin registry key"),
    };
    let Some(path) = registry_string(&plugins, PLUGIN_VALUE_NAME)? else {
        println!("plugin: not registered");
        return Ok(());
    };
    let path = PathBuf::from(path);
    let exists = path.is_file();
    let absolute = path.is_absolute();
    let signature = if exists {
        signature_status(&path).to_string()
    } else {
        "not checked (file is absent)".to_owned()
    };
    println!("plugin: registered");
    println!("  value: {PLUGIN_VALUE_NAME}");
    println!("  path: {}", path.display());
    println!("  absolute: {absolute}");
    println!("  exists: {exists}");
    println!("  signature: {signature}");
    Ok(())
}

#[cfg(windows)]
fn distro_enable(arguments: &DistroEnableArguments) -> Result<()> {
    check_wsl_version()?;
    let distribution = find_distribution(&arguments.name)?;
    ensure!(
        distribution.version == Some(2),
        "'{}' is WSL{}; WinCred requires a WSL 2 distribution",
        distribution.name,
        distribution.version.map_or_else(
            || " with unknown version".to_owned(),
            |version| version.to_string()
        )
    );

    let payload_argument = arguments
        .payload_root
        .clone()
        .unwrap_or_else(default_payload_root);
    let payload_root = absolute_existing_directory(&payload_argument, "Linux payload root")?;
    verify_payload(&payload_root)?;
    let broker_argument = arguments.broker.clone().unwrap_or_else(default_broker_path);
    let broker = validate_broker(&broker_argument)?;
    let source = wsl_path(&distribution.name, &payload_root)?;
    let broker_wsl = wsl_path(&distribution.name, &broker)?;
    let bootstrap = format!("{source}/{LINUX_BOOTSTRAP}");

    let mut common_arguments = vec![
        OsString::from(&bootstrap),
        OsString::from("--source"),
        OsString::from(&source),
        OsString::from("--broker"),
        OsString::from(&broker_wsl),
        OsString::from("--protocol"),
        OsString::from(PROTOCOL_VERSION.to_string()),
        OsString::from("--version"),
        OsString::from(env!("CARGO_PKG_VERSION")),
    ];
    if arguments.replace_conflicts {
        common_arguments.push(OsString::from("--replace-conflicts"));
    }

    let mut preflight = common_arguments.clone();
    preflight.push(OsString::from("--check"));
    ensure_wsl_success(
        &distribution.name,
        &preflight,
        "distribution prerequisite/conflict check",
    )?;

    let mut install = common_arguments;
    install.push(OsString::from("--install"));
    ensure_wsl_success(&distribution.name, &install, "atomic provider installation")?;

    set_distribution_enabled(distribution.id, true)?;
    println!(
        "Enabled WinCred Secret Service for '{}' ({}).",
        distribution.name, distribution.id
    );
    Ok(())
}

#[cfg(windows)]
fn distro_disable(arguments: &DistroNameArguments) -> Result<()> {
    let distribution = find_distribution(&arguments.name)?;
    let helper_check = run_wsl_root(
        &distribution.name,
        &[
            OsString::from("/usr/bin/test"),
            OsString::from("-x"),
            OsString::from(LINUX_STATUS_HELPER),
        ],
    )?;
    if !helper_check.success
        && (!helper_check.stdout.trim().is_empty() || !helper_check.stderr.trim().is_empty())
    {
        bail!(
            "could not inspect project files in '{}': {}",
            distribution.name,
            helper_check.display_error()
        );
    }
    if !helper_check.success {
        set_distribution_enabled(distribution.id, false)?;
        println!(
            "Disabled WinCred Secret Service for '{}'; no project payload was present and the Windows Credential Manager vault was not modified.",
            distribution.name
        );
        return Ok(());
    }
    let result = run_wsl_root(
        &distribution.name,
        &[
            OsString::from(LINUX_STATUS_HELPER),
            OsString::from("--disable"),
        ],
    )?;
    if !result.success {
        bail!(
            "could not remove project-owned files from '{}': {}",
            distribution.name,
            result.display_error()
        );
    }
    set_distribution_enabled(distribution.id, false)?;
    println!(
        "Disabled WinCred Secret Service for '{}'; the Windows Credential Manager vault was not modified.",
        distribution.name
    );
    Ok(())
}

#[cfg(windows)]
fn distro_list() -> Result<()> {
    let distributions = enumerate_distributions()?;
    if distributions.is_empty() {
        println!("No WSL distributions are registered for this Windows user.");
        return Ok(());
    }
    for distribution in distributions {
        let enabled = distribution_enabled(distribution.id)?;
        let remote = remote_status(&distribution.name);
        let provisioned = remote
            .as_ref()
            .is_ok_and(|result| result.success && result.stdout.contains("provisioned=true"));
        let reported_conflict = remote.as_ref().ok().and_then(|result| {
            result
                .success
                .then(|| result.stdout.contains("conflict=true"))
        });
        let conflict = reported_conflict
            .or_else(|| common_service_conflict(&distribution.name).ok().flatten())
            .map_or_else(|| "unknown".to_owned(), |value| value.to_string());
        println!(
            "{}\n  guid: {}\n  WSL version: {}\n  enabled: {}\n  provisioned: {}\n  conflict: {}",
            distribution.name,
            distribution.id,
            distribution
                .version
                .map_or_else(|| "unknown".to_owned(), |version| version.to_string()),
            enabled,
            provisioned,
            conflict
        );
    }
    Ok(())
}

#[cfg(windows)]
fn common_service_conflict(distribution: &str) -> Result<Option<bool>> {
    const SERVICE: &str = "org.freedesktop.secrets.service";
    for directory in [
        "/usr/share/dbus-1/services",
        "/etc/xdg/dbus-1/services",
        "/usr/local/share/dbus-1/services",
        "/root/.local/share/dbus-1/services",
    ] {
        let result = run_wsl_root(
            distribution,
            &[
                OsString::from("/usr/bin/test"),
                OsString::from("-e"),
                OsString::from(format!("{directory}/{SERVICE}")),
            ],
        )?;
        if result.success {
            return Ok(Some(true));
        }
        if !result.stdout.trim().is_empty() || !result.stderr.trim().is_empty() {
            return Err(anyhow!(result.display_error()));
        }
    }

    let home_exists = run_wsl_root(
        distribution,
        &[
            OsString::from("/usr/bin/test"),
            OsString::from("-d"),
            OsString::from("/home"),
        ],
    )?;
    if !home_exists.success {
        return Ok(Some(false));
    }
    let result = run_wsl_root(
        distribution,
        &[
            OsString::from("/usr/bin/find"),
            OsString::from("/home"),
            OsString::from("-path"),
            OsString::from(format!("*/.local/share/dbus-1/services/{SERVICE}")),
            OsString::from("-type"),
            OsString::from("f"),
            OsString::from("-print"),
        ],
    )?;
    ensure!(
        result.success,
        "could not inspect common user D-Bus service definitions: {}",
        result.display_error()
    );
    Ok(Some(!result.stdout.is_empty()))
}

#[cfg(windows)]
fn doctor(arguments: DoctorArguments) -> Result<()> {
    let mut findings = Vec::new();
    findings.push(wsl_version_finding());
    findings.extend(plugin_findings()?);
    let distributions = if let Some(name) = arguments.distro {
        vec![find_distribution(&name)?]
    } else {
        enumerate_distributions()?
    };
    let distributions = distributions
        .iter()
        .map(distribution_findings)
        .collect::<Vec<_>>();

    let failures = findings
        .iter()
        .chain(
            distributions
                .iter()
                .flat_map(|distribution| distribution.findings.iter()),
        )
        .filter(|finding| !finding.ok)
        .count();
    print!("{}", format_doctor_report(&findings, &distributions));
    if failures > 0 {
        bail!("{failures} diagnostic check(s) failed");
    }
    Ok(())
}

#[cfg(windows)]
fn wsl_version_finding() -> DoctorFinding {
    match check_wsl_version() {
        Ok(version) => DoctorFinding::ok("wsl-version", format!("WSL {version}")),
        Err(error) => DoctorFinding::fail(
            "wsl-version",
            error.to_string(),
            "Install or update WSL to version 2.5.1 or newer.",
        ),
    }
}

#[cfg(windows)]
fn plugin_findings() -> Result<Vec<DoctorFinding>> {
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let plugins = match hklm.open_subkey_with_flags(PLUGIN_REGISTRY_PATH, KEY_READ) {
        Ok(key) => key,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Ok(vec![DoctorFinding::fail(
                "plugin-registry",
                "project plugin value is absent",
                "Run `wincred-libsecret plugin install --dll <absolute-path>` from an elevated terminal.",
            )]);
        }
        Err(error) => return Err(error).context("could not inspect the plugin registry"),
    };
    let Some(value) = registry_string(&plugins, PLUGIN_VALUE_NAME)? else {
        let foreign = plugins
            .enum_values()
            .filter_map(Result::ok)
            .map(|(name, _)| name)
            .filter(|name| name != PLUGIN_VALUE_NAME)
            .collect::<Vec<_>>();
        if foreign.is_empty() {
            return Ok(vec![DoctorFinding::fail(
                "plugin-registry",
                "project lifecycle plugin is absent",
                "Run `wincred-libsecret plugin install --dll <absolute-path>` from an elevated terminal.",
            )]);
        }
        return Ok(vec![DoctorFinding::ok(
            "plugin-registry",
            format!(
                "project lifecycle plugin is intentionally absent; preserving existing WSL plugin(s): {}",
                foreign.join(", ")
            ),
        )]);
    };
    let path = PathBuf::from(value);
    let mut findings = vec![if path.is_absolute() && path.is_file() {
        DoctorFinding::ok("plugin-path", path.display().to_string())
    } else {
        DoctorFinding::fail(
            "plugin-path",
            format!("{} is not an existing absolute DLL path", path.display()),
            "Reinstall the plugin using an existing absolute DLL path.",
        )
    }];
    if path.is_file() {
        findings.push(match signature_status(&path) {
            SignatureStatus::Valid => DoctorFinding::ok("plugin-signature", "Authenticode Valid"),
            status @ SignatureStatus::NotValid => DoctorFinding::fail(
                "plugin-signature",
                status.to_string(),
                "Install a signed release DLL.",
            ),
        });
    }
    Ok(findings)
}

#[cfg(windows)]
fn format_doctor_report(
    findings: &[DoctorFinding],
    distributions: &[DistributionDiagnostics],
) -> String {
    let mut report = String::new();
    append_doctor_findings(&mut report, findings, None);
    for distribution in distributions {
        let _ = writeln!(
            report,
            "[DISTRO] {}: {}",
            distribution.name,
            distribution.state()
        );
        append_doctor_findings(
            &mut report,
            &distribution.findings,
            Some(&distribution.name),
        );
    }
    report
}

#[cfg(windows)]
fn append_doctor_findings(
    report: &mut String,
    findings: &[DoctorFinding],
    distribution: Option<&str>,
) {
    for finding in findings {
        let status = if finding.ok { "OK" } else { "FAIL" };
        let check = distribution.map_or_else(
            || finding.check.to_owned(),
            |name| format!("{} ({name})", finding.check),
        );
        let _ = writeln!(report, "[{status}] {check}: {}", finding.detail);
        if let Some(remedy) = &finding.remedy {
            let _ = writeln!(report, "       remedy: {remedy}");
        }
    }
}

#[cfg(windows)]
fn distribution_findings(distribution: &Distribution) -> DistributionDiagnostics {
    let enablement = distribution_enabled(distribution.id).map_err(|error| error.to_string());
    let remote = if should_check_runtime(&enablement) {
        Some(remote_doctor(&distribution.name).map_err(|error| error.to_string()))
    } else {
        None
    };
    distribution_diagnostics(distribution, enablement, remote)
}

#[cfg(windows)]
fn should_check_runtime(enablement: &Result<bool, String>) -> bool {
    enablement.as_ref().is_ok_and(|enabled| *enabled)
}

#[cfg(windows)]
fn distribution_diagnostics(
    distribution: &Distribution,
    enablement: Result<bool, String>,
    remote: Option<Result<ProcessResult, String>>,
) -> DistributionDiagnostics {
    let mut findings = Vec::new();
    findings.push(if distribution.version == Some(2) {
        DoctorFinding::ok("distro-wsl2", format!("WSL 2 ({})", distribution.id))
    } else {
        DoctorFinding::fail(
            "distro-wsl2",
            format!(
                "WSL {}",
                distribution
                    .version
                    .map_or_else(|| "unknown".to_owned(), |version| version.to_string())
            ),
            format!(
                "Convert the distribution with `wsl --set-version {:?} 2`.",
                distribution.name
            ),
        )
    });
    let enabled = match enablement {
        Ok(true) => {
            findings.push(DoctorFinding::ok(
                "distro-enablement",
                "enabled: HKCU enablement is set",
            ));
            Some(true)
        }
        Ok(false) => {
            findings.push(DoctorFinding::fail(
                "distro-enablement",
                "disabled: HKCU enablement is absent",
                distro_enable_remedy(&distribution.name),
            ));
            Some(false)
        }
        Err(error) => {
            findings.push(DoctorFinding::fail(
                "distro-enablement",
                error.clone(),
                "Check the current-user registry permissions.",
            ));
            None
        }
    };
    let runtime_ok = remote.is_some_and(|remote| {
        let runtime_findings = runtime_findings(distribution, remote);
        let runtime_ok = runtime_findings.iter().all(|finding| finding.ok);
        findings.extend(runtime_findings);
        runtime_ok
    });
    DistributionDiagnostics {
        name: distribution.name.clone(),
        enabled,
        wsl2: distribution.version == Some(2),
        runtime_ok,
        findings,
    }
}

#[cfg(windows)]
fn runtime_findings(
    distribution: &Distribution,
    remote: Result<ProcessResult, String>,
) -> Vec<DoctorFinding> {
    let mut findings = Vec::new();
    match remote {
        Ok(result) if result.success => {
            let mut has_diagnostics = false;
            for line in result
                .stdout
                .lines()
                .filter(|line| line.starts_with("CHECK "))
            {
                has_diagnostics = true;
                let mut fields = line.splitn(3, ' ');
                let _ = fields.next();
                let check = fields.next().unwrap_or("distro");
                let detail = fields.next().unwrap_or_default();
                if detail.starts_with("ok ") {
                    findings.push(DoctorFinding::ok(
                        "distro-runtime",
                        format!("{check}: {}", detail.trim_start_matches("ok ")),
                    ));
                } else {
                    findings.push(DoctorFinding::fail(
                        "distro-runtime",
                        format!("{check}: {detail}"),
                        format!(
                            "Run {} after resolving the reported prerequisite.",
                            distro_enable_command(&distribution.name)
                        ),
                    ));
                }
            }
            if !has_diagnostics {
                findings.push(DoctorFinding::fail(
                    "distro-runtime",
                    "the installed refresh helper returned no diagnostics",
                    format!(
                        "Re-run {} to repair the installation.",
                        distro_enable_command(&distribution.name)
                    ),
                ));
            }
        }
        Ok(result) => findings.push(DoctorFinding::fail(
            "distro-runtime",
            result.display_error(),
            distro_enable_remedy(&distribution.name),
        )),
        Err(error) => findings.push(DoctorFinding::fail(
            "distro-runtime",
            error,
            format!(
                "Start the distribution with `wsl -d {:?}` and retry.",
                distribution.name
            ),
        )),
    }
    findings
}

#[cfg(windows)]
fn distro_enable_command(distribution: &str) -> String {
    format!("`wincred-libsecret distro enable {distribution:?}`")
}

#[cfg(windows)]
fn distro_enable_remedy(distribution: &str) -> String {
    format!("Run {}.", distro_enable_command(distribution))
}

#[cfg(windows)]
fn remote_status(distribution: &str) -> Result<ProcessResult> {
    run_wsl_root(
        distribution,
        &[
            OsString::from(LINUX_STATUS_HELPER),
            OsString::from("--status"),
        ],
    )
}

#[cfg(windows)]
fn remote_doctor(distribution: &str) -> Result<ProcessResult> {
    run_wsl_root(
        distribution,
        &[
            OsString::from(LINUX_STATUS_HELPER),
            OsString::from("--doctor"),
        ],
    )
}

#[cfg(windows)]
fn check_wsl_version() -> Result<WslVersion> {
    let result = run_process("wsl.exe", &["--version".into()])
        .context("could not run wsl.exe --version; install WSL first")?;
    ensure!(
        result.success,
        "wsl.exe --version failed: {}",
        result.display_error()
    );
    let version =
        parse_wsl_version(&result.stdout).context("could not parse `wsl.exe --version` output")?;
    ensure!(
        compare_versions(version, MINIMUM_WSL_VERSION).is_ge(),
        "WSL {version} is too old; version {MINIMUM_WSL_VERSION} or newer is required"
    );
    Ok(version)
}

#[cfg(windows)]
fn enumerate_distributions() -> Result<Vec<Distribution>> {
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let lxss = match hkcu
        .open_subkey_with_flags(r"Software\Microsoft\Windows\CurrentVersion\Lxss", KEY_READ)
    {
        Ok(key) => key,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error).context("could not enumerate WSL distribution registry"),
    };
    let listed = run_process("wsl.exe", &["--list".into(), "--quiet".into()])
        .ok()
        .filter(|result| result.success)
        .map(|result| parse_wsl_distribution_names(&result.stdout))
        .unwrap_or_default();
    let mut distributions = Vec::new();
    for name in lxss.enum_keys().filter_map(Result::ok) {
        let Ok(id) = Uuid::parse_str(name.trim_matches(['{', '}'])) else {
            continue;
        };
        let Ok(key) = lxss.open_subkey_with_flags(&name, KEY_READ) else {
            continue;
        };
        let Ok(distribution_name) = key.get_value::<String, _>("DistributionName") else {
            continue;
        };
        // `wsl --list --quiet` confirms this registry entry is exposed through
        // the supported WSL CLI. Keep registry-only entries visible for repair.
        let _reported_by_wsl = listed
            .iter()
            .any(|listed_name| listed_name.eq_ignore_ascii_case(&distribution_name));
        distributions.push(Distribution {
            id,
            name: distribution_name,
            version: key.get_value::<u32, _>("Version").ok(),
        });
    }
    distributions.sort_by(|left, right| left.name.cmp(&right.name));
    Ok(distributions)
}

#[cfg(windows)]
fn find_distribution(name: &str) -> Result<Distribution> {
    let distributions = enumerate_distributions()?;
    let matches: Vec<_> = distributions
        .into_iter()
        .filter(|distribution| distribution.name.eq_ignore_ascii_case(name))
        .collect();
    match matches.as_slice() {
        [distribution] => Ok(distribution.clone()),
        [] => bail!("WSL distribution '{name}' was not found for this Windows user"),
        _ => bail!("multiple WSL distributions match '{name}'; use its exact registered name"),
    }
}

#[cfg(windows)]
fn distribution_enabled(id: Uuid) -> Result<bool> {
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let path = distribution_registry_path(id);
    match hkcu.open_subkey_with_flags(&path, KEY_READ) {
        Ok(key) => Ok(key
            .get_value::<u32, _>(DISTRIBUTION_ENABLEMENT_VALUE)
            .is_ok_and(|value| value != 0)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error).context("could not read distribution enablement"),
    }
}

#[cfg(windows)]
fn set_distribution_enabled(id: Uuid, enabled: bool) -> Result<()> {
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let path = distribution_registry_path(id);
    if enabled {
        let (key, _) = hkcu
            .create_subkey(&path)
            .context("could not create distribution enablement key")?;
        key.set_value(DISTRIBUTION_ENABLEMENT_VALUE, &1_u32)
            .context("could not enable the distribution callback")?;
        return Ok(());
    }
    match hkcu.delete_subkey_all(&path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).context("could not remove distribution enablement"),
    }
}

#[cfg(windows)]
fn ensure_wsl_success(distribution: &str, arguments: &[OsString], operation: &str) -> Result<()> {
    let result = run_wsl_root(distribution, arguments)?;
    ensure!(
        result.success,
        "{operation} failed: {}",
        result.display_error()
    );
    Ok(())
}

#[cfg(windows)]
fn run_wsl_root(distribution: &str, arguments: &[OsString]) -> Result<ProcessResult> {
    let mut command = Command::new("wsl.exe");
    command
        .arg("-d")
        .arg(distribution)
        .arg("-u")
        .arg("root")
        .arg("--")
        .args(arguments);
    Ok(process_result(
        command.output().context("could not launch wsl.exe")?,
    ))
}

#[cfg(windows)]
fn wsl_path(distribution: &str, path: &Path) -> Result<String> {
    let output = Command::new("wsl.exe")
        .arg("-d")
        .arg(distribution)
        .arg("--")
        .arg("wslpath")
        .arg("-a")
        .arg(wslpath_argument(path))
        .output()
        .context("could not invoke wslpath")?;
    let result = process_result(output);
    ensure!(
        result.success && !result.stdout.trim().is_empty(),
        "could not translate '{}' for WSL: {}",
        path.display(),
        result.display_error()
    );
    let translated = result
        .stdout
        .strip_suffix("\r\n")
        .or_else(|| result.stdout.strip_suffix('\n'))
        .unwrap_or(&result.stdout);
    Ok(translated.to_owned())
}

#[cfg(windows)]
fn wslpath_argument(path: &Path) -> OsString {
    let wide: Vec<u16> = path
        .as_os_str()
        .encode_wide()
        .map(|unit| {
            if unit == u16::from(b'\\') {
                u16::from(b'/')
            } else {
                unit
            }
        })
        .collect();
    OsString::from_wide(&wide)
}

#[cfg(windows)]
fn run_process(program: &str, arguments: &[OsString]) -> Result<ProcessResult> {
    let output = Command::new(program)
        .args(arguments)
        .output()
        .with_context(|| format!("could not launch {program}"))?;
    Ok(process_result(output))
}

#[cfg(windows)]
fn process_result(output: Output) -> ProcessResult {
    let Output {
        status,
        stdout,
        stderr,
    } = output;
    ProcessResult {
        success: status.success(),
        stdout: decode_process_output(&stdout),
        stderr: decode_process_output(&stderr),
    }
}

#[cfg(windows)]
fn decode_process_output(bytes: &[u8]) -> String {
    let utf16_le = bytes.starts_with(&[0xff, 0xfe])
        || (bytes.len() >= 4
            && bytes.len().is_multiple_of(2)
            && bytes
                .chunks_exact(2)
                .take(64)
                .filter(|pair| pair[1] == 0)
                .count()
                * 4
                >= bytes.chunks_exact(2).take(64).count() * 3);
    if utf16_le {
        let offset = usize::from(bytes.starts_with(&[0xff, 0xfe])) * 2;
        let units = bytes[offset..]
            .chunks_exact(2)
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
            .collect::<Vec<_>>();
        return String::from_utf16_lossy(&units);
    }
    String::from_utf8_lossy(bytes).into_owned()
}

#[cfg(windows)]
fn require_administrator() -> Result<()> {
    let script = concat!(
        "$principal = [Security.Principal.WindowsPrincipal] ",
        "[Security.Principal.WindowsIdentity]::GetCurrent(); ",
        "$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)"
    );
    let result = run_process(
        "powershell.exe",
        &[
            "-NoLogo".into(),
            "-NoProfile".into(),
            "-NonInteractive".into(),
            "-Command".into(),
            script.into(),
        ],
    )
    .context("could not determine whether the process is elevated")?;
    ensure!(
        result.success && result.stdout.trim().eq_ignore_ascii_case("true"),
        "administrator privileges are required. Start an elevated terminal and retry."
    );
    Ok(())
}

#[cfg(windows)]
fn signature_status(path: &Path) -> SignatureStatus {
    let path = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let file_info_size = u32::try_from(size_of::<WINTRUST_FILE_INFO>())
        .expect("WINTRUST_FILE_INFO is smaller than u32::MAX");
    let trust_data_size =
        u32::try_from(size_of::<WINTRUST_DATA>()).expect("WINTRUST_DATA is smaller than u32::MAX");
    let mut file_info = WINTRUST_FILE_INFO {
        cbStruct: file_info_size,
        pcwszFilePath: PCWSTR(path.as_ptr()),
        ..Default::default()
    };
    let mut trust_data = WINTRUST_DATA {
        cbStruct: trust_data_size,
        dwUIChoice: WTD_UI_NONE,
        fdwRevocationChecks: WTD_REVOKE_WHOLECHAIN,
        dwUnionChoice: WTD_CHOICE_FILE,
        Anonymous: WINTRUST_DATA_0 {
            pFile: &raw mut file_info,
        },
        dwStateAction: WTD_STATEACTION_VERIFY,
        ..Default::default()
    };
    let mut verify_action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    #[allow(unsafe_code)]
    let result =
        unsafe { WinVerifyTrustEx(HWND::default(), &raw mut verify_action, &raw mut trust_data) };

    trust_data.dwStateAction = WTD_STATEACTION_CLOSE;
    #[allow(unsafe_code)]
    let _ =
        unsafe { WinVerifyTrustEx(HWND::default(), &raw mut verify_action, &raw mut trust_data) };
    signature_status_from_winverifytrust(result)
}

#[cfg(windows)]
fn signature_status_from_winverifytrust(result: i32) -> SignatureStatus {
    if result == 0 {
        SignatureStatus::Valid
    } else {
        SignatureStatus::NotValid
    }
}

#[cfg(windows)]
fn validate_plugin_dll(path: &Path) -> Result<PathBuf> {
    let canonical = absolute_existing_file(path, "plugin DLL")?;
    ensure!(
        canonical
            .file_name()
            .is_some_and(|name| name.eq_ignore_ascii_case(PLUGIN_DLL_NAME)),
        "plugin DLL must be named {PLUGIN_DLL_NAME}"
    );
    Ok(canonical)
}

#[cfg(windows)]
fn validate_broker(path: &Path) -> Result<PathBuf> {
    let canonical = absolute_existing_file(path, "broker executable")?;
    ensure!(
        canonical
            .file_name()
            .is_some_and(|name| name.eq_ignore_ascii_case("wincred-libsecret-broker.exe")),
        "broker executable must be named wincred-libsecret-broker.exe"
    );
    Ok(canonical)
}

#[cfg(windows)]
fn absolute_existing_file(path: &Path, description: &str) -> Result<PathBuf> {
    ensure!(
        path.is_absolute(),
        "{description} path must be absolute: {}",
        path.display()
    );
    let canonical = fs::canonicalize(path)
        .with_context(|| format!("{description} does not exist: {}", path.display()))?;
    let canonical = normalize_windows_path(&canonical);
    ensure!(
        canonical.is_file(),
        "{description} is not a file: {}",
        canonical.display()
    );
    Ok(canonical)
}

#[cfg(windows)]
fn absolute_existing_directory(path: &Path, description: &str) -> Result<PathBuf> {
    ensure!(
        path.is_absolute(),
        "{description} path must be absolute: {}",
        path.display()
    );
    let canonical = fs::canonicalize(path)
        .with_context(|| format!("{description} does not exist: {}", path.display()))?;
    let canonical = normalize_windows_path(&canonical);
    ensure!(
        canonical.is_dir(),
        "{description} is not a directory: {}",
        canonical.display()
    );
    Ok(canonical)
}

#[cfg(windows)]
fn normalize_windows_path(path: &Path) -> PathBuf {
    let text = path.to_string_lossy();
    if let Some(unc) = text.strip_prefix(r"\\?\UNC\") {
        return PathBuf::from(format!(r"\\{unc}"));
    }
    text.strip_prefix(r"\\?\")
        .map_or_else(|| path.to_path_buf(), PathBuf::from)
}

#[cfg(windows)]
fn windows_paths_equal(left: &Path, right: &Path) -> bool {
    normalize_windows_path(left)
        .to_string_lossy()
        .eq_ignore_ascii_case(&normalize_windows_path(right).to_string_lossy())
}

#[cfg(windows)]
fn default_payload_root() -> PathBuf {
    std::env::current_exe()
        .ok()
        .and_then(|path| path.parent().map(|parent| parent.join("linux")))
        .unwrap_or_else(|| PathBuf::from(r"C:\Program Files\WinCredLibsecret\linux"))
}

#[cfg(windows)]
fn default_broker_path() -> PathBuf {
    std::env::current_exe()
        .ok()
        .and_then(|path| {
            path.parent()
                .map(|parent| parent.join("wincred-libsecret-broker.exe"))
        })
        .unwrap_or_else(|| {
            PathBuf::from(r"C:\Program Files\WinCredLibsecret\wincred-libsecret-broker.exe")
        })
}

#[cfg(windows)]
fn verify_payload(root: &Path) -> Result<()> {
    let manifest = root.join(LINUX_PAYLOAD_MANIFEST);
    let manifest_text = fs::read_to_string(&manifest)
        .with_context(|| format!("payload manifest is missing: {}", manifest.display()))?;
    let mut count = 0_usize;
    for line in manifest_text.lines().filter(|line| !line.trim().is_empty()) {
        let (expected, relative) = line
            .split_once("  ")
            .ok_or_else(|| anyhow!("invalid payload manifest entry"))?;
        ensure!(
            expected.len() == 64 && expected.bytes().all(|byte| byte.is_ascii_hexdigit()),
            "invalid payload hash"
        );
        let relative = Path::new(relative);
        ensure!(
            !relative.is_absolute()
                && !relative.components().any(|component| matches!(
                    component,
                    std::path::Component::ParentDir | std::path::Component::RootDir
                )),
            "payload manifest contains an unsafe path"
        );
        let contents = fs::read(root.join(relative))
            .with_context(|| format!("payload file is missing: {}", relative.display()))?;
        let mut actual = String::with_capacity(64);
        for byte in Sha256::digest(&contents) {
            write!(&mut actual, "{byte:02x}").expect("writing to a String cannot fail");
        }
        ensure!(
            actual.eq_ignore_ascii_case(expected),
            "payload hash mismatch: {}",
            relative.display()
        );
        count += 1;
    }
    ensure!(count > 0, "payload manifest contains no files");
    for required in [
        LINUX_BOOTSTRAP,
        "wincred-libsecret-provider",
        "org.freedesktop.secrets.service",
        "wincred-libsecret.service",
        "wincred-libsecret-refresh.service",
    ] {
        ensure!(
            root.join(required).is_file(),
            "payload is missing {required}"
        );
    }
    Ok(())
}

#[cfg(windows)]
fn registry_string(key: &RegKey, name: &str) -> Result<Option<String>> {
    match key.get_value::<String, _>(name) {
        Ok(value) => Ok(Some(value)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error).context("registry value is not a readable string"),
    }
}

#[cfg(all(test, windows))]
mod tests {
    use std::path::{Path, PathBuf};

    use uuid::Uuid;

    use super::{
        Distribution, ProcessResult, SignatureStatus, decode_process_output,
        distribution_diagnostics, format_doctor_report, normalize_windows_path,
        should_check_runtime, signature_status, signature_status_from_winverifytrust,
        windows_paths_equal,
    };

    #[test]
    fn decodes_utf8_process_output() {
        assert_eq!(decode_process_output(b"Valid\r\n"), "Valid\r\n");
    }

    #[test]
    fn decodes_unmarked_utf16le_process_output() {
        let bytes = "WSL version: 2.7.11.0\r\n"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect::<Vec<_>>();
        assert_eq!(decode_process_output(&bytes), "WSL version: 2.7.11.0\r\n");
    }

    #[test]
    fn normalizes_extended_windows_paths() {
        assert_eq!(
            normalize_windows_path(Path::new(r"\\?\C:\Program Files\WinCredLibsecret\a.dll")),
            PathBuf::from(r"C:\Program Files\WinCredLibsecret\a.dll")
        );
        assert!(windows_paths_equal(
            Path::new(r"\\?\C:\Program Files\WinCredLibsecret\a.dll"),
            Path::new(r"c:\program files\wincredlibsecret\a.dll")
        ));
    }

    #[test]
    fn winverifytrust_success_identifies_a_signed_plugin_as_valid() {
        assert_eq!(
            signature_status_from_winverifytrust(0),
            SignatureStatus::Valid
        );
        assert_eq!(
            signature_status_from_winverifytrust(i32::MIN),
            SignatureStatus::NotValid
        );
    }

    #[test]
    fn winverifytrust_validates_a_signed_windows_binary() {
        let system_root = std::env::var_os("SystemRoot").expect("Windows defines SystemRoot");
        let kernel32 = PathBuf::from(system_root).join(r"System32\kernel32.dll");
        assert_eq!(signature_status(&kernel32), SignatureStatus::Valid);

        let installed_plugin =
            PathBuf::from(r"C:\Program Files\WinCredLibsecret\wincred-libsecret-wsl-plugin.dll");
        if installed_plugin.is_file() {
            assert_eq!(signature_status(&installed_plugin), SignatureStatus::Valid);
        }
    }

    #[test]
    fn doctor_report_attributes_multiple_distros_and_names_enable_remedies() {
        let docker_desktop = Distribution {
            id: Uuid::from_u128(1),
            name: "docker-desktop".to_owned(),
            version: Some(2),
        };
        let ubuntu = Distribution {
            id: Uuid::from_u128(2),
            name: "Ubuntu 24.04".to_owned(),
            version: Some(2),
        };
        let fedora = Distribution {
            id: Uuid::from_u128(3),
            name: "Fedora".to_owned(),
            version: Some(2),
        };
        let docker_desktop = distribution_diagnostics(&docker_desktop, Ok(false), None);
        let ubuntu = distribution_diagnostics(
            &ubuntu,
            Ok(true),
            Some(Ok(ProcessResult {
                success: true,
                stdout: "CHECK payload failed manifest mismatch\n".to_owned(),
                stderr: String::new(),
            })),
        );
        let fedora = distribution_diagnostics(
            &fedora,
            Ok(true),
            Some(Ok(ProcessResult {
                success: true,
                stdout: "CHECK payload ok manifest verified\n".to_owned(),
                stderr: String::new(),
            })),
        );

        let report = format_doctor_report(&[], &[docker_desktop, ubuntu, fedora]);

        assert!(!should_check_runtime(&Ok(false)));
        assert!(should_check_runtime(&Ok(true)));
        assert!(report.contains("[DISTRO] docker-desktop: disabled"));
        assert!(!report.contains("[DISTRO] docker-desktop: disabled,"));
        assert!(report.contains("[DISTRO] Ubuntu 24.04: enabled, degraded"));
        assert!(report.contains("[DISTRO] Fedora: enabled, working"));
        assert!(report.contains("[FAIL] distro-enablement (docker-desktop): disabled:"));
        assert!(!report.contains("distro-runtime (docker-desktop)"));
        assert!(!report.contains("refresh helper is absent"));
        assert!(report.contains("[FAIL] distro-runtime (Ubuntu 24.04): payload: failed"));
        assert_eq!(
            report
                .matches("wincred-libsecret distro enable \"docker-desktop\"")
                .count(),
            1
        );
        assert!(
            report
                .contains("Run `wincred-libsecret distro enable \"Ubuntu 24.04\"` after resolving")
        );
        assert!(!report.contains("<name>"));
    }
}
