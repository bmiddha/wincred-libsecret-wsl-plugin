# Troubleshooting and complete removal

Start with non-secret diagnostics:

```powershell
& $cli plugin status
& $cli distro list
& $cli doctor --distro <distro-name>
```

For a development build, set `$cli` to the built
`wincred-libsecret.exe`; for an MSI install, use the CLI in the Program Files
product directory. On Linux:

```bash
sudo /usr/libexec/wincred-libsecret/wincred-libsecret-refresh --doctor
systemctl --user status wincred-libsecret.service
journalctl --user -u wincred-libsecret.service
journalctl -u wincred-libsecret-refresh.service
```

## Signing and plugin load

| Symptom | Resolution |
| --- | --- |
| CLI says the DLL signature is not valid | Register a trusted signed release DLL. For a local development build, create/trust the short-lived dev certificate and sign the DLL; use `--allow-unsigned` only in an isolated dev scenario. |
| `TRUST_E_NOSIGNATURE` or no signature | The DLL was unsigned or its signature was stripped. Rebuild/sign it with the development script or production release signer; do not bypass this for MSI/production. |
| Signature is present but not `Valid` | Check certificate trust, expiry, timestamp reachability, and that the exact registered DLL has not changed. `plugin status` reports the path and status. |
| `wslservice` does not load the updated DLL | Confirm the HKLM value and absolute path with `plugin status`, then restart `wslservice` or restart WSL/reboot. Use ETW provider `WinCredLibsecret.WslPlugin` for plugin failure operation/HRESULT evidence. |
| Registry write fails | Run from an elevated terminal. Check that another administrator has not placed an unexpected value at the project value name. Development scripts preserve a foreign value unless replacement is explicit. |
| Development cleanup rejects state | Do not edit or copy plugin state. It is fixed at `%ProgramData%\WinCredLibsecret\DevPlugin` and accepts only SYSTEM/Administrators ACLs, a non-reparse path, and trusted signed restore DLLs. Resolve the conflicting registration manually, then rerun the elevated helper. |

## WSL, systemd, D-Bus, and broker

| Symptom | Resolution |
| --- | --- |
| WSL service / plugin API error | Update WSL to 2.5.1 or newer, verify x64 Windows and an x86_64 WSL 2 distro, restart WSL, then rerun `doctor`. |
| `systemd is not active` | Enable systemd for the distribution in its normal WSL configuration, terminate/restart the distro, and rerun enable. |
| No session bus or Secret Service activation | Install/enable a D-Bus user-service implementation, inspect the global D-Bus service file and user unit, then use `dbus-run-session` for non-graphical test sessions. |
| Broker cannot launch / interop unavailable | Ensure `cmd.exe` is visible and executable from the distro and that Windows interop was not disabled. Re-enable with a reachable broker path or repair the MSI payload. |
| Provider starts but client cannot connect | Inspect `journalctl --user -u wincred-libsecret.service`; verify `org.freedesktop.secrets` activation and `systemctl --user` service status in the same Linux user's D-Bus session. |
| Payload hash or mode check fails | Treat the payload as untrusted. Disable the distro, repair/reinstall from trusted artifacts, then re-enable. Do not manually relax root ownership/modes. |

## Conflicts, limits, and corrupt data

| Symptom | Resolution |
| --- | --- |
| Existing Secret Service provider conflict | The installer intentionally refuses replacement. Review the existing provider. If it should be replaced, rerun distro enable with `--replace-conflicts`; disable restores the protected backup unless another provider now owns the target. |
| Secret larger than 2,560 bytes | Split, compress, or store a reference rather than the payload. The WinCred blob limit is exact; 2,561 bytes cannot be stored. |
| Unexpected access across distro or Linux user | This is the documented Windows-user shared-vault model. Disable the provider in untrusted distributions/users; it is not a Linux UID isolation mechanism. |
| Corrupt or missing committed generation | Preserve diagnostics. Broker reconciliation deletes only uncommitted generations and reports metadata pointing to missing data. Restore the affected item from backup, or intentionally delete/recreate that project item; do not delete unrelated WinCred credentials. |

## Recovery and rollback

If enable fails before completion, the CLI does not set the per-distro HKCU
flag. The bootstrap restores conflict backups when an installation failure
occurs. Check the helper doctor, remove only project-owned files via
`distro disable`, and retry from a trusted payload.

For a bad upgrade, disable affected distros first, reinstall the previous
trusted MSI or re-register the previous signed DLL using the guarded CLI,
restart `wslservice`, and re-enable each distro. Do not overwrite a plugin
registration that now belongs to another administrator/product.

## Complete removal

1. List enabled distributions, then disable every one:

   ```powershell
   & $cli distro list
   & $cli distro disable <distro-name>
   ```

   This removes only marker-owned Linux files, restores backed-up Secret
   Service definitions when safe, and removes the matching HKCU enablement
   key. It deliberately leaves vault data intact.

2. Remove the Windows registration and payload:

   - MSI install: use Apps & Features or `msiexec.exe /x <msi>`.
   - Development registration: run
     `scripts\Uninstall-DevPlugin.ps1 -RestartWslService`.

   Restart `wslservice`, restart WSL, or reboot. The guarded uninstall
   preserves a value that no longer points to this product DLL.

3. If development signing was used, run
   `scripts\Remove-DevSigningCertificate.ps1` to remove the tracked
   short-lived certificate and state.

4. Decide separately whether to delete persisted secrets. Back up anything
   required, then remove only Credential Manager generic credentials whose
   targets begin exactly with `WinCredLibSecret/v1/`. The product intentionally
   has no arbitrary-credential delete command. Never bulk-delete unrelated
   Credential Manager entries.

5. Confirm no project registry values, root-owned provider files, D-Bus
   service definitions, development state, or project-prefixed credential
   targets remain. If a conflict backup could not be restored because another
   provider owns its path, leave that newer provider in place and resolve the
   ownership decision manually.
