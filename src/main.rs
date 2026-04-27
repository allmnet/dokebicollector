use std::env;
use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::Command;

use chrono::Utc;
use clap::Parser;
use serde::Serialize;
use sha2::{Digest, Sha256};
use walkdir::WalkDir;

#[derive(Parser, Debug)]
#[command(author, version, about = "Cross-platform incident artifact collector")]
struct Args {
    #[arg(short, long, default_value = "collection-output")]
    output: String,

    #[arg(short = 'n', long = "name", default_value = "default")]
    case_name: String,
}

#[derive(Debug, Serialize)]
struct Manifest {
    collector_version: String,
    started_at_utc: String,
    finished_at_utc: String,
    host: String,
    os: String,
    case_name: String,
    output_dir: String,
    command_results: Vec<CommandResult>,
    copied_artifacts: Vec<ArtifactResult>,
    #[cfg(target_os = "windows")]
    evtx_exports: Vec<ArtifactResult>,
    #[cfg(target_os = "windows")]
    registry_exports: Vec<ArtifactResult>,
    browser_artifacts: Vec<ArtifactResult>,
    errors: Vec<String>,
}

#[derive(Debug, Serialize)]
struct CommandResult {
    name: String,
    command: String,
    status: String,
    exit_code: Option<i32>,
    output_file: String,
    sha256: Option<String>,
    error: Option<String>,
}

#[derive(Debug, Serialize)]
struct ArtifactResult {
    source: String,
    destination: String,
    status: String,
    sha256: Option<String>,
    error: Option<String>,
}

struct CommandSpec {
    name: &'static str,
    shell: &'static str,
}

fn main() {
    let args = Args::parse();
    let started_at = Utc::now();

    // 관리자 권한 확인 후 경고 출력
    #[cfg(target_os = "windows")]
    {
        if !is_elevated_windows() {
            eprintln!("[WARNING] Running without Administrator privileges.");
            eprintln!("         Security event log, registry hives (SAM/SYSTEM/SOFTWARE/SECURITY)");
            eprintln!("         and Prefetch may not be accessible. Run as Administrator for full collection.");
        }
    }
    #[cfg(not(target_os = "windows"))]
    {
        if !is_root_unix() {
            eprintln!("[WARNING] Running without root privileges.");
            eprintln!("         Some artifacts (shadow, audit.log, etc.) may not be accessible.");
            eprintln!("         Run with sudo for full collection.");
        }
    }

    let run_id = started_at.format("%Y%m%dT%H%M%SZ").to_string();
    let base_dir = PathBuf::from(args.output)
        .join(sanitize_segment(&args.case_name))
        .join(run_id.clone());

    let mut errors = Vec::new();

    if let Err(e) = fs::create_dir_all(&base_dir) {
        eprintln!("failed to create output directory: {}", e);
        std::process::exit(1);
    }

    let command_dir = base_dir.join("commands");
    let artifact_dir = base_dir.join("artifacts");
    for dir in [&command_dir, &artifact_dir] {
        if let Err(e) = fs::create_dir_all(dir) {
            eprintln!("failed to create directory {}: {}", dir.display(), e);
            std::process::exit(1);
        }
    }

    let command_results = collect_commands(&command_dir, &mut errors);
    let copied_artifacts = collect_artifacts(&artifact_dir, &mut errors);

    #[cfg(target_os = "windows")]
    let evtx_exports = {
        let evtx_dir = base_dir.join("evtx");
        if let Err(e) = fs::create_dir_all(&evtx_dir) {
            errors.push(format!("failed to create evtx dir: {}", e));
            Vec::new()
        } else {
            collect_windows_evtx(&evtx_dir, &mut errors)
        }
    };

    #[cfg(target_os = "windows")]
    let registry_exports = {
        let reg_dir = base_dir.join("registry");
        if let Err(e) = fs::create_dir_all(&reg_dir) {
            errors.push(format!("failed to create registry dir: {}", e));
            Vec::new()
        } else {
            collect_windows_registry(&reg_dir, &mut errors)
        }
    };

    let browser_artifacts = {
        let browser_dir = base_dir.join("browser");
        if let Err(e) = fs::create_dir_all(&browser_dir) {
            errors.push(format!("failed to create browser dir: {}", e));
            Vec::new()
        } else {
            collect_browser_artifacts(&browser_dir, &mut errors)
        }
    };

    let finished_at = Utc::now();

    let manifest = Manifest {
        collector_version: env!("CARGO_PKG_VERSION").to_string(),
        started_at_utc: started_at.to_rfc3339(),
        finished_at_utc: finished_at.to_rfc3339(),
        host: get_hostname(),
        os: env::consts::OS.to_string(),
        case_name: args.case_name,
        output_dir: base_dir.to_string_lossy().to_string(),
        command_results,
        copied_artifacts,
        #[cfg(target_os = "windows")]
        evtx_exports,
        #[cfg(target_os = "windows")]
        registry_exports,
        browser_artifacts,
        errors,
    };

    let manifest_path = base_dir.join("collection_manifest.json");
    if let Err(e) = write_json(&manifest_path, &manifest) {
        eprintln!("failed to write manifest: {}", e);
        std::process::exit(1);
    }

    let manifest_hash_path = base_dir.join("collection_manifest.sha256");
    match hash_file(&manifest_path) {
        Ok(hash) => {
            if let Err(e) = fs::write(&manifest_hash_path, format!("{}  collection_manifest.json\n", hash)) {
                eprintln!("failed to write manifest hash: {}", e);
                std::process::exit(1);
            }
        }
        Err(e) => {
            eprintln!("failed to hash manifest: {}", e);
            std::process::exit(1);
        }
    }

    println!("collection completed: {}", base_dir.display());
}

fn collect_commands(command_dir: &Path, errors: &mut Vec<String>) -> Vec<CommandResult> {
    let specs = command_specs();
    let mut results = Vec::new();

    for spec in specs {
        let output_file = command_dir.join(format!("{}.txt", sanitize_segment(spec.name)));
        let command_text = spec.shell.to_string();

        let execution = run_shell_command(spec.shell);
        match execution {
            Ok((stdout, stderr, code)) => {
                let mut content = String::new();
                content.push_str("# command\n");
                content.push_str(spec.shell);
                content.push_str("\n\n# stdout\n");
                content.push_str(&stdout);
                content.push_str("\n\n# stderr\n");
                content.push_str(&stderr);

                let write_res = fs::write(&output_file, content);
                if let Err(e) = write_res {
                    let msg = format!("failed writing command output {}: {}", spec.name, e);
                    errors.push(msg.clone());
                    results.push(CommandResult {
                        name: spec.name.to_string(),
                        command: command_text,
                        status: "write_error".to_string(),
                        exit_code: code,
                        output_file: output_file.to_string_lossy().to_string(),
                        sha256: None,
                        error: Some(msg),
                    });
                    continue;
                }

                let hash = hash_file(&output_file).ok();
                let status = if code.unwrap_or(1) == 0 { "ok" } else { "command_error" };

                results.push(CommandResult {
                    name: spec.name.to_string(),
                    command: command_text,
                    status: status.to_string(),
                    exit_code: code,
                    output_file: output_file.to_string_lossy().to_string(),
                    sha256: hash,
                    error: None,
                });
            }
            Err(e) => {
                let msg = format!("failed to execute {}: {}", spec.name, e);
                errors.push(msg.clone());

                results.push(CommandResult {
                    name: spec.name.to_string(),
                    command: command_text,
                    status: "exec_error".to_string(),
                    exit_code: None,
                    output_file: output_file.to_string_lossy().to_string(),
                    sha256: None,
                    error: Some(msg),
                });
            }
        }
    }

    results
}

fn collect_artifacts(artifact_dir: &Path, errors: &mut Vec<String>) -> Vec<ArtifactResult> {
    let mut results = Vec::new();

    for source in artifact_sources() {
        let expanded = expand_env_vars(source);
        let src = PathBuf::from(&expanded);
        if !src.exists() {
            continue;
        }

        let dest = artifact_dir.join(flatten_source_path(&expanded));
        if src.is_file() {
            let parent = dest.parent().map(Path::to_path_buf).unwrap_or_else(|| artifact_dir.to_path_buf());
            if let Err(e) = fs::create_dir_all(parent) {
                let msg = format!("failed to create destination for {}: {}", expanded, e);
                errors.push(msg.clone());
                results.push(ArtifactResult {
                    source: expanded.clone(),
                    destination: dest.to_string_lossy().to_string(),
                    status: "mkdir_error".to_string(),
                    sha256: None,
                    error: Some(msg),
                });
                continue;
            }

            match fs::copy(&src, &dest) {
                Ok(_) => {
                    let hash = hash_file(&dest).ok();
                    results.push(ArtifactResult {
                        source: expanded.clone(),
                        destination: dest.to_string_lossy().to_string(),
                        status: "ok".to_string(),
                        sha256: hash,
                        error: None,
                    });
                }
                Err(e) => {
                    let msg = format!("failed copying file {}: {}", expanded, e);
                    errors.push(msg.clone());
                    results.push(ArtifactResult {
                        source: expanded.clone(),
                        destination: dest.to_string_lossy().to_string(),
                        status: "copy_error".to_string(),
                        sha256: None,
                        error: Some(msg),
                    });
                }
            }
        } else if src.is_dir() {
            let mut copied_any = false;
            for entry in WalkDir::new(&src).follow_links(false).into_iter().filter_map(Result::ok) {
                if !entry.file_type().is_file() {
                    continue;
                }

                let rel = match entry.path().strip_prefix(&src) {
                    Ok(v) => v,
                    Err(_) => continue,
                };

                let file_dest = dest.join(rel);
                if let Some(parent) = file_dest.parent() {
                    if let Err(e) = fs::create_dir_all(parent) {
                        let msg = format!("failed creating directory {}: {}", parent.display(), e);
                        errors.push(msg);
                        continue;
                    }
                }

                if let Err(e) = fs::copy(entry.path(), &file_dest) {
                    let msg = format!("failed copying {}: {}", entry.path().display(), e);
                    errors.push(msg);
                    continue;
                }
                copied_any = true;
            }

            results.push(ArtifactResult {
                source: expanded.clone(),
                destination: dest.to_string_lossy().to_string(),
                status: if copied_any { "ok".to_string() } else { "empty_or_unreadable".to_string() },
                sha256: None,
                error: None,
            });
        }
    }

    results
}

fn write_json<T: Serialize>(path: &Path, value: &T) -> Result<(), String> {
    let json = serde_json::to_string_pretty(value).map_err(|e| e.to_string())?;
    fs::write(path, json).map_err(|e| e.to_string())
}

fn hash_file(path: &Path) -> Result<String, String> {
    let mut file = File::open(path).map_err(|e| e.to_string())?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 8192];

    loop {
        let n = file.read(&mut buf).map_err(|e| e.to_string())?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }

    Ok(format!("{:x}", hasher.finalize()))
}

fn run_shell_command(command: &str) -> Result<(String, String, Option<i32>), String> {
    #[cfg(target_os = "windows")]
    let output = Command::new("powershell")
        .arg("-NoProfile")
        .arg("-ExecutionPolicy")
        .arg("Bypass")
        .arg("-Command")
        .arg(command)
        .output()
        .map_err(|e| e.to_string())?;

    #[cfg(not(target_os = "windows"))]
    let output = Command::new("sh")
        .arg("-c")
        .arg(command)
        .output()
        .map_err(|e| e.to_string())?;

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    Ok((stdout, stderr, output.status.code()))
}

fn sanitize_segment(input: &str) -> String {
    input
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

fn flatten_source_path(path: &str) -> String {
    let mut out = String::new();
    for c in path.chars() {
        if c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_' {
            out.push(c);
        } else {
            out.push('_');
        }
    }
    out
}

fn get_hostname() -> String {
    if let Ok(v) = env::var("COMPUTERNAME") {
        if !v.trim().is_empty() {
            return v;
        }
    }
    if let Ok(v) = env::var("HOSTNAME") {
        if !v.trim().is_empty() {
            return v;
        }
    }
    "unknown-host".to_string()
}

fn expand_env_vars(input: &str) -> String {
    let mut out = input.to_string();
    for (key, value) in env::vars() {
        let token = format!("%{}%", key);
        if out.contains(&token) {
            out = out.replace(&token, &value);
        }
    }
    out
}

#[cfg(target_os = "windows")]
fn command_specs() -> Vec<CommandSpec> {
    vec![
        CommandSpec { name: "time_info",            shell: "Get-Date; Get-TimeZone" },
        CommandSpec { name: "system_info",           shell: "systeminfo" },
        CommandSpec { name: "users_sessions",        shell: "query user 2>&1; qwinsta 2>&1" },
        CommandSpec { name: "processes",             shell: "Get-CimInstance Win32_Process | Select-Object ProcessId,ParentProcessId,Name,CommandLine,ExecutablePath | Format-List" },
        CommandSpec { name: "services",              shell: "Get-CimInstance Win32_Service | Select-Object Name,State,StartMode,PathName | Format-List" },
        CommandSpec { name: "drivers",               shell: "Get-CimInstance Win32_SystemDriver | Select-Object Name,State,PathName | Format-List" },
        CommandSpec { name: "network_connections",   shell: "netstat -ano" },
        CommandSpec { name: "routes",                shell: "route print" },
        CommandSpec { name: "arp",                   shell: "arp -a" },
        CommandSpec { name: "dns_cache",             shell: "Get-DnsClientCache | Format-List" },
        CommandSpec { name: "firewall_rules",        shell: "Get-NetFirewallRule | Where-Object {$_.Enabled -eq 'True'} | Format-List" },
        CommandSpec { name: "firewall_status",       shell: "netsh advfirewall show allprofiles" },
        CommandSpec { name: "scheduled_tasks",       shell: "schtasks /query /fo LIST /v" },
        CommandSpec { name: "local_users",           shell: "Get-LocalUser | Format-List" },
        CommandSpec { name: "local_groups",          shell: "Get-LocalGroup | Format-List; net localgroup administrators" },
        CommandSpec { name: "autorun_hklm_run",      shell: "Get-ItemProperty HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" },
        CommandSpec { name: "autorun_hkcu_run",      shell: "Get-ItemProperty HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" },
        CommandSpec { name: "autorun_hklm_runonce",  shell: "Get-ItemProperty HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce 2>&1" },
        CommandSpec { name: "startup_folders",       shell: "Get-ChildItem -Path 'C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp', \"$env:APPDATA\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\" -ErrorAction SilentlyContinue | Format-List" },
        CommandSpec { name: "installed_software",    shell: "Get-ItemProperty HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* | Select-Object DisplayName,DisplayVersion,InstallDate,Publisher | Format-Table -AutoSize" },
        CommandSpec { name: "shares",                shell: "net share" },
        CommandSpec { name: "defender_status",       shell: "Get-MpComputerStatus" },
        CommandSpec { name: "logon_sessions",        shell: "Get-CimInstance Win32_LogonSession | Format-List" },
        CommandSpec { name: "named_pipes",           shell: "[System.IO.Directory]::GetFiles('\\\\.\\pipe') | Format-Table" },
        CommandSpec { name: "env_vars",              shell: "Get-ChildItem Env:" },
        CommandSpec { name: "hosts_file",            shell: "Get-Content C:\\Windows\\System32\\drivers\\etc\\hosts" },
    ]
}

#[cfg(target_os = "windows")]
fn evtx_channels() -> Vec<(&'static str, &'static str)> {
    // (채널명, 출력파일명)
    vec![
        ("Security",                                                       "Security"),
        ("System",                                                         "System"),
        ("Application",                                                    "Application"),
        ("Microsoft-Windows-Sysmon/Operational",                           "Sysmon_Operational"),
        ("Microsoft-Windows-PowerShell/Operational",                       "PowerShell_Operational"),
        ("Windows PowerShell",                                             "Windows_PowerShell"),
        ("Microsoft-Windows-TaskScheduler/Operational",                    "TaskScheduler_Operational"),
        ("Microsoft-Windows-WMI-Activity/Operational",                     "WMI_Operational"),
        ("Microsoft-Windows-Windows Defender/Operational",                 "Defender_Operational"),
        ("Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational", "RDP_RemoteConnectionManager"),
        ("Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",     "RDP_LocalSessionManager"),
        ("Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational",          "RDP_CoreTS"),
        ("Microsoft-Windows-Bits-Client/Operational",                      "BITS_Client"),
        ("Microsoft-Windows-DNSClient/Operational",                        "DNS_Client"),
    ]
}

/// wevtutil epl 을 사용해 EVTX 채널을 내보낸다 (서비스 경유, 잠금 없음).
#[cfg(target_os = "windows")]
fn collect_windows_evtx(evtx_dir: &Path, errors: &mut Vec<String>) -> Vec<ArtifactResult> {
    let mut results = Vec::new();
    for (channel, filename) in evtx_channels() {
        let dest = evtx_dir.join(format!("{}.evtx", filename));
        let dest_str = dest.to_string_lossy().to_string();

        // 대상 파일이 이미 있으면 삭제 (wevtutil은 덮어쓰기 거부)
        let _ = fs::remove_file(&dest);

        let status = Command::new("wevtutil")
            .args(["epl", channel, dest_str.as_str()])
            .output();

        match status {
            Ok(out) => {
                let code = out.status.code().unwrap_or(-1);
                if code == 0 && dest.exists() {
                    let hash = hash_file(&dest).ok();
                    results.push(ArtifactResult {
                        source: channel.to_string(),
                        destination: dest_str,
                        status: "ok".to_string(),
                        sha256: hash,
                        error: None,
                    });
                } else if code == 15007 {
                    // 채널이 존재하지 않거나 비활성화된 경우 — 오류가 아닌 정보
                    results.push(ArtifactResult {
                        source: channel.to_string(),
                        destination: dest_str,
                        status: "not_found".to_string(),
                        sha256: None,
                        error: Some("channel not found or not enabled on this system".to_string()),
                    });
                } else {
                    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
                    let hint = if code == 5 { " (requires Administrator)" } else { "" };
                    let msg = format!("wevtutil epl {} failed (code {}){}: {}", channel, code, hint, stderr.trim());
                    errors.push(msg.clone());
                    results.push(ArtifactResult {
                        source: channel.to_string(),
                        destination: dest_str,
                        status: "error".to_string(),
                        sha256: None,
                        error: Some(msg),
                    });
                }
            }
            Err(e) => {
                let msg = format!("failed to run wevtutil for {}: {}", channel, e);
                errors.push(msg.clone());
                results.push(ArtifactResult {
                    source: channel.to_string(),
                    destination: dest_str,
                    status: "exec_error".to_string(),
                    sha256: None,
                    error: Some(msg),
                });
            }
        }
    }
    results
}

/// reg save 를 사용해 레지스트리 하이브를 덤프한다.
#[cfg(target_os = "windows")]
fn collect_windows_registry(reg_dir: &Path, errors: &mut Vec<String>) -> Vec<ArtifactResult> {
    let hives = vec![
        ("HKLM\\SAM",      "SAM"),
        ("HKLM\\SYSTEM",   "SYSTEM"),
        ("HKLM\\SOFTWARE", "SOFTWARE"),
        ("HKLM\\SECURITY", "SECURITY"),
    ];

    let mut results = Vec::new();
    for (hive, filename) in hives {
        let dest = reg_dir.join(format!("{}.hiv", filename));
        let dest_str = dest.to_string_lossy().to_string();

        // reg save 는 대상 파일이 없어야 한다
        let _ = fs::remove_file(&dest);

        let status = Command::new("reg")
            .args(["save", hive, dest_str.as_str(), "/y"])
            .output();

        match status {
            Ok(out) => {
                let code = out.status.code().unwrap_or(-1);
                if code == 0 && dest.exists() {
                    let hash = hash_file(&dest).ok();
                    results.push(ArtifactResult {
                        source: hive.to_string(),
                        destination: dest_str,
                        status: "ok".to_string(),
                        sha256: hash,
                        error: None,
                    });
                } else {
                    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
                    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
                    let msg = format!("reg save {} failed (code {}): {} {}", hive, code, stderr.trim(), stdout.trim());
                    errors.push(msg.clone());
                    results.push(ArtifactResult {
                        source: hive.to_string(),
                        destination: dest_str,
                        status: "error".to_string(),
                        sha256: None,
                        error: Some(msg),
                    });
                }
            }
            Err(e) => {
                let msg = format!("failed to run reg save for {}: {}", hive, e);
                errors.push(msg.clone());
                results.push(ArtifactResult {
                    source: hive.to_string(),
                    destination: dest_str,
                    status: "exec_error".to_string(),
                    sha256: None,
                    error: Some(msg),
                });
            }
        }
    }
    results
}

#[cfg(target_os = "linux")]
fn command_specs() -> Vec<CommandSpec> {
    vec![
        CommandSpec { name: "time_info",           shell: "date -u; timedatectl status 2>/dev/null || true" },
        CommandSpec { name: "host_info",            shell: "uname -a; cat /etc/os-release 2>/dev/null; hostnamectl 2>/dev/null || true" },
        CommandSpec { name: "uptime",               shell: "uptime" },
        CommandSpec { name: "logged_in_users",      shell: "who; w" },
        CommandSpec { name: "last_logins",          shell: "last | head -n 100" },
        CommandSpec { name: "failed_logins",        shell: "lastb 2>/dev/null | head -n 100 || echo 'lastb unavailable'" },
        CommandSpec { name: "processes",            shell: "ps auxwwf" },
        CommandSpec { name: "open_files",           shell: "lsof -n -P 2>/dev/null | head -n 2000 || ss -pant" },
        CommandSpec { name: "network_connections",  shell: "ss -pant" },
        CommandSpec { name: "routes",               shell: "ip route" },
        CommandSpec { name: "neighbors",            shell: "ip neigh" },
        CommandSpec { name: "interfaces",           shell: "ip addr" },
        CommandSpec { name: "iptables",             shell: "iptables -S 2>/dev/null || echo 'unavailable'" },
        CommandSpec { name: "nftables",             shell: "nft list ruleset 2>/dev/null || echo 'unavailable'" },
        CommandSpec { name: "systemd_units",        shell: "systemctl list-units --all 2>/dev/null || true" },
        CommandSpec { name: "systemd_failed",       shell: "systemctl --failed 2>/dev/null || true" },
        CommandSpec { name: "crontab_root",         shell: "crontab -l 2>/dev/null; ls -la /etc/cron* /var/spool/cron/ 2>/dev/null" },
        CommandSpec { name: "sudoers",              shell: "cat /etc/sudoers 2>/dev/null; ls /etc/sudoers.d/ 2>/dev/null" },
        CommandSpec { name: "passwd_shadow",        shell: "cat /etc/passwd; getent group" },
        CommandSpec { name: "suid_sgid_files",      shell: "find / -xdev \\( -perm -4000 -o -perm -2000 \\) -type f 2>/dev/null | head -n 200" },
        CommandSpec { name: "dmesg",                shell: "dmesg | tail -n 500" },
        CommandSpec { name: "env_vars",             shell: "env" },
        CommandSpec { name: "hosts_file",           shell: "cat /etc/hosts; cat /etc/resolv.conf 2>/dev/null" },
    ]
}

#[cfg(target_os = "macos")]
fn command_specs() -> Vec<CommandSpec> {
    vec![
        CommandSpec { name: "time_info",           shell: "date -u; systemsetup -gettimezone 2>/dev/null" },
        CommandSpec { name: "host_info",            shell: "sw_vers; uname -a" },
        CommandSpec { name: "uptime",               shell: "uptime" },
        CommandSpec { name: "logged_in_users",      shell: "who; w" },
        CommandSpec { name: "last_logins",          shell: "last | head -n 100" },
        CommandSpec { name: "processes",            shell: "ps auxww" },
        CommandSpec { name: "open_files",           shell: "lsof -n -P 2>/dev/null | head -n 2000" },
        CommandSpec { name: "network_connections",  shell: "netstat -anv -p tcp; netstat -anv -p udp" },
        CommandSpec { name: "routes",               shell: "netstat -rn" },
        CommandSpec { name: "arp",                  shell: "arp -an" },
        CommandSpec { name: "interfaces",           shell: "ifconfig" },
        CommandSpec { name: "launchd_list",         shell: "launchctl list" },
        CommandSpec { name: "firewall_status",      shell: "/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>/dev/null" },
        CommandSpec { name: "users",                shell: "dscl . list /Users | grep -v '^_'" },
        CommandSpec { name: "admin_group",          shell: "dscl . read /Groups/admin GroupMembership" },
        CommandSpec { name: "suid_files",           shell: "find / -xdev \\( -perm -4000 -o -perm -2000 \\) -type f 2>/dev/null | head -n 200" },
        CommandSpec { name: "quarantine_events",    shell: "sqlite3 ~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2 'select LSQuarantineTimeStamp,LSQuarantineAgentName,LSQuarantineDataURLString from LSQuarantineEvent order by LSQuarantineTimeStamp desc limit 200;' 2>/dev/null || echo 'unavailable'" },
        CommandSpec { name: "env_vars",             shell: "env" },
        CommandSpec { name: "hosts_file",           shell: "cat /etc/hosts" },
        CommandSpec { name: "system_profiler",      shell: "system_profiler SPSoftwareDataType SPHardwareDataType 2>/dev/null" },
    ]
}

#[cfg(target_os = "windows")]
fn artifact_sources() -> Vec<&'static str> {
    // 잠금 없이 직접 복사 가능한 파일만 포함
    // EVTX: collect_windows_evtx() / Registry hives: collect_windows_registry() 에서 별도 처리
    vec![
        "C:/Windows/Prefetch",
        "C:/Windows/System32/drivers/etc/hosts",
    ]
}

#[cfg(target_os = "linux")]
fn artifact_sources() -> Vec<&'static str> {
    vec![
        "/var/log/auth.log",
        "/var/log/secure",
        "/var/log/syslog",
        "/var/log/messages",
        "/var/log/kern.log",
        "/var/log/audit/audit.log",
        "/var/log/dpkg.log",
        "/var/log/apt/history.log",
        "/etc/passwd",
        "/etc/group",
        "/etc/sudoers",
        "/etc/crontab",
        "/etc/ssh/sshd_config",
        "/etc/hosts",
        "/etc/resolv.conf",
        "/etc/systemd/system",
        "/var/spool/cron",
    ]
}

#[cfg(target_os = "macos")]
fn artifact_sources() -> Vec<&'static str> {
    vec![
        "/etc/hosts",
        "/etc/resolv.conf",
        "/Library/LaunchDaemons",
        "/Library/LaunchAgents",
        "/Library/Application Support/com.apple.TCC/TCC.db",
        "/var/db/auth.db",
        "/var/log/install.log",
        "/private/etc/passwd",
        "/private/etc/sudoers",
    ]
}

// ── 브라우저 아티팩트 ──────────────────────────────────────────────────────

/// (사용자명, 브라우저명, 파일 상대경로) 튜플.
/// 실제 경로는 user_home + relative_path 로 조합.
struct BrowserProfile {
    browser: &'static str,
    /// 홈 디렉터리 기준 상대 경로
    relative: &'static str,
    /// 수집 대상 파일 (프로파일 디렉터리 내 상대 경로)
    files: &'static [&'static str],
}

#[cfg(target_os = "windows")]
fn browser_profiles() -> Vec<BrowserProfile> {
    vec![
        BrowserProfile {
            browser: "Chrome",
            relative: r"AppData\Local\Google\Chrome\User Data\Default",
            files: &["History", "Cookies", "Login Data", "Web Data", "Bookmarks", "Extensions"],
        },
        BrowserProfile {
            browser: "Edge",
            relative: r"AppData\Local\Microsoft\Edge\User Data\Default",
            files: &["History", "Cookies", "Login Data", "Web Data", "Bookmarks"],
        },
        BrowserProfile {
            browser: "Brave",
            relative: r"AppData\Local\BraveSoftware\Brave-Browser\User Data\Default",
            files: &["History", "Cookies", "Login Data", "Web Data", "Bookmarks"],
        },
        BrowserProfile {
            browser: "Firefox",
            relative: r"AppData\Roaming\Mozilla\Firefox\Profiles",
            files: &["places.sqlite", "cookies.sqlite", "downloads.sqlite", "logins.json", "key4.db"],
        },
    ]
}

#[cfg(target_os = "linux")]
fn browser_profiles() -> Vec<BrowserProfile> {
    vec![
        BrowserProfile {
            browser: "Chrome",
            relative: ".config/google-chrome/Default",
            files: &["History", "Cookies", "Login Data", "Web Data", "Bookmarks"],
        },
        BrowserProfile {
            browser: "Chromium",
            relative: ".config/chromium/Default",
            files: &["History", "Cookies", "Login Data", "Web Data", "Bookmarks"],
        },
        BrowserProfile {
            browser: "Brave",
            relative: ".config/BraveSoftware/Brave-Browser/Default",
            files: &["History", "Cookies", "Login Data", "Web Data", "Bookmarks"],
        },
        BrowserProfile {
            browser: "Firefox",
            relative: ".mozilla/firefox",
            files: &["places.sqlite", "cookies.sqlite", "logins.json", "key4.db"],
        },
    ]
}

#[cfg(target_os = "macos")]
fn browser_profiles() -> Vec<BrowserProfile> {
    vec![
        BrowserProfile {
            browser: "Chrome",
            relative: "Library/Application Support/Google/Chrome/Default",
            files: &["History", "Cookies", "Login Data", "Web Data", "Bookmarks"],
        },
        BrowserProfile {
            browser: "Edge",
            relative: "Library/Application Support/Microsoft Edge/Default",
            files: &["History", "Cookies", "Login Data", "Web Data", "Bookmarks"],
        },
        BrowserProfile {
            browser: "Brave",
            relative: "Library/Application Support/BraveSoftware/Brave-Browser/Default",
            files: &["History", "Cookies", "Login Data", "Web Data", "Bookmarks"],
        },
        BrowserProfile {
            browser: "Firefox",
            relative: "Library/Application Support/Firefox/Profiles",
            files: &["places.sqlite", "cookies.sqlite", "logins.json", "key4.db"],
        },
        BrowserProfile {
            browser: "Safari",
            relative: "Library/Safari",
            files: &["History.db", "History.db-wal", "History.db-shm", "Downloads.plist", "Bookmarks.plist"],
        },
    ]
}

/// OS별 사용자 홈 디렉터리 목록을 반환한다.
fn enumerate_user_homes() -> Vec<(String, PathBuf)> {
    let mut homes = Vec::new();

    #[cfg(target_os = "windows")]
    {
        let users_dir = PathBuf::from(r"C:\Users");
        let skip = ["Public", "Default", "Default User", "All Users", "desktop.ini"];
        if let Ok(entries) = fs::read_dir(&users_dir) {
            for entry in entries.filter_map(Result::ok) {
                let name = entry.file_name().to_string_lossy().to_string();
                if skip.iter().any(|s| s.eq_ignore_ascii_case(&name)) {
                    continue;
                }
                if entry.path().is_dir() {
                    homes.push((name, entry.path()));
                }
            }
        }
    }

    #[cfg(target_os = "linux")]
    {
        if let Ok(entries) = fs::read_dir("/home") {
            for entry in entries.filter_map(Result::ok) {
                if entry.path().is_dir() {
                    homes.push((entry.file_name().to_string_lossy().to_string(), entry.path()));
                }
            }
        }
        // root 홈
        homes.push(("root".to_string(), PathBuf::from("/root")));
    }

    #[cfg(target_os = "macos")]
    {
        let skip = ["Shared"];
        if let Ok(entries) = fs::read_dir("/Users") {
            for entry in entries.filter_map(Result::ok) {
                let name = entry.file_name().to_string_lossy().to_string();
                if skip.iter().any(|s| s.eq_ignore_ascii_case(&name)) {
                    continue;
                }
                if entry.path().is_dir() {
                    homes.push((name, entry.path()));
                }
            }
        }
    }

    homes
}

/// 브라우저 SQLite/파일 아티팩트를 사용자별로 수집한다.
/// Firefox 처럼 프로파일 디렉터리가 동적 이름인 경우 하위 디렉터리 전체를 순회한다.
fn collect_browser_artifacts(browser_dir: &Path, errors: &mut Vec<String>) -> Vec<ArtifactResult> {
    let mut results = Vec::new();
    let profiles = browser_profiles();
    let homes = enumerate_user_homes();

    for (username, home) in &homes {
        for profile in &profiles {
            let profile_path = home.join(profile.relative);
            if !profile_path.exists() {
                continue;
            }

            // Firefox/동적 프로파일: relative 경로가 디렉터리이고 그 안에 또 프로파일 폴더가 있음
            // → 하위 디렉터리를 한 단계 더 순회
            let search_dirs: Vec<PathBuf> = if profile_path.is_dir() {
                // 직접 대상 파일이 있는지 먼저 확인
                let has_direct = profile.files.iter().any(|f| profile_path.join(f).exists());
                if has_direct {
                    vec![profile_path.clone()]
                } else {
                    // 하위 디렉터리 (Firefox 프로파일 폴더들)
                    fs::read_dir(&profile_path)
                        .map(|rd| {
                            rd.filter_map(Result::ok)
                                .filter(|e| e.path().is_dir())
                                .map(|e| e.path())
                                .collect()
                        })
                        .unwrap_or_default()
                }
            } else {
                continue;
            };

            for dir in &search_dirs {
                for &filename in profile.files {
                    let src = dir.join(filename);
                    if !src.exists() {
                        continue;
                    }

                    // browser/<browser>/<username>/<profile_subdir>/<filename>
                    let profile_label = dir
                        .file_name()
                        .map(|n| n.to_string_lossy().to_string())
                        .unwrap_or_else(|| "default".to_string());

                    let dest_dir = browser_dir
                        .join(profile.browser)
                        .join(sanitize_segment(username))
                        .join(sanitize_segment(&profile_label));

                    if let Err(e) = fs::create_dir_all(&dest_dir) {
                        let msg = format!("mkdir failed for browser {}/{}: {}", profile.browser, username, e);
                        errors.push(msg);
                        continue;
                    }

                    let dest = dest_dir.join(filename);
                    let dest_str = dest.to_string_lossy().to_string();
                    let src_str = src.to_string_lossy().to_string();

                    match fs::copy(&src, &dest) {
                        Ok(_) => {
                            let hash = hash_file(&dest).ok();
                            results.push(ArtifactResult {
                                source: src_str,
                                destination: dest_str,
                                status: "ok".to_string(),
                                sha256: hash,
                                error: None,
                            });
                        }
                        Err(e) => {
                            // 브라우저 실행 중 잠금 여부 구분
                            let (status, msg) = if e.raw_os_error() == Some(32) || e.raw_os_error() == Some(5) {
                                ("locked", format!("browser file locked (browser may be running): {}", src_str))
                            } else {
                                ("copy_error", format!("failed to copy {}: {}", src_str, e))
                            };
                            errors.push(msg.clone());
                            results.push(ArtifactResult {
                                source: src_str,
                                destination: dest_str,
                                status: status.to_string(),
                                sha256: None,
                                error: Some(msg),
                            });
                        }
                    }
                }
            }
        }
    }

    results
}

// ── 권한 확인 ──────────────────────────────────────────────────────────────

#[cfg(target_os = "windows")]
fn is_elevated_windows() -> bool {
    // whoami /groups 에서 S-1-16-12288 (High Mandatory Level) 존재 여부로 판별
    Command::new("whoami")
        .args(["/groups"])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).contains("S-1-16-12288"))
        .unwrap_or(false)
}

#[cfg(not(target_os = "windows"))]
fn is_root_unix() -> bool {
    // UID 0 이면 root
    Command::new("id")
        .arg("-u")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim() == "0")
        .unwrap_or(false)
}
