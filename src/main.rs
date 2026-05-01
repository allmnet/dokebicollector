use std::env;
use std::fs::{self, File};
#[cfg(target_os = "windows")]
use std::io::{self, IsTerminal};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::Command;

use chrono::Utc;
use clap::Parser;
use encoding_rs::EUC_KR;
use serde::Serialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use walkdir::WalkDir;
use zip::write::FileOptions;

#[derive(Parser, Debug)]
#[command(author, version, about = "Cross-platform incident artifact collector")]
struct Args {
    #[arg(short, long, default_value = "collection-output")]
    output: String,

    #[arg(short = 'n', long = "name", default_value = "default")]
    case_name: String,

    #[arg(long, help = "Do not request Windows administrator elevation")]
    no_elevate: bool,
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
    normalized_exports: Vec<ArtifactResult>,
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

const DEVELOPER_SITE: &str = "https://dokebi.org";

fn main() {
    let args = Args::parse();

    #[cfg(target_os = "windows")]
    maybe_request_windows_elevation(&args);

    let started_at = Utc::now();

    print_startup_banner(&args, &started_at.to_rfc3339());

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

    println!("[DOKEBI] Output directory: {}", base_dir.display());

    let command_dir = base_dir.join("commands");
    let artifact_dir = base_dir.join("artifacts");
    for dir in [&command_dir, &artifact_dir] {
        if let Err(e) = fs::create_dir_all(dir) {
            eprintln!("failed to create directory {}: {}", dir.display(), e);
            std::process::exit(1);
        }
    }

    println!("[DOKEBI] Collecting live command outputs...");
    let command_results = collect_commands(&command_dir, &mut errors);
    println!("[DOKEBI] Copying filesystem artifacts...");
    let copied_artifacts = collect_artifacts(&artifact_dir, &mut errors);

    #[cfg(target_os = "windows")]
    let evtx_exports = {
        println!("[DOKEBI] Exporting Windows event logs...");
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
        println!("[DOKEBI] Saving Windows registry hives...");
        let reg_dir = base_dir.join("registry");
        if let Err(e) = fs::create_dir_all(&reg_dir) {
            errors.push(format!("failed to create registry dir: {}", e));
            Vec::new()
        } else {
            collect_windows_registry(&reg_dir, &mut errors)
        }
    };

    let browser_artifacts = {
        println!("[DOKEBI] Collecting browser artifacts...");
        let browser_dir = base_dir.join("browser");
        if let Err(e) = fs::create_dir_all(&browser_dir) {
            errors.push(format!("failed to create browser dir: {}", e));
            Vec::new()
        } else {
            collect_browser_artifacts(&browser_dir, &mut errors)
        }
    };

    println!("[DOKEBI] Writing normalized JSONL exports...");
    let normalized_exports = {
        let normalized_dir = base_dir.join("normalized");
        if let Err(e) = fs::create_dir_all(&normalized_dir) {
            errors.push(format!("failed to create normalized dir: {}", e));
            Vec::new()
        } else {
            let exports = collect_normalized_outputs(
                &normalized_dir,
                &command_results,
                &copied_artifacts,
                &browser_artifacts,
                &artifact_dir,
                &mut errors,
            );

            #[cfg(target_os = "windows")]
            {
                let mut exports = exports;
                let evtx_jsonl_dir = normalized_dir.join("evtx");
                match fs::create_dir_all(&evtx_jsonl_dir) {
                    Ok(_) => {
                        exports.extend(collect_windows_evtx_jsonl(&evtx_jsonl_dir, &mut errors))
                    }
                    Err(e) => errors.push(format!("failed to create normalized evtx dir: {}", e)),
                }
                exports
            }

            #[cfg(not(target_os = "windows"))]
            exports
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
        normalized_exports,
        errors,
    };

    let manifest_path = base_dir.join("collection_manifest.json");
    println!("[DOKEBI] Writing collection manifest...");
    if let Err(e) = write_json(&manifest_path, &manifest) {
        eprintln!("failed to write manifest: {}", e);
        std::process::exit(1);
    }

    let manifest_hash_path = base_dir.join("collection_manifest.sha256");
    match hash_file(&manifest_path) {
        Ok(hash) => {
            if let Err(e) = fs::write(
                &manifest_hash_path,
                format!("{}  collection_manifest.json\n", hash),
            ) {
                eprintln!("failed to write manifest hash: {}", e);
                std::process::exit(1);
            }
        }
        Err(e) => {
            eprintln!("failed to hash manifest: {}", e);
            std::process::exit(1);
        }
    }

    println!("[DOKEBI] Compressing collection output...");
    let archive_path = base_dir.with_extension("zip");
    if let Err(e) = create_zip_archive(&base_dir, &archive_path) {
        eprintln!("failed to create zip archive: {}", e);
        std::process::exit(1);
    }

    let archive_hash_path = PathBuf::from(format!("{}.sha256", archive_path.to_string_lossy()));
    match hash_file(&archive_path) {
        Ok(hash) => {
            let archive_name = archive_path
                .file_name()
                .map(|name| name.to_string_lossy().to_string())
                .unwrap_or_else(|| archive_path.to_string_lossy().to_string());
            if let Err(e) = fs::write(&archive_hash_path, format!("{}  {}\n", hash, archive_name)) {
                eprintln!("failed to write zip archive hash: {}", e);
                std::process::exit(1);
            }
        }
        Err(e) => {
            eprintln!("failed to hash zip archive: {}", e);
            std::process::exit(1);
        }
    }

    println!("[DOKEBI] Collection completed: {}", base_dir.display());
    println!("[DOKEBI] Manifest: {}", manifest_path.display());
    println!("[DOKEBI] Archive: {}", archive_path.display());
    println!("[DOKEBI] Archive SHA-256: {}", archive_hash_path.display());
    println!("[DOKEBI] Developer site: {}", DEVELOPER_SITE);
}

fn print_startup_banner(args: &Args, started_at_utc: &str) {
    println!("============================================================");
    println!("  DOKEBI Collector v{}", env!("CARGO_PKG_VERSION"));
    println!("  Cross-platform incident artifact collector");
    println!("  Developer site: {}", DEVELOPER_SITE);
    println!("------------------------------------------------------------");
    println!("  Case name : {}", args.case_name);
    println!("  Output    : {}", args.output);
    println!("  OS        : {}", env::consts::OS);
    println!("  Started   : {}", started_at_utc);
    println!("------------------------------------------------------------");
    println!("  This tool collects live system state, logs, registry or");
    println!("  platform artifacts, browser traces, and SHA-256 hashes for");
    println!("  incident response triage. Run with elevated privileges for");
    println!("  the most complete collection.");
    println!("============================================================");
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
                let status = if code.unwrap_or(1) == 0 {
                    "ok"
                } else {
                    "command_error"
                };

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
            let parent = dest
                .parent()
                .map(Path::to_path_buf)
                .unwrap_or_else(|| artifact_dir.to_path_buf());
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
            for entry in WalkDir::new(&src)
                .follow_links(false)
                .into_iter()
                .filter_map(Result::ok)
            {
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
                status: if copied_any {
                    "ok".to_string()
                } else {
                    "empty_or_unreadable".to_string()
                },
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

fn collect_normalized_outputs(
    normalized_dir: &Path,
    command_results: &[CommandResult],
    copied_artifacts: &[ArtifactResult],
    browser_artifacts: &[ArtifactResult],
    artifact_dir: &Path,
    errors: &mut Vec<String>,
) -> Vec<ArtifactResult> {
    let mut results = Vec::new();

    let commands_path = normalized_dir.join("commands.jsonl");
    results.push(write_normalized_file(
        "commands",
        &commands_path,
        errors,
        |writer| write_command_lines_jsonl(writer, command_results),
    ));

    let items_path = normalized_dir.join("collection_items.jsonl");
    results.push(write_normalized_file(
        "collection_items",
        &items_path,
        errors,
        |writer| {
            write_collection_items_jsonl(
                writer,
                command_results,
                copied_artifacts,
                browser_artifacts,
            )
        },
    ));

    let file_lines_path = normalized_dir.join("file_lines.jsonl");
    results.push(write_normalized_file(
        "file_lines",
        &file_lines_path,
        errors,
        |writer| write_text_artifact_lines_jsonl(writer, artifact_dir),
    ));

    results
}

fn write_normalized_file<F>(
    source: &str,
    path: &Path,
    errors: &mut Vec<String>,
    writer_fn: F,
) -> ArtifactResult
where
    F: FnOnce(&mut File) -> Result<(), String>,
{
    let destination = path.to_string_lossy().to_string();
    match File::create(path) {
        Ok(mut file) => {
            match writer_fn(&mut file).and_then(|_| file.flush().map_err(|e| e.to_string())) {
                Ok(_) => ArtifactResult {
                    source: source.to_string(),
                    destination,
                    status: "ok".to_string(),
                    sha256: hash_file(path).ok(),
                    error: None,
                },
                Err(e) => {
                    let msg = format!("failed writing normalized {}: {}", source, e);
                    errors.push(msg.clone());
                    ArtifactResult {
                        source: source.to_string(),
                        destination,
                        status: "write_error".to_string(),
                        sha256: None,
                        error: Some(msg),
                    }
                }
            }
        }
        Err(e) => {
            let msg = format!("failed creating normalized {}: {}", source, e);
            errors.push(msg.clone());
            ArtifactResult {
                source: source.to_string(),
                destination,
                status: "write_error".to_string(),
                sha256: None,
                error: Some(msg),
            }
        }
    }
}

fn write_command_lines_jsonl(
    writer: &mut File,
    command_results: &[CommandResult],
) -> Result<(), String> {
    for result in command_results {
        let path = Path::new(&result.output_file);
        if !path.exists() {
            continue;
        }

        let bytes = fs::read(path).map_err(|e| e.to_string())?;
        let content = decode_command_output(bytes);
        for (index, line) in content.lines().enumerate() {
            write_json_line(
                writer,
                json!({
                    "schema": "dokebi.command_line.v1",
                    "os": env::consts::OS,
                    "source_type": "command",
                    "source": result.name,
                    "command": result.command,
                    "status": result.status,
                    "exit_code": result.exit_code,
                    "output_file": result.output_file,
                    "line_number": index + 1,
                    "text": line,
                }),
            )?;
        }
    }
    Ok(())
}

fn write_collection_items_jsonl(
    writer: &mut File,
    command_results: &[CommandResult],
    copied_artifacts: &[ArtifactResult],
    browser_artifacts: &[ArtifactResult],
) -> Result<(), String> {
    for result in command_results {
        write_json_line(
            writer,
            json!({
                "schema": "dokebi.collection_item.v1",
                "os": env::consts::OS,
                "source_type": "command",
                "source": result.name,
                "destination": result.output_file,
                "status": result.status,
                "sha256": result.sha256,
                "error": result.error,
            }),
        )?;
    }

    for (source_type, artifacts) in [
        ("artifact", copied_artifacts),
        ("browser_artifact", browser_artifacts),
    ] {
        for artifact in artifacts {
            write_json_line(
                writer,
                json!({
                    "schema": "dokebi.collection_item.v1",
                    "os": env::consts::OS,
                    "source_type": source_type,
                    "source": artifact.source,
                    "destination": artifact.destination,
                    "status": artifact.status,
                    "sha256": artifact.sha256,
                    "error": artifact.error,
                }),
            )?;
        }
    }

    Ok(())
}

fn write_text_artifact_lines_jsonl(writer: &mut File, artifact_dir: &Path) -> Result<(), String> {
    if !artifact_dir.exists() {
        return Ok(());
    }

    for entry in WalkDir::new(artifact_dir).follow_links(false) {
        let entry = entry.map_err(|e| e.to_string())?;
        if !entry.file_type().is_file() {
            continue;
        }

        let metadata = entry.metadata().map_err(|e| e.to_string())?;
        if metadata.len() > 50 * 1024 * 1024 {
            continue;
        }

        let bytes = fs::read(entry.path()).map_err(|e| e.to_string())?;
        if !is_probably_text(&bytes) {
            continue;
        }

        let content = decode_command_output(bytes);
        let source = entry.path().to_string_lossy().to_string();
        for (index, line) in content.lines().enumerate() {
            write_json_line(
                writer,
                json!({
                    "schema": "dokebi.file_line.v1",
                    "os": env::consts::OS,
                    "source_type": "artifact_file",
                    "source": source,
                    "line_number": index + 1,
                    "text": line,
                }),
            )?;
        }
    }

    Ok(())
}

fn is_probably_text(bytes: &[u8]) -> bool {
    let sample_len = bytes.len().min(8192);
    if sample_len == 0 {
        return true;
    }
    let nul_count = bytes[..sample_len]
        .iter()
        .filter(|byte| **byte == 0)
        .count();
    nul_count == 0
}

fn write_json_line(writer: &mut File, value: serde_json::Value) -> Result<(), String> {
    serde_json::to_writer(&mut *writer, &value).map_err(|e| e.to_string())?;
    writer.write_all(b"\n").map_err(|e| e.to_string())
}

#[cfg(target_os = "windows")]
fn collect_windows_evtx_jsonl(
    evtx_jsonl_dir: &Path,
    errors: &mut Vec<String>,
) -> Vec<ArtifactResult> {
    let mut results = Vec::new();
    for (channel, filename) in evtx_channels() {
        let path = evtx_jsonl_dir.join(format!("{}.jsonl", filename));
        let destination = path.to_string_lossy().to_string();
        let output = Command::new("wevtutil")
            .args(["qe", channel, "/f:xml", "/rd:true"])
            .output();

        match output {
            Ok(out) => {
                let code = out.status.code().unwrap_or(-1);
                if code == 0 {
                    let xml = decode_command_output(out.stdout);
                    let write_result = File::create(&path)
                        .map_err(|e| e.to_string())
                        .and_then(|mut file| write_evtx_xml_jsonl(&mut file, channel, &xml));

                    match write_result {
                        Ok(_) => results.push(ArtifactResult {
                            source: channel.to_string(),
                            destination,
                            status: "ok".to_string(),
                            sha256: hash_file(&path).ok(),
                            error: None,
                        }),
                        Err(e) => {
                            let msg = format!("failed writing normalized evtx {}: {}", channel, e);
                            errors.push(msg.clone());
                            results.push(ArtifactResult {
                                source: channel.to_string(),
                                destination,
                                status: "write_error".to_string(),
                                sha256: None,
                                error: Some(msg),
                            });
                        }
                    }
                } else {
                    let stderr = decode_command_output(out.stderr);
                    let status = if stderr.contains("No events were found")
                        || stderr.contains("cannot find")
                        || stderr.contains("지정한 로그")
                    {
                        "not_found"
                    } else {
                        "error"
                    };
                    let msg = format!(
                        "wevtutil qe {} failed (code {}): {}",
                        channel,
                        code,
                        stderr.trim()
                    );
                    if status == "error" {
                        errors.push(msg.clone());
                    }
                    results.push(ArtifactResult {
                        source: channel.to_string(),
                        destination,
                        status: status.to_string(),
                        sha256: None,
                        error: Some(msg),
                    });
                }
            }
            Err(e) => {
                let msg = format!("failed to run wevtutil qe for {}: {}", channel, e);
                errors.push(msg.clone());
                results.push(ArtifactResult {
                    source: channel.to_string(),
                    destination,
                    status: "exec_error".to_string(),
                    sha256: None,
                    error: Some(msg),
                });
            }
        }
    }
    results
}

#[cfg(target_os = "windows")]
fn write_evtx_xml_jsonl(writer: &mut File, channel: &str, xml: &str) -> Result<(), String> {
    for event in xml.split("<Event ").skip(1) {
        let event = format!("<Event {}", event);
        write_json_line(
            writer,
            json!({
                "schema": "dokebi.event.v1",
                "os": "windows",
                "source_type": "evtx",
                "source": channel,
                "timestamp_utc": extract_xml_attr(&event, "TimeCreated", "SystemTime"),
                "event_id": extract_xml_tag_text(&event, "EventID").and_then(|value| value.parse::<u32>().ok()),
                "provider": extract_xml_attr(&event, "Provider", "Name"),
                "level": extract_xml_tag_text(&event, "Level"),
                "task": extract_xml_tag_text(&event, "Task"),
                "opcode": extract_xml_tag_text(&event, "Opcode"),
                "keywords": extract_xml_tag_text(&event, "Keywords"),
                "record_id": extract_xml_tag_text(&event, "EventRecordID").and_then(|value| value.parse::<u64>().ok()),
                "process_id": extract_xml_attr(&event, "Execution", "ProcessID").and_then(|value| value.parse::<u32>().ok()),
                "thread_id": extract_xml_attr(&event, "Execution", "ThreadID").and_then(|value| value.parse::<u32>().ok()),
                "computer": extract_xml_tag_text(&event, "Computer"),
                "user_id": extract_xml_attr(&event, "Security", "UserID"),
                "event_data": extract_event_data(&event),
            }),
        )?;
    }
    Ok(())
}

#[cfg(target_os = "windows")]
fn extract_xml_tag_text(xml: &str, tag: &str) -> Option<String> {
    let start_pattern = format!("<{}", tag);
    let start = xml.find(&start_pattern)?;
    let after_start = &xml[start..];
    let text_start = after_start.find('>')? + 1;
    let after_text_start = &after_start[text_start..];
    let end_pattern = format!("</{}>", tag);
    let end = after_text_start.find(&end_pattern)?;
    Some(xml_unescape(after_text_start[..end].trim()))
}

#[cfg(target_os = "windows")]
fn extract_xml_attr(xml: &str, tag: &str, attr: &str) -> Option<String> {
    let tag_pattern = format!("<{}", tag);
    let start = xml.find(&tag_pattern)?;
    let after_start = &xml[start..];
    let tag_end = after_start.find('>')?;
    let tag_text = &after_start[..tag_end];
    extract_attr_from_tag(tag_text, attr)
}

#[cfg(target_os = "windows")]
fn extract_attr_from_tag(tag_text: &str, attr: &str) -> Option<String> {
    let attr_pattern = format!("{}=", attr);
    let start = tag_text.find(&attr_pattern)? + attr_pattern.len();
    let quote = tag_text[start..].chars().next()?;
    if quote != '\'' && quote != '"' {
        return None;
    }
    let value_start = start + quote.len_utf8();
    let value_end = tag_text[value_start..].find(quote)? + value_start;
    Some(xml_unescape(&tag_text[value_start..value_end]))
}

#[cfg(target_os = "windows")]
fn extract_event_data(xml: &str) -> Vec<serde_json::Value> {
    let mut data = Vec::new();
    let mut remaining = xml;
    while let Some(start) = remaining.find("<Data") {
        remaining = &remaining[start..];
        let Some(tag_end) = remaining.find('>') else {
            break;
        };
        let tag_text = &remaining[..tag_end];
        let value_start = tag_end + 1;
        let Some(value_end) = remaining[value_start..].find("</Data>") else {
            break;
        };
        let value = xml_unescape(remaining[value_start..value_start + value_end].trim());
        data.push(json!({
            "name": extract_attr_from_tag(tag_text, "Name"),
            "value": value,
        }));
        remaining = &remaining[value_start + value_end + "</Data>".len()..];
    }
    data
}

#[cfg(target_os = "windows")]
fn xml_unescape(value: &str) -> String {
    value
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&amp;", "&")
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

fn create_zip_archive(source_dir: &Path, archive_path: &Path) -> Result<(), String> {
    if archive_path.exists() {
        fs::remove_file(archive_path).map_err(|e| e.to_string())?;
    }

    let archive_file = File::create(archive_path).map_err(|e| e.to_string())?;
    let mut zip = zip::ZipWriter::new(archive_file);
    let options = FileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated)
        .unix_permissions(0o644);

    let archive_root = source_dir.parent().unwrap_or(source_dir);
    let mut buffer = Vec::new();

    for entry in WalkDir::new(source_dir).follow_links(false) {
        let entry = entry.map_err(|e| e.to_string())?;
        let path = entry.path();
        let name = path_to_zip_name(path.strip_prefix(archive_root).map_err(|e| e.to_string())?);

        if entry.file_type().is_dir() {
            if !name.is_empty() {
                zip.add_directory(format!("{}/", name), options)
                    .map_err(|e| e.to_string())?;
            }
            continue;
        }

        if !entry.file_type().is_file() {
            continue;
        }

        zip.start_file(name, options).map_err(|e| e.to_string())?;
        let mut file = File::open(path).map_err(|e| e.to_string())?;
        file.read_to_end(&mut buffer).map_err(|e| e.to_string())?;
        zip.write_all(&buffer).map_err(|e| e.to_string())?;
        buffer.clear();
    }

    zip.finish().map_err(|e| e.to_string())?;
    Ok(())
}

fn path_to_zip_name(path: &Path) -> String {
    path.components()
        .map(|component| component.as_os_str().to_string_lossy())
        .collect::<Vec<_>>()
        .join("/")
}

fn run_shell_command(command: &str) -> Result<(String, String, Option<i32>), String> {
    #[cfg(target_os = "windows")]
    let output = Command::new("powershell")
        .arg("-NoProfile")
        .arg("-ExecutionPolicy")
        .arg("Bypass")
        .arg("-Command")
        .arg(windows_utf8_powershell_command(command))
        .output()
        .map_err(|e| e.to_string())?;

    #[cfg(not(target_os = "windows"))]
    let output = Command::new("sh")
        .arg("-c")
        .arg(command)
        .output()
        .map_err(|e| e.to_string())?;

    let stdout = decode_command_output(output.stdout);
    let stderr = decode_command_output(output.stderr);
    Ok((stdout, stderr, output.status.code()))
}

#[cfg(target_os = "windows")]
fn windows_utf8_powershell_command(command: &str) -> String {
    format!(
        "[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false); \
         $OutputEncoding = [System.Text.UTF8Encoding]::new($false); \
         {}",
        command
    )
}

fn decode_command_output(bytes: Vec<u8>) -> String {
    if let Ok(value) = String::from_utf8(bytes.clone()) {
        return value;
    }

    let mut decoded = String::new();
    for segment in bytes.split_inclusive(|byte| *byte == b'\n') {
        decoded.push_str(&decode_command_output_segment(segment));
    }
    decoded
}

fn decode_command_output_segment(bytes: &[u8]) -> String {
    match std::str::from_utf8(bytes) {
        Ok(value) => value.to_string(),
        Err(_) => {
            let (decoded, _, had_errors) = EUC_KR.decode(bytes);
            if had_errors {
                String::from_utf8_lossy(bytes).to_string()
            } else {
                decoded.into_owned()
            }
        }
    }
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
        ("Security", "Security"),
        ("System", "System"),
        ("Application", "Application"),
        ("Microsoft-Windows-Sysmon/Operational", "Sysmon_Operational"),
        (
            "Microsoft-Windows-PowerShell/Operational",
            "PowerShell_Operational",
        ),
        ("Windows PowerShell", "Windows_PowerShell"),
        (
            "Microsoft-Windows-TaskScheduler/Operational",
            "TaskScheduler_Operational",
        ),
        (
            "Microsoft-Windows-WMI-Activity/Operational",
            "WMI_Operational",
        ),
        (
            "Microsoft-Windows-Windows Defender/Operational",
            "Defender_Operational",
        ),
        (
            "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational",
            "RDP_RemoteConnectionManager",
        ),
        (
            "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
            "RDP_LocalSessionManager",
        ),
        (
            "Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational",
            "RDP_CoreTS",
        ),
        ("Microsoft-Windows-Bits-Client/Operational", "BITS_Client"),
        ("Microsoft-Windows-DNSClient/Operational", "DNS_Client"),
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
                    let stderr = decode_command_output(out.stderr);
                    let hint = if code == 5 {
                        " (requires Administrator)"
                    } else {
                        ""
                    };
                    let msg = format!(
                        "wevtutil epl {} failed (code {}){}: {}",
                        channel,
                        code,
                        hint,
                        stderr.trim()
                    );
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
        ("HKLM\\SAM", "SAM"),
        ("HKLM\\SYSTEM", "SYSTEM"),
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
                    let stderr = decode_command_output(out.stderr);
                    let stdout = decode_command_output(out.stdout);
                    let msg = format!(
                        "reg save {} failed (code {}): {} {}",
                        hive,
                        code,
                        stderr.trim(),
                        stdout.trim()
                    );
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
        CommandSpec {
            name: "time_info",
            shell: "date -u; timedatectl status 2>/dev/null || true",
        },
        CommandSpec {
            name: "host_info",
            shell: "uname -a; cat /etc/os-release 2>/dev/null; hostnamectl 2>/dev/null || true",
        },
        CommandSpec {
            name: "uptime",
            shell: "uptime",
        },
        CommandSpec {
            name: "logged_in_users",
            shell: "who; w",
        },
        CommandSpec {
            name: "last_logins",
            shell: "last | head -n 100",
        },
        CommandSpec {
            name: "failed_logins",
            shell: "lastb 2>/dev/null | head -n 100 || echo 'lastb unavailable'",
        },
        CommandSpec {
            name: "processes",
            shell: "ps auxwwf",
        },
        CommandSpec {
            name: "open_files",
            shell: "lsof -n -P 2>/dev/null | head -n 2000 || ss -pant",
        },
        CommandSpec {
            name: "network_connections",
            shell: "ss -pant",
        },
        CommandSpec {
            name: "routes",
            shell: "ip route",
        },
        CommandSpec {
            name: "neighbors",
            shell: "ip neigh",
        },
        CommandSpec {
            name: "interfaces",
            shell: "ip addr",
        },
        CommandSpec {
            name: "iptables",
            shell: "iptables -S 2>/dev/null || echo 'unavailable'",
        },
        CommandSpec {
            name: "nftables",
            shell: "nft list ruleset 2>/dev/null || echo 'unavailable'",
        },
        CommandSpec {
            name: "systemd_units",
            shell: "systemctl list-units --all 2>/dev/null || true",
        },
        CommandSpec {
            name: "systemd_failed",
            shell: "systemctl --failed 2>/dev/null || true",
        },
        CommandSpec {
            name: "crontab_root",
            shell: "crontab -l 2>/dev/null; ls -la /etc/cron* /var/spool/cron/ 2>/dev/null",
        },
        CommandSpec {
            name: "sudoers",
            shell: "cat /etc/sudoers 2>/dev/null; ls /etc/sudoers.d/ 2>/dev/null",
        },
        CommandSpec {
            name: "passwd_shadow",
            shell: "cat /etc/passwd; getent group",
        },
        CommandSpec {
            name: "suid_sgid_files",
            shell:
                "find / -xdev \\( -perm -4000 -o -perm -2000 \\) -type f 2>/dev/null | head -n 200",
        },
        CommandSpec {
            name: "dmesg",
            shell: "dmesg | tail -n 500",
        },
        CommandSpec {
            name: "env_vars",
            shell: "env",
        },
        CommandSpec {
            name: "hosts_file",
            shell: "cat /etc/hosts; cat /etc/resolv.conf 2>/dev/null",
        },
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
            files: &[
                "History",
                "Cookies",
                "Login Data",
                "Web Data",
                "Bookmarks",
                "Extensions",
            ],
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
            files: &[
                "places.sqlite",
                "cookies.sqlite",
                "downloads.sqlite",
                "logins.json",
                "key4.db",
            ],
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
            files: &[
                "History.db",
                "History.db-wal",
                "History.db-shm",
                "Downloads.plist",
                "Bookmarks.plist",
            ],
        },
    ]
}

/// OS별 사용자 홈 디렉터리 목록을 반환한다.
fn enumerate_user_homes() -> Vec<(String, PathBuf)> {
    let mut homes = Vec::new();

    #[cfg(target_os = "windows")]
    {
        let users_dir = PathBuf::from(r"C:\Users");
        let skip = [
            "Public",
            "Default",
            "Default User",
            "All Users",
            "desktop.ini",
        ];
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
                    homes.push((
                        entry.file_name().to_string_lossy().to_string(),
                        entry.path(),
                    ));
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
                        let msg = format!(
                            "mkdir failed for browser {}/{}: {}",
                            profile.browser, username, e
                        );
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
                            let (status, msg) =
                                if e.raw_os_error() == Some(32) || e.raw_os_error() == Some(5) {
                                    (
                                        "locked",
                                        format!(
                                            "browser file locked (browser may be running): {}",
                                            src_str
                                        ),
                                    )
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
fn maybe_request_windows_elevation(args: &Args) {
    if args.no_elevate || env::var("DOKEBI_SKIP_ELEVATION").ok().as_deref() == Some("1") {
        return;
    }
    if is_elevated_windows() || !is_interactive_gui_session_windows() {
        return;
    }

    println!("[DOKEBI] Administrator privileges are recommended for full Windows collection.");
    println!(
        "[DOKEBI] Security EVTX, registry hives, and Prefetch may be incomplete without elevation."
    );

    let should_request = if io::stdin().is_terminal() {
        print!("[DOKEBI] Request administrator privileges with UAC now? [Y/n]: ");
        let _ = io::stdout().flush();

        let mut answer = String::new();
        match io::stdin().read_line(&mut answer) {
            Ok(_) => {
                let answer = answer.trim().to_ascii_lowercase();
                answer.is_empty() || answer == "y" || answer == "yes"
            }
            Err(_) => false,
        }
    } else {
        true
    };

    if !should_request {
        println!("[DOKEBI] Continuing without administrator privileges.");
        return;
    }

    match relaunch_windows_as_admin() {
        Ok(code) => std::process::exit(code),
        Err(e) => {
            eprintln!("[DOKEBI] Administrator elevation request failed: {}", e);
            eprintln!("[DOKEBI] Continuing without administrator privileges.");
        }
    }
}

#[cfg(target_os = "windows")]
fn is_interactive_gui_session_windows() -> bool {
    if env::var("SESSIONNAME")
        .map(|v| v.eq_ignore_ascii_case("services"))
        .unwrap_or(false)
    {
        return false;
    }

    env::var("USERPROFILE").is_ok() && env::var("WINDIR").is_ok()
}

#[cfg(target_os = "windows")]
fn relaunch_windows_as_admin() -> Result<i32, String> {
    let exe = env::current_exe().map_err(|e| e.to_string())?;
    let args = env::args_os()
        .skip(1)
        .map(|arg| windows_quote_arg(&arg.to_string_lossy()))
        .collect::<Vec<_>>()
        .join(" ");

    let start_process = if args.is_empty() {
        format!(
            "Start-Process -FilePath {} -Verb RunAs -Wait -PassThru",
            powershell_quote(&exe.to_string_lossy())
        )
    } else {
        format!(
            "Start-Process -FilePath {} -ArgumentList {} -Verb RunAs -Wait -PassThru",
            powershell_quote(&exe.to_string_lossy()),
            powershell_quote(&args)
        )
    };

    let command = format!(
        "$ErrorActionPreference = 'Stop'; try {{ $p = {}; if ($null -eq $p) {{ exit 1223 }}; exit $p.ExitCode }} catch {{ Write-Error $_; exit 1223 }}",
        start_process
    );

    let status = Command::new("powershell")
        .arg("-NoProfile")
        .arg("-ExecutionPolicy")
        .arg("Bypass")
        .arg("-Command")
        .arg(command)
        .status()
        .map_err(|e| e.to_string())?;

    let code = status.code().unwrap_or(1);
    if code == 1223 {
        Err("UAC elevation was cancelled or could not be started".to_string())
    } else {
        Ok(code)
    }
}

#[cfg(target_os = "windows")]
fn powershell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

#[cfg(target_os = "windows")]
fn windows_quote_arg(value: &str) -> String {
    if value.is_empty() {
        return "\"\"".to_string();
    }
    if !value.chars().any(|c| c.is_whitespace() || c == '"') {
        return value.to_string();
    }

    let mut quoted = String::from("\"");
    let mut backslashes = 0;
    for ch in value.chars() {
        match ch {
            '\\' => backslashes += 1,
            '"' => {
                quoted.push_str(&"\\".repeat(backslashes * 2 + 1));
                quoted.push('"');
                backslashes = 0;
            }
            _ => {
                quoted.push_str(&"\\".repeat(backslashes));
                backslashes = 0;
                quoted.push(ch);
            }
        }
    }
    quoted.push_str(&"\\".repeat(backslashes * 2));
    quoted.push('"');
    quoted
}

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
