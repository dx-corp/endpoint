//! `merlin check`: readiness and capability probe for the sensor host.

use std::ffi::CStr;
use std::io::Write;
use std::path::PathBuf;

use aya::Ebpf;

use crate::{fanotify_mon, portability, telemetry};

fn kernel_release() -> String {
    unsafe {
        let mut uts: libc::utsname = std::mem::zeroed();
        libc::uname(&mut uts);
        CStr::from_ptr(uts.release.as_ptr())
            .to_string_lossy()
            .into_owned()
    }
}

/// Run all checks, print one line each (or a machine-readable capability
/// report), and return overall readiness.
pub async fn run(ebpf_path: Option<PathBuf>, json: bool) -> anyhow::Result<bool> {
    let mut checks = Vec::new();
    let kernel = kernel_release();
    let portability = portability::probe();

    if !json {
        println!("kernel: {kernel}");
    }

    check_line(
        &mut checks,
        json,
        "syscall_abi",
        portability.abi.is_some(),
        &format!("{} ({})", portability.abi_name(), portability.arch),
    );
    check_line(
        &mut checks,
        json,
        "tracepoint_layout",
        portability.tracepoints.iter().all(|check| check.ok),
        &portability.summary(),
    );
    for tracepoint in &portability.tracepoints {
        check_line(
            &mut checks,
            json,
            &format!(
                "tracepoint_layout/{}/{}",
                tracepoint.group, tracepoint.event
            ),
            tracepoint.ok,
            &tracepoint.reason,
        );
    }

    let is_root = unsafe { libc::geteuid() } == 0;
    let mut ok = portability.ready();
    check_line(
        &mut checks,
        json,
        "privileged_runtime",
        is_root,
        if is_root {
            "root available for fanotify/eBPF"
        } else {
            "run with sudo"
        },
    );
    if !is_root {
        finish(json, false, &kernel, checks);
        return Ok(false);
    }

    match fanotify_mon::init_and_mark("/") {
        Ok(fd) => {
            check_line(
                &mut checks,
                json,
                "exec_prevention",
                true,
                "fanotify FAN_OPEN_EXEC_PERM is available",
            );
            unsafe { libc::close(fd) };
        }
        Err(e) => {
            check_line(
                &mut checks,
                json,
                "exec_prevention",
                false,
                &format!("fanotify unavailable: {e:#}"),
            );
            ok = false;
        }
    }

    match &ebpf_path {
        Some(p) if p.exists() => check_line(
            &mut checks,
            json,
            "ebpf_object",
            true,
            &format!("{} found", p.display()),
        ),
        Some(p) => {
            check_line(
                &mut checks,
                json,
                "ebpf_object",
                false,
                &format!("not found: {}", p.display()),
            );
            ok = false;
        }
        None => {
            check_line(
                &mut checks,
                json,
                "ebpf_object",
                false,
                "not found; pass --ebpf",
            );
            ok = false;
        }
    }

    if let Some(p) = ebpf_path.filter(|p| p.exists()) {
        let result = Ebpf::load_file(&p)
            .map_err(|e| anyhow::anyhow!(e))
            .and_then(|mut bpf| telemetry::attach_all(&mut bpf));
        match result {
            // bpf is dropped here, detaching everything again.
            Ok(()) => check_line(
                &mut checks,
                json,
                "ebpf_capture",
                true,
                "exec/fork/exit/socket/security/memfd programs load and attach",
            ),
            Err(e) => {
                check_line(
                    &mut checks,
                    json,
                    "ebpf_capture",
                    false,
                    &format!("load/attach failed: {e:#}"),
                );
                ok = false;
            }
        }
    }

    // These are explicit run-time modes rather than optimistic claims that a
    // host has a kernel feature. The watcher is userspace metadata-only and
    // the loss mode documents the bounded fail-open contract.
    check_line(
        &mut checks,
        json,
        "persistence_inventory",
        true,
        "bounded metadata-only watch is available at run time",
    );
    check_line(
        &mut checks,
        json,
        "loss_behavior",
        true,
        "ring/channel backpressure remains bounded and fail-open",
    );
    check_line(
        &mut checks,
        json,
        "fleet_health",
        true,
        "periodic health events expose capture capability and spool loss counters",
    );
    finish(json, ok, &kernel, checks);
    Ok(ok)
}

fn check_line(
    checks: &mut Vec<serde_json::Value>,
    json: bool,
    capability: &str,
    pass: bool,
    reason: &str,
) {
    let status = if pass { "pass" } else { "fail" };
    checks.push(serde_json::json!({
        "capability": capability,
        "status": status,
        "reason": reason,
    }));
    if !json {
        println!("{capability}: {status} ({reason})");
    }
}

fn finish(json: bool, ready: bool, kernel: &str, checks: Vec<serde_json::Value>) {
    if json {
        println!(
            "{}",
            serde_json::json!({"ready": ready, "kernel": kernel, "capabilities": checks})
        );
    } else {
        println!("READY: {}", if ready { "yes" } else { "no" });
    }
    let _ = std::io::stdout().flush();
}
