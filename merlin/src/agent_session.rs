//! Agent session attribution: which AI agent a program runs under.
//!
//! The names come from the collection manifest (every `cli` row of
//! ai_locations and the `ai_agent_processes` rows), never from code. An
//! event's process, or its nearest ancestor that runs under one of those
//! names, is the agent; the event gains `agent` (the client) and
//! `agent_session` (that agent process's process key). MCP stdio servers are
//! the agent's children, so what they do is attributed too. Nothing else
//! about the agent leaves the computer: no command line, no prompt, no
//! account.

use std::sync::{LazyLock, Mutex};

use serde_json::Value;

use crate::manifest::AiAgentProcess;
use crate::proctree::{AgentProcess, ProcInfo, ProcTable};
use crate::spool;

/// The kernel keeps a process name in 16 bytes, the last a NUL.
const COMM_LEN: usize = 15;

static NAMES: LazyLock<Vec<AiAgentProcess>> = LazyLock::new(|| AiAgentProcess::all().collect());

/// The client `info` runs as, when its kernel name (the first 15 bytes of a
/// declared name) or its executable's file name is a declared agent name.
pub fn client_of(info: &ProcInfo) -> Option<&'static str> {
    client_in(&NAMES, info)
}

fn client_in(names: &[AiAgentProcess], info: &ProcInfo) -> Option<&'static str> {
    let comm = info.comm.as_deref();
    let exe = info
        .exe
        .as_deref()
        .and_then(|exe| exe.rsplit('/').next())
        .map(|base| base.strip_suffix(" (deleted)").unwrap_or(base));
    names
        .iter()
        .find(|p| {
            let short = p.name.get(..COMM_LEN).unwrap_or(p.name);
            comm == Some(short) || exe == Some(p.name)
        })
        .map(|p| p.client)
}

/// The agent `pid` runs under, from the shared process table. None when the
/// pid is not valid in this namespace or no agent is in its chain.
pub fn agent_for(table: &Mutex<ProcTable>, pid: Option<u32>) -> Option<AgentProcess> {
    let pid = pid.filter(|p| *p > 0)?;
    table
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .agent_of(pid, client_of)
}

/// Add `agent` and `agent_session` to an event when it has an agent. The
/// keys are absent otherwise, which keeps the common line short.
pub fn stamp(event: &mut Value, agent: Option<AgentProcess>) {
    let (Some(agent), Some(object)) = (agent, event.as_object_mut()) else {
        return;
    };
    object.insert("agent".into(), Value::from(agent.client));
    object.insert(
        "agent_session".into(),
        Value::from(spool::process_key(agent.pid, agent.start_time)),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn proc(pid_parent: u32, start: u64, comm: &str, exe: &str) -> ProcInfo {
        ProcInfo {
            start_time: start,
            ppid: Some(pid_parent),
            comm: Some(comm.into()),
            exe: Some(exe.into()),
            ..Default::default()
        }
    }

    /// systemd(1) <- bash(10) <- claude(20) <- npx(30) <- node(40, an MCP
    /// server) <- curl(50); and bash(11) <- curl(60) outside any agent.
    fn table() -> ProcTable {
        let mut t = ProcTable::default();
        t.upsert(1, proc(0, 1, "systemd", "/usr/lib/systemd/systemd"));
        t.upsert(10, proc(1, 5, "bash", "/usr/bin/bash"));
        t.upsert(
            20,
            proc(
                10,
                700,
                "claude",
                "/home/u/.local/share/claude/versions/2.1.3",
            ),
        );
        t.upsert(30, proc(20, 710, "npm exec", "/usr/bin/node"));
        t.upsert(40, proc(30, 720, "node", "/usr/bin/node"));
        t.upsert(50, proc(40, 730, "curl", "/usr/bin/curl"));
        t.upsert(11, proc(1, 6, "bash", "/usr/bin/bash"));
        t.upsert(60, proc(11, 740, "curl", "/usr/bin/curl"));
        t
    }

    #[test]
    fn every_declared_cli_name_and_agent_process_name_is_an_agent() {
        let names: Vec<AiAgentProcess> = AiAgentProcess::all().collect();
        assert!(names.iter().any(|p| p.name == "claude"));
        for p in &names {
            let info = proc(1, 1, p.name, &format!("/opt/x/{}", p.name));
            assert_eq!(client_of(&info), Some(p.client), "{}", p.name);
        }
    }

    #[test]
    fn an_mcp_server_child_of_an_agent_is_attributed_to_that_agent_session() {
        let mut t = table();
        let agent = t.agent_of(50, client_of).expect("curl runs under claude");
        assert_eq!(
            agent,
            AgentProcess {
                client: "claude",
                pid: 20,
                start_time: 700
            }
        );
        // The agent itself is its own session.
        assert_eq!(t.agent_of(20, client_of), Some(agent));
        let mut event = serde_json::json!({ "kind": "connect", "pid": 50 });
        stamp(&mut event, Some(agent));
        assert_eq!(event["agent"], "claude");
        let session = event["agent_session"].as_str().unwrap();
        assert!(session.ends_with(":20:700"), "{session}");
        assert_eq!(session, spool::process_key(20, 700));
    }

    #[test]
    fn a_program_outside_any_agent_is_not_attributed_and_gains_no_keys() {
        let mut t = table();
        assert_eq!(t.agent_of(60, client_of), None);
        assert_eq!(t.agent_of(1, client_of), None);
        let mut event = serde_json::json!({ "kind": "exec", "pid": 60 });
        stamp(&mut event, None);
        assert!(event.get("agent").is_none() && event.get("agent_session").is_none());
    }

    #[test]
    fn the_nearest_agent_wins_when_one_agent_runs_another() {
        let mut t = table();
        t.upsert(41, proc(20, 800, "codex", "/usr/local/bin/codex"));
        t.upsert(42, proc(41, 810, "sh", "/usr/bin/dash"));
        let agent = t.agent_of(42, client_of).unwrap();
        assert_eq!((agent.client, agent.pid), ("codex", 41));
    }

    #[test]
    fn a_renamed_process_is_recognized_once_a_fork_reports_its_new_name() {
        // npm-installed agents start as node and rename themselves.
        let mut t = ProcTable::default();
        t.upsert(1, proc(0, 1, "systemd", "/usr/lib/systemd/systemd"));
        t.upsert(20, proc(1, 700, "node", "/usr/bin/node"));
        t.upsert(21, proc(20, 701, "sh", "/usr/bin/dash"));
        assert_eq!(t.agent_of(21, client_of), None);
        t.note_comm(20, "claude");
        assert_eq!(t.agent_of(21, client_of).map(|a| a.pid), Some(20));
        // An uncached pid is never invented.
        t.note_comm(4_000_000, "claude");
        assert_eq!(t.agent_of(4_000_000, client_of), None);
    }

    #[test]
    fn a_name_matches_whole_never_by_substring() {
        let names = [AiAgentProcess {
            client: "pi",
            name: "pi",
        }];
        assert_eq!(client_in(&names, &proc(1, 1, "pip", "/usr/bin/pip")), None);
        assert_eq!(
            client_in(&names, &proc(1, 1, "python3", "/usr/bin/pi (deleted)")),
            Some("pi")
        );
        // A kernel name holds 15 bytes: a longer declared name matches its
        // first 15, and the full name matches the executable.
        let long = [AiAgentProcess {
            client: "x",
            name: "a-very-long-agent-name",
        }];
        assert_eq!(
            client_in(&long, &proc(1, 1, "a-very-long-age", "/usr/bin/node")),
            Some("x")
        );
        assert_eq!(
            client_in(&long, &proc(1, 1, "node", "/opt/a-very-long-agent-name")),
            Some("x")
        );
    }
}
