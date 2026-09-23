//! Merlin kernel collector: aya-based eBPF programs.
//!
//! Field offsets for the tracepoints are taken from the kernel's format
//! files (/sys/kernel/tracing/events/<grp>/<evt>/format). The BPF context
//! for a TRACEPOINT program is the `trace_event_raw_*` struct itself, i.e.
//! the 8-byte trace_entry common header followed by the event fields, so
//! format-file offsets apply directly to the ctx pointer.
#![no_std]
#![no_main]

use aya_ebpf::{
    EbpfContext,
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid,
        bpf_get_ns_current_pid_tgid, bpf_probe_read_kernel_str_bytes,
        bpf_probe_read_user_str_bytes,
    },
    macros::{kprobe, map, tracepoint},
    maps::{Array, PerCpuArray, RingBuf},
    programs::{ProbeContext, TracePointContext},
};
use merlin_common::*;

#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(1 << 18, 0);

/// Per-CPU lower-bound counter for ring-buffer reservations rejected because
/// the buffer was full. It is telemetry only: the collector never blocks the
/// kernel path to preserve fail-open enforcement behavior.
#[map]
static EVENT_STATS: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);

/// dev/ino of the daemon's pid namespace, written by userspace before
/// attach. Tracepoint/kprobe pid fields are in the *init* pid namespace,
/// which is useless on hosts that run containers (this sensor itself may
/// run inside one): a container-local process cannot resolve host pids in
/// its /proc. bpf_get_ns_current_pid_tgid translates to our namespace.
#[map]
static PID_NS: Array<u64> = Array::with_max_entries(2, 0);

/// Userspace writes the host syscall ABI before attach. Keeping the profile
/// in a map avoids silently applying x86_64 numbers to an arm64 host.
#[map]
static SYSCALL_ABI: Array<u32> = Array::with_max_entries(1, 0);

const ABI_X86_64: u32 = 1;
const ABI_AARCH64: u32 = 2;

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

fn submit(event: &Event) {
    // Dropped events (full ring) are acceptable for a teaching sensor; the
    // alternative is blocking the kernel path, which is not.
    if EVENTS.output::<Event>(event, 0).is_err() {
        if let Some(ptr) = EVENT_STATS.get_ptr_mut(0) {
            unsafe { *ptr = (*ptr).wrapping_add(1) };
        }
    }
}

fn current_uid() -> u32 {
    (bpf_get_current_uid_gid() & 0xffff_ffff) as u32
}

fn current_pid() -> u32 {
    (bpf_get_current_pid_tgid() >> 32) as u32
}

/// Return the tgid in the daemon's pid namespace. If translation is
/// configured but fails, return an invalid marker instead of falling back to
/// an init-namespace number that userspace could signal incorrectly.
fn current_pid_ns() -> (u32, bool) {
    let dev = PID_NS.get(0).copied().unwrap_or(0);
    let ino = PID_NS.get(1).copied().unwrap_or(0);
    if dev != 0 || ino != 0 {
        let mut info = aya_ebpf::bindings::bpf_pidns_info { pid: 0, tgid: 0 };
        let ret = unsafe {
            bpf_get_ns_current_pid_tgid(
                dev,
                ino,
                &mut info as *mut _,
                core::mem::size_of::<aya_ebpf::bindings::bpf_pidns_info>() as u32,
            )
        };
        if ret == 0 && info.tgid != 0 {
            return (info.tgid, true);
        }
        return (0, false);
    }
    (current_pid(), true)
}

// sched_process_exec format:
//   __data_loc char[] filename; offset:8; size:4
//   pid_t pid;                   offset:12
//   pid_t old_pid;               offset:16
#[tracepoint]
pub fn sched_process_exec(ctx: TracePointContext) -> u32 {
    match try_exec(&ctx) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

fn try_exec(ctx: &TracePointContext) -> Result<(), i64> {
    let data_loc: u32 = unsafe { ctx.read_at(8)? };
    let filename_off = (data_loc & 0xffff) as usize;
    let (pid, pid_ns_valid) = current_pid_ns();

    let mut event = Event {
        kind: KIND_EXEC,
        _pad: 0,
        payload: EventPayload {
            exec: ExecEvent {
                pid,
                ppid: 0,
                uid: current_uid(),
                pid_ns_valid: pid_ns_valid as u32,
                comm: [0; COMM_LEN],
                filename: [0; PATH_LEN],
            },
        },
    };
    unsafe {
        let exec = &mut event.payload.exec;
        exec.comm = bpf_get_current_comm().map_err(|e| e as i64)?;
        let src = ctx.as_ptr().add(filename_off) as *const u8;
        bpf_probe_read_kernel_str_bytes(src, &mut exec.filename)?;
    }
    submit(&event);
    Ok(())
}

// sched_process_fork format (this kernel uses __data_loc comms):
//   __data_loc char[] parent_comm; offset:8
//   pid_t parent_pid;              offset:12
//   __data_loc char[] child_comm;  offset:16
//   pid_t child_pid;               offset:20
#[tracepoint]
pub fn sched_process_fork(ctx: TracePointContext) -> u32 {
    match try_fork(&ctx) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

fn try_fork(ctx: &TracePointContext) -> Result<(), i64> {
    let child_pid: u32 = unsafe { ctx.read_at(20)? };
    let child_loc: u32 = unsafe { ctx.read_at(16)? };
    let child_off = (child_loc & 0xffff) as usize;
    let (parent_pid, pid_ns_valid) = current_pid_ns();
    let mut event = Event {
        kind: KIND_FORK,
        _pad: 0,
        payload: EventPayload {
            fork: ForkEvent {
                parent_pid,
                child_pid,
                uid: current_uid(),
                parent_pid_ns_valid: pid_ns_valid as u32,
                // The child pid is emitted for lineage/telemetry only. The
                // tracepoint does not expose a namespace translation for a
                // not-yet-running child, so never treat it as an action pid.
                child_pid_ns_valid: 0,
                parent_comm: [0; COMM_LEN],
                child_comm: [0; COMM_LEN],
            },
        },
    };
    unsafe {
        let fork = &mut event.payload.fork;
        fork.parent_comm = bpf_get_current_comm().map_err(|e| e as i64)?;
        let child: *const u8 = ctx.as_ptr().add(child_off) as *const u8;
        bpf_probe_read_kernel_str_bytes(child, &mut fork.child_comm)?;
    }
    submit(&event);
    Ok(())
}

// sched/sched_process_exit has no exit_code field (only comm, pid, prio,
// group_dead), so exits are collected with a kprobe on do_exit instead:
//   long do_exit(long code)
#[kprobe]
pub fn do_exit(ctx: ProbeContext) -> u32 {
    match try_exit(&ctx) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

fn try_exit(ctx: &ProbeContext) -> Result<(), i64> {
    let code: i64 = ctx.arg(0).ok_or(-1i64)?;

    let (pid, pid_ns_valid) = current_pid_ns();
    let mut event = Event {
        kind: KIND_EXIT,
        _pad: 0,
        payload: EventPayload {
            exit: ExitEvent {
                pid,
                uid: current_uid(),
                pid_ns_valid: pid_ns_valid as u32,
                exit_code: code,
                comm: [0; COMM_LEN],
            },
        },
    };
    unsafe {
        let exit = &mut event.payload.exit;
        exit.comm = bpf_get_current_comm().map_err(|e| e as i64)?;
    }
    submit(&event);
    Ok(())
}

// inet_sock_set_state format (offsets relative to ctx):
//   int oldstate;  offset:16
//   int newstate;  offset:20
//   __u16 sport;   offset:24
//   __u16 dport;   offset:26  (host order; the tracepoint does ntohs)
//   __u16 family;  offset:28
//   __u8 saddr[4]; offset:32  (network order bytes)
//   __u8 daddr[4]; offset:36
//   __u8 saddr_v6[16]; offset:40
//   __u8 daddr_v6[16]; offset:56
const TCP_SYN_SENT: i32 = 2;
const AF_INET: u16 = 2;
const AF_INET6: u16 = 10;

#[tracepoint]
pub fn inet_sock_set_state(ctx: TracePointContext) -> u32 {
    match try_socket(&ctx) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

fn try_socket(ctx: &TracePointContext) -> Result<(), i64> {
    let oldstate: i32 = unsafe { ctx.read_at(16)? };
    let newstate: i32 = unsafe { ctx.read_at(20)? };
    let family: u16 = unsafe { ctx.read_at(28)? };
    // Keep the stream bounded while covering the useful lifecycle edges:
    // connect, established, listen, and close transitions.
    if !matches!(newstate, 1 | TCP_SYN_SENT | 3 | 4 | 5 | 7 | 8 | 9 | 10 | 11) {
        return Ok(());
    }
    if family != AF_INET && family != AF_INET6 {
        return Ok(());
    }

    let sport: u16 = unsafe { ctx.read_at(24)? };
    let dport: u16 = unsafe { ctx.read_at(26)? };
    let mut saddr = [0u8; 16];
    let mut daddr = [0u8; 16];
    if family == AF_INET {
        let source: u32 = unsafe { ctx.read_at(32)? };
        let destination: u32 = unsafe { ctx.read_at(36)? };
        saddr[..4].copy_from_slice(&source.to_le_bytes());
        daddr[..4].copy_from_slice(&destination.to_le_bytes());
    } else {
        saddr = unsafe { ctx.read_at(40)? };
        daddr = unsafe { ctx.read_at(56)? };
    }

    let (pid, pid_ns_valid) = current_pid_ns();
    let mut event = Event {
        kind: KIND_SOCKET,
        _pad: 0,
        payload: EventPayload {
            socket: SocketEvent {
                pid,
                uid: current_uid(),
                pid_ns_valid: pid_ns_valid as u32,
                family,
                protocol: 6,
                old_state: oldstate as u8,
                new_state: newstate as u8,
                _pad: 0,
                sport,
                dport,
                saddr,
                daddr,
                comm: [0; COMM_LEN],
            },
        },
    };
    unsafe {
        let socket = &mut event.payload.socket;
        socket.comm = bpf_get_current_comm().map_err(|e| e as i64)?;
    }
    submit(&event);
    Ok(())
}

// High-signal syscall ids for each supported Linux ABI. We intentionally
// keep these lists explicit: tracing every syscall would turn the ring
// buffer into a denial-of-service surface. Arguments are copied as integers
// only. The userspace loader selects the profile in SYSCALL_ABI.
fn interesting_x86_64(nr: i64) -> bool {
    matches!(
        nr,
        9   // mmap
            | 10  // mprotect
            | 41  // socket
            | 42  // connect
            | 43  // accept
            | 48  // shutdown
            | 49  // bind
            | 50  // listen
            | 59  // execve (exec tracepoint is the canonical event)
            | 101 // ptrace
            | 105 // setuid
            | 106 // setgid
            | 113 // setreuid
            | 114 // setregid
            | 117 // setresuid
            | 119 // setresgid
            | 126 // capset
            | 155 // pivot_root
            | 165 // mount
            | 166 // umount2
            | 175 // init_module
            | 176 // delete_module
            | 272 // unshare
            | 308 // setns
            | 310 // process_vm_writev
            | 311 // process_vm_readv
            | 313 // finit_module
            | 317 // seccomp
            | 321 // bpf
            | 322 // execveat
            | 323 // userfaultfd
            | 435 // clone3
    )
}

fn interesting_aarch64(nr: i64) -> bool {
    matches!(
        nr,
        39  // umount2
            | 40  // mount
            | 41  // pivot_root
            | 91  // capset
            | 97  // unshare
            | 105 // init_module
            | 106 // delete_module
            | 117 // ptrace
            | 143 // setregid
            | 144 // setgid
            | 145 // setreuid
            | 146 // setuid
            | 147 // setresuid
            | 149 // setresgid
            | 198 // socket
            | 200 // bind
            | 201 // listen
            | 202 // accept
            | 203 // connect
            | 210 // shutdown
            | 221 // execve
            | 222 // mmap
            | 226 // mprotect
            | 268 // setns
            | 270 // process_vm_readv
            | 271 // process_vm_writev
            | 273 // finit_module
            | 277 // seccomp
            | 280 // bpf
            | 281 // execveat
            | 282 // userfaultfd
            | 435 // clone3
    )
}

fn current_syscall_abi() -> u32 {
    SYSCALL_ABI.get(0).copied().unwrap_or(0)
}

fn interesting_syscall(nr: i64, abi: u32) -> bool {
    match abi {
        ABI_X86_64 => interesting_x86_64(nr),
        ABI_AARCH64 => interesting_aarch64(nr),
        _ => false,
    }
}

fn is_exec_memory_syscall(nr: i64, abi: u32) -> bool {
    matches!((abi, nr), (ABI_X86_64, 9 | 10) | (ABI_AARCH64, 222 | 226))
}

#[tracepoint]
pub fn raw_syscalls_sys_enter(ctx: TracePointContext) -> u32 {
    match try_security(&ctx) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

fn try_security(ctx: &TracePointContext) -> Result<(), i64> {
    let syscall_nr: i64 = unsafe { ctx.read_at(8)? };
    let syscall_abi = current_syscall_abi();
    if !interesting_syscall(syscall_nr, syscall_abi) {
        return Ok(());
    }
    let mut args = [0u64; 6];
    args[0] = unsafe { ctx.read_at(16)? };
    args[1] = unsafe { ctx.read_at(24)? };
    args[2] = unsafe { ctx.read_at(32)? };
    args[3] = unsafe { ctx.read_at(40)? };
    args[4] = unsafe { ctx.read_at(48)? };
    args[5] = unsafe { ctx.read_at(56)? };
    // mmap/mprotect are common. Keep only executable mappings, which covers
    // W->X and executable anonymous/file mappings without turning normal heap
    // allocation into a high-volume syscall stream.
    if is_exec_memory_syscall(syscall_nr, syscall_abi) && args[2] & 0x4 == 0 {
        return Ok(());
    }

    let (pid, pid_ns_valid) = current_pid_ns();
    let mut event = Event {
        kind: KIND_SECURITY,
        _pad: 0,
        payload: EventPayload {
            security: SecurityEvent {
                pid,
                uid: current_uid(),
                pid_ns_valid: pid_ns_valid as u32,
                syscall_abi,
                syscall_nr: syscall_nr as u32,
                args,
                comm: [0; COMM_LEN],
            },
        },
    };
    unsafe {
        let security = &mut event.payload.security;
        security.comm = bpf_get_current_comm().map_err(|e| e as i64)?;
    }
    submit(&event);
    Ok(())
}

// sys_enter_memfd_create format (offsets relative to ctx):
//   int __syscall_nr;              offset:8
//   const char * uname;            offset:16 (userspace pointer)
//   unsigned int flags;            offset:24 (stored in an 8-byte slot)
//   __data_loc char[] __uname_val; offset:32
// Note: the kernel-captured __uname_val read back as garbage in practice
// (verified on 7.0.14), so the name is read from the userspace pointer
// instead — same approach as tracee.
#[tracepoint]
pub fn sys_enter_memfd_create(ctx: TracePointContext) -> u32 {
    match try_memfd(&ctx) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

fn try_memfd(ctx: &TracePointContext) -> Result<(), i64> {
    let uname: *const u8 = unsafe { ctx.read_at(16)? };
    let flags: u64 = unsafe { ctx.read_at(24)? };
    let (pid, pid_ns_valid) = current_pid_ns();
    let mut event = Event {
        kind: KIND_MEMFD,
        _pad: 0,
        payload: EventPayload {
            memfd: MemfdEvent {
                pid,
                uid: current_uid(),
                flags: flags as u32,
                pid_ns_valid: pid_ns_valid as u32,
                comm: [0; COMM_LEN],
                name: [0; MEMFD_NAME_LEN],
            },
        },
    };
    unsafe {
        let memfd = &mut event.payload.memfd;
        memfd.comm = bpf_get_current_comm().map_err(|e| e as i64)?;
        bpf_probe_read_user_str_bytes(uname, &mut memfd.name)?;
    }
    submit(&event);
    Ok(())
}

// Credential-change tracepoints (tetragon-style). Field offsets from
// /sys/kernel/tracing/events/syscalls/<name>/format on this kernel:
//   sys_enter_setuid:    field:uid_t uid;   offset:16
//   sys_enter_setreuid:  field:uid_t ruid;  offset:16  field:uid_t euid; offset:24
//   sys_enter_setresuid: field:uid_t ruid;  offset:16  field:uid_t euid; offset:24
//                        field:uid_t suid;  offset:32
// The recorded target is the *effective* destination: the uid argument for
// setuid, euid for setre(uid). A -1 argument (euid unchanged) arrives as
// 0xFFFF_FFFF after truncation; userspace maps that to null.
const CRED_SETUID: u32 = 0;
const CRED_SETREUID: u32 = 1;
const CRED_SETRESUID: u32 = 2;

fn emit_cred(_ctx: &TracePointContext, syscall: u32, target: u64) -> Result<(), i64> {
    let (pid, pid_ns_valid) = current_pid_ns();
    let mut event = Event {
        kind: KIND_CRED,
        _pad: 0,
        payload: EventPayload {
            cred: CredEvent {
                pid,
                uid: current_uid(),
                pid_ns_valid: pid_ns_valid as u32,
                syscall,
                target_uid: target as u32,
                _pad: 0,
                comm: [0; COMM_LEN],
            },
        },
    };
    unsafe {
        let cred = &mut event.payload.cred;
        cred.comm = bpf_get_current_comm().map_err(|e| e as i64)?;
    }
    submit(&event);
    Ok(())
}

#[tracepoint]
pub fn sys_enter_setuid(ctx: TracePointContext) -> u32 {
    match try_setuid(&ctx) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

fn try_setuid(ctx: &TracePointContext) -> Result<(), i64> {
    let uid: u64 = unsafe { ctx.read_at(16)? };
    emit_cred(ctx, CRED_SETUID, uid)
}

#[tracepoint]
pub fn sys_enter_setreuid(ctx: TracePointContext) -> u32 {
    match try_setreuid(&ctx) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

fn try_setreuid(ctx: &TracePointContext) -> Result<(), i64> {
    let euid: u64 = unsafe { ctx.read_at(24)? };
    emit_cred(ctx, CRED_SETREUID, euid)
}

#[tracepoint]
pub fn sys_enter_setresuid(ctx: TracePointContext) -> u32 {
    match try_setresuid(&ctx) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

fn try_setresuid(ctx: &TracePointContext) -> Result<(), i64> {
    let euid: u64 = unsafe { ctx.read_at(24)? };
    emit_cred(ctx, CRED_SETRESUID, euid)
}

// sys_enter_io_uring_setup format:
//   u32 entries;                    offset:16
//   struct io_uring_params * params; offset:24
// Syscall tracepoints are blind to everything io_uring does afterwards, so
// setup is the choke point: log every ring creation.
#[tracepoint]
pub fn sys_enter_io_uring_setup(ctx: TracePointContext) -> u32 {
    match try_iouring_setup(&ctx) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

fn try_iouring_setup(ctx: &TracePointContext) -> Result<(), i64> {
    let entries: u64 = unsafe { ctx.read_at(16)? };
    let (pid, pid_ns_valid) = current_pid_ns();
    let mut event = Event {
        kind: KIND_IOURING,
        _pad: 0,
        payload: EventPayload {
            iouring: IouringEvent {
                pid,
                uid: current_uid(),
                pid_ns_valid: pid_ns_valid as u32,
                entries: entries as u32,
                comm: [0; COMM_LEN],
            },
        },
    };
    unsafe {
        let io = &mut event.payload.iouring;
        io.comm = bpf_get_current_comm().map_err(|e| e as i64)?;
    }
    submit(&event);
    Ok(())
}

// io_uring/io_uring_submit_req format:
//   u8 opcode;                 offset:32
//   unsigned long long flags;  offset:40
//   __data_loc char[] op_str;  offset:52
// Emitted per submission — high volume on real io_uring users, so only the
// filesystem/network-relevant opcodes are forwarded.
fn interesting_iouring_op(op: u8) -> bool {
    matches!(
        op,
        13  // IORING_OP_ACCEPT
        | 16  // IORING_OP_CONNECT
        | 18  // IORING_OP_OPENAT
        | 19  // IORING_OP_CLOSE
        | 22  // IORING_OP_READ
        | 23  // IORING_OP_WRITE
        | 28  // IORING_OP_OPENAT2
        | 45 // IORING_OP_SOCKET
    )
}

#[tracepoint]
pub fn io_uring_submit_req(ctx: TracePointContext) -> u32 {
    match try_iouring_op(&ctx) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

fn try_iouring_op(ctx: &TracePointContext) -> Result<(), i64> {
    let opcode: u8 = unsafe { ctx.read_at(32)? };
    if !interesting_iouring_op(opcode) {
        return Ok(());
    }
    let (pid, pid_ns_valid) = current_pid_ns();
    let mut event = Event {
        kind: KIND_IOURING_OP,
        _pad: 0,
        payload: EventPayload {
            iouring_op: IouringOpEvent {
                pid,
                uid: current_uid(),
                pid_ns_valid: pid_ns_valid as u32,
                opcode,
                _pad: [0; 3],
                comm: [0; COMM_LEN],
            },
        },
    };
    unsafe {
        let io = &mut event.payload.iouring_op;
        io.comm = bpf_get_current_comm().map_err(|e| e as i64)?;
    }
    submit(&event);
    Ok(())
}
