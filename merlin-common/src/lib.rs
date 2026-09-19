//! Shared event types between the eBPF collector and the userspace daemon.
//!
//! All types are plain-old-data with a stable C layout so both sides can
//! reinterpret the same ring-buffer bytes.
#![no_std]

pub const COMM_LEN: usize = 16;
pub const PATH_LEN: usize = 128;
pub const MEMFD_NAME_LEN: usize = 64;

pub const KIND_EXEC: u32 = 1;
pub const KIND_EXIT: u32 = 2;
pub const KIND_CONNECT: u32 = 3;
pub const KIND_MEMFD: u32 = 4;
pub const KIND_FORK: u32 = 5;
pub const KIND_SECURITY: u32 = 6;
pub const KIND_SOCKET: u32 = 7;
pub const KIND_CRED: u32 = 8;
pub const KIND_IOURING: u32 = 9;
pub const KIND_IOURING_OP: u32 = 10;

/// Emitted when a process execs (sched/sched_process_exec).
///
/// `ppid` is filled in by userspace from /proc; the tracepoint context does
/// not carry it and reading task_struct ancestry without CO-RE is brittle.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct ExecEvent {
    pub pid: u32,
    pub ppid: u32,
    pub uid: u32,
    /// 1 when pid is valid in the daemon's configured namespace; 0 means
    /// translation failed and userspace must not act on the numeric value.
    pub pid_ns_valid: u32,
    pub comm: [u8; COMM_LEN],
    pub filename: [u8; PATH_LEN],
}

/// Emitted when a process exits (kprobe on do_exit, which carries the exit
/// code; the sched/sched_process_exit tracepoint does not).
#[repr(C)]
#[derive(Copy, Clone)]
pub struct ExitEvent {
    pub pid: u32,
    pub uid: u32,
    pub pid_ns_valid: u32,
    /// Raw `code` argument of do_exit: exit status is (code >> 8) & 0xff for
    /// normal exits.
    pub exit_code: i64,
    pub comm: [u8; COMM_LEN],
}

/// Emitted on outbound IPv4 TCP connect (sock/inet_sock_set_state,
/// newstate == TCP_SYN_SENT).
#[repr(C)]
#[derive(Copy, Clone)]
pub struct ConnectEvent {
    pub pid: u32,
    pub uid: u32,
    /// IPv4 addresses as u32 read from little-endian memory holding the
    /// network-order bytes; convert with `u32::to_le_bytes`.
    pub saddr: u32,
    pub daddr: u32,
    /// Destination port, host byte order (the tracepoint already does ntohs).
    pub dport: u16,
    pub pid_ns_valid: u16,
    pub comm: [u8; COMM_LEN],
}

/// Emitted on memfd_create (syscalls/sys_enter_memfd_create). Feeding
/// signal for fileless-execution detection: an exec whose
/// /proc/<pid>/exe readlinks to "/memfd:<name> (deleted)" came from an
/// anonymous in-memory file.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct MemfdEvent {
    pub pid: u32,
    pub uid: u32,
    pub flags: u32,
    /// 1 when pid is valid in the daemon's configured namespace; 0 means
    /// translation failed and userspace must not act on the numeric value.
    pub pid_ns_valid: u32,
    pub comm: [u8; COMM_LEN],
    pub name: [u8; MEMFD_NAME_LEN],
}

/// Emitted when a process forks or clones a child task. The pids are used for
/// telemetry and lineage only; userspace must still validate a process start
/// time before taking an action against either pid.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct ForkEvent {
    pub parent_pid: u32,
    pub child_pid: u32,
    pub uid: u32,
    pub parent_pid_ns_valid: u32,
    pub child_pid_ns_valid: u32,
    pub parent_comm: [u8; COMM_LEN],
    pub child_comm: [u8; COMM_LEN],
}

/// High-signal syscall transition. Arguments are recorded as opaque numeric
/// values only; pointer arguments are never dereferenced and syscall payloads
/// are never collected.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct SecurityEvent {
    pub pid: u32,
    pub uid: u32,
    pub pid_ns_valid: u32,
    /// Userspace-selected syscall ABI profile (1 = x86_64, 2 = aarch64).
    /// A zero/unknown profile must never be treated as complete coverage.
    pub syscall_abi: u32,
    pub syscall_nr: u32,
    pub args: [u64; 6],
    pub comm: [u8; COMM_LEN],
}

/// TCP socket state transition. The address fields contain network-order
/// bytes: IPv4 uses the first four bytes and IPv6 uses all sixteen bytes.
/// `inet_sock_set_state` is TCP-only; UDP socket lifecycle evidence is emitted
/// by the high-signal syscall stream instead of inspecting packet payloads.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct SocketEvent {
    pub pid: u32,
    pub uid: u32,
    pub pid_ns_valid: u32,
    pub family: u16,
    pub protocol: u8,
    pub old_state: u8,
    pub new_state: u8,
    pub _pad: u8,
    pub sport: u16,
    pub dport: u16,
    pub saddr: [u8; 16],
    pub daddr: [u8; 16],
    pub comm: [u8; COMM_LEN],
}

/// Emitted on credential-change syscalls (setuid/setreuid/setresuid).
/// `syscall`: 0 = setuid, 1 = setreuid, 2 = setresuid. `target_uid` is the
/// effective destination (the uid arg for setuid, euid otherwise);
/// 0xFFFF_FFFF when the syscall leaves euid unchanged (-1 argument).
#[repr(C)]
#[derive(Copy, Clone)]
pub struct CredEvent {
    pub pid: u32,
    pub uid: u32,
    pub pid_ns_valid: u32,
    pub syscall: u32,
    pub target_uid: u32,
    pub _pad: u32,
    pub comm: [u8; COMM_LEN],
}

/// Emitted on io_uring_setup — the syscall tracepoints are blind to
/// io_uring operations, so setup is the choke point for detecting use of
/// the evasion-prone API.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct IouringEvent {
    pub pid: u32,
    pub uid: u32,
    pub pid_ns_valid: u32,
    /// Requested ring entries.
    pub entries: u32,
    pub comm: [u8; COMM_LEN],
}

/// Emitted per interesting io_uring submission (openat/connect/read/write
/// family). `opcode` is the raw IORING_OP_* number; userspace maps names.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct IouringOpEvent {
    pub pid: u32,
    pub uid: u32,
    pub pid_ns_valid: u32,
    pub opcode: u8,
    pub _pad: [u8; 3],
    pub comm: [u8; COMM_LEN],
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union EventPayload {
    pub exec: ExecEvent,
    pub exit: ExitEvent,
    pub connect: ConnectEvent,
    pub memfd: MemfdEvent,
    pub fork: ForkEvent,
    pub security: SecurityEvent,
    pub socket: SocketEvent,
    pub cred: CredEvent,
    pub iouring: IouringEvent,
    pub iouring_op: IouringOpEvent,
}

/// One ring-buffer record.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct Event {
    pub kind: u32,
    pub _pad: u32,
    pub payload: EventPayload,
}
