//! The seccomp-bpf syscall filter the run jail installs, hand-assembled as a
//! classic-BPF program.
//!
//! The run jail closes one axis a namespace alone cannot: syscalls. A fresh
//! network namespace stops egress, a mount scope stops file access — but a
//! shared PID namespace still lets a process `fork`, and no namespace stops
//! `ptrace`, `io_uring`, or `process_vm_readv`. This filter denies those, and
//! refuses every syscall that creates or joins a namespace (`unshare`, `setns`,
//! `clone3`, and `clone` with any `CLONE_NEW*` flag) in every subprocess mode.
//!
//! ## Why hand-assembled classic BPF, not a crate
//!
//! The program is small, fixed, and security-critical, so its exact bytes are
//! asserted in-crate ([`tests`]); a dependency would put the load-bearing bytes
//! behind a version we do not pin at the instruction level. Bubblewrap loads
//! the compiled program from a file descriptor (`--seccomp <fd>`), so this
//! module only has to *emit the bytes*; the kernel install is bubblewrap's.
//!
//! ## Fail-closed architecture guard
//!
//! The first thing the program does is check the audit architecture. A seccomp
//! filter that ignores the arch is a silent no-op on a mismatched ABI (the
//! syscall *numbers* differ), which would be fail-**open**. This filter instead
//! kills the process on any architecture other than the one it was built for —
//! an unexpected ABI refuses, it never runs unfiltered.
//!
//! Two Linux ABIs are supported: `x86_64` and `aarch64`. Each has its own audit
//! architecture and its own syscall-number table (the numbers differ entirely
//! between the two — aarch64 follows the asm-generic table and has no `open`,
//! `fork`, or `vfork` at all). The active table is selected at compile time by
//! [`target_arch`], and the emitted filter first checks the audit arch and kills
//! any process running the mismatched ABI. On any other build target
//! [`subprocess_deny_program`] returns `None` and the run-jail wiring refuses
//! (fail-closed) rather than install a filter that does not match the running
//! kernel's syscall numbers.

// ── classic-BPF instruction encoding ────────────────────────────────────────

/// One classic-BPF instruction (`struct sock_filter`): a 16-bit opcode, two
/// 8-bit jump offsets, and a 32-bit operand. The kernel ABI is fixed, so the
/// field order and widths are load-bearing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SockFilter {
    /// Opcode.
    pub code: u16,
    /// Jump-if-true offset (in instructions).
    pub jt: u8,
    /// Jump-if-false offset (in instructions).
    pub jf: u8,
    /// 32-bit operand (a constant, a syscall number, or an absolute offset).
    pub k: u32,
}

impl SockFilter {
    /// The 8-byte little-endian wire encoding the kernel reads.
    #[must_use]
    pub const fn to_bytes(self) -> [u8; 8] {
        let [c0, c1] = self.code.to_ne_bytes();
        let [k0, k1, k2, k3] = self.k.to_ne_bytes();
        [c0, c1, self.jt, self.jf, k0, k1, k2, k3]
    }
}

// BPF opcode constants (from <linux/bpf_common.h>). Only the ones this program
// uses are defined; each is the exact value the kernel's classic-BPF verifier
// expects.
const BPF_LD: u16 = 0x00;
const BPF_JMP: u16 = 0x05;
const BPF_RET: u16 = 0x06;
const BPF_W: u16 = 0x00;
const BPF_ABS: u16 = 0x20;
const BPF_JEQ: u16 = 0x10;
const BPF_JGE: u16 = 0x30;
const BPF_JSET: u16 = 0x40;
const BPF_K: u16 = 0x00;

/// `seccomp_data` field offsets (from <linux/seccomp.h>): the filter reads the
/// syscall number, the audit arch, and — for the clone thread/process
/// discriminator — the low 32 bits of the first argument.
const OFF_NR: u32 = 0;
const OFF_ARCH: u32 = 4;
/// `args[0]` is a `u64` at offset 16; its low 32 bits (little-endian) hold the
/// `clone` flags, which is where `CLONE_VM`/`CLONE_THREAD` live. Both supported
/// ABIs place `clone_flags` as raw-syscall arg0: `x86_64` and `aarch64` both use
/// the flags-first `sys_clone` signature (aarch64 does NOT set
/// `CONFIG_CLONE_BACKWARDS`, unlike 32-bit arm/x86), so this offset reads the
/// flag mask on both.
const OFF_ARG0_LO: u32 = 16;

/// The `x86_64` audit architecture. `AUDIT_ARCH_X86_64` = `EM_X86_64 (62) |
/// __AUDIT_ARCH_64BIT (0x8000_0000) | __AUDIT_ARCH_LE (0x4000_0000)` =
/// `0xC000_003E`.
const AUDIT_ARCH_X86_64: u32 = 0x3E | 0x8000_0000 | 0x4000_0000;

/// `__X32_SYSCALL_BIT` (from `<asm/unistd.h>`): on a kernel built with
/// `CONFIG_X86_X32_ABI`, an x32-ABI syscall reports the `x86_64` audit arch but
/// carries this bit in its number, so `syscall(0x4000_0000 | nr)` reaches the
/// same handler as `nr` while dodging an exact-number match. The `x86_64` filter
/// kills any number at or above this bit; no legitimate 64-bit payload issues one.
const X32_SYSCALL_BIT: u32 = 0x4000_0000;

/// The aarch64 audit architecture. `AUDIT_ARCH_AARCH64` = `EM_AARCH64 (183) |
/// __AUDIT_ARCH_64BIT (0x8000_0000) | __AUDIT_ARCH_LE (0x4000_0000)` =
/// `0xC000_00B7`. aarch64 is little-endian in the ABI Ipê targets.
const AUDIT_ARCH_AARCH64: u32 = 0xB7 | 0x8000_0000 | 0x4000_0000;

/// seccomp return actions (from <linux/seccomp.h>).
const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;
const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;
const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
/// `EPERM` — the errno a denied syscall returns (so a caller sees a permission
/// error, the same as any other blocked operation, rather than a crash).
const EPERM: u32 = 1;
/// `ENOSYS` (asm-generic, the same on `x86_64` and `aarch64`) — the errno a
/// refused `clone3` returns, so glibc falls back to the inspectable `clone`.
const ENOSYS: u32 = 38;

// ── per-ABI syscall numbers ─────────────────────────────────────────────────
//
// The syscall numbers differ completely between the two Linux ABIs. x86_64
// numbers come from <asm/unistd_64.h>; aarch64 numbers come from the asm-generic
// table <asm-generic/unistd.h> (aarch64 has no arch-specific unistd overrides
// for these calls). aarch64 notably has NO `open`, `fork`, or `vfork` syscall —
// user space uses `openat` and creates tasks exclusively through `clone`/
// `clone3` — so the fork/vfork deny list is empty there and the whole
// subprocess-deny axis rests on the `clone` flag split (`clone3` is refused
// with `ENOSYS` in every mode).
//
// Each field of [`AbiSyscalls`] names one syscall the filter reasons about;
// [`X86_64_SYSCALLS`] and [`AARCH64_SYSCALLS`] hold the two tables, and
// [`active_abi`] selects the one matching the build target.

/// The audit architecture plus the syscall numbers one ABI's filter needs. The
/// numbers are ABI-specific and must never be shared across ABIs — a single
/// wrong number would deny the wrong call (fail-open for the intended one).
#[derive(Debug, Clone, Copy)]
struct AbiSyscalls {
    /// The `AUDIT_ARCH_*` value the arch guard compares against.
    audit_arch: u32,
    /// A fail-closed kill for every syscall number at or above this value, when
    /// the ABI shares an audit arch with a secondary calling convention that
    /// tags its numbers with a high bit (`x86_64`'s x32 ABI sets
    /// [`X32_SYSCALL_BIT`]). Emitted before any per-syscall compare so a tagged
    /// number cannot slip past the exact-match denials into the default allow.
    /// `None` on ABIs with no such secondary convention (aarch64).
    deny_nr_ge: Option<u32>,
    nr_clone: u32,
    /// `clone3`, refused with `ENOSYS` in every mode: its flags live behind a
    /// pointer classic BPF cannot read, so no namespace check is expressible.
    nr_clone3: u32,
    /// `fork`/`vfork` on `x86_64`; empty on `aarch64` (no such syscalls there).
    create_denied_non_clone: &'static [u32],
    /// The unconditional escape/exfiltration denials for this ABI.
    baseline_denied: &'static [u32],
    /// `execve`/`execveat` — never denied; carried only so the
    /// removal/allow-guard tests can assert they are absent from the filter. The
    /// builder never reads it, so a non-test build sees it unused.
    #[cfg_attr(not(test), allow(dead_code))]
    never_denied: &'static [u32],
}

// Each ABI's table is compile-time-selected by `active_abi`, so on a host of the
// OTHER arch its numbers and table are referenced only by the unit tests (which
// build both). Each ABI's numbers live in a private module carrying one
// dead-code allowance for exactly that case: `not(any(<that arch>, test))`. On a
// build FOR the arch, `active_abi` uses the table and it is live; under `test`,
// both are live. The table `const`s are re-exported so `active_abi` and the
// tests can name them unqualified.

/// `x86_64` syscall numbers (from `<asm/unistd_64.h>`) and the table built from
/// them.
#[cfg_attr(not(any(target_arch = "x86_64", test)), allow(dead_code))]
mod x86_64_abi {
    use super::{AUDIT_ARCH_X86_64, AbiSyscalls};

    const NR_CLONE: u32 = 56;
    const NR_FORK: u32 = 57;
    const NR_VFORK: u32 = 58;
    const NR_EXECVE: u32 = 59;
    const NR_PTRACE: u32 = 101;
    const NR_PIVOT_ROOT: u32 = 155;
    const NR_MOUNT: u32 = 165;
    const NR_UMOUNT2: u32 = 166;
    const NR_KEXEC_LOAD: u32 = 246;
    const NR_KEYCTL: u32 = 250;
    const NR_UNSHARE: u32 = 272;
    const NR_SETNS: u32 = 308;
    const NR_PROCESS_VM_READV: u32 = 310;
    const NR_PROCESS_VM_WRITEV: u32 = 311;
    const NR_KEXEC_FILE_LOAD: u32 = 320;
    const NR_BPF: u32 = 321;
    const NR_EXECVEAT: u32 = 322;
    const NR_USERFAULTFD: u32 = 323;
    const NR_IO_URING_SETUP: u32 = 425;
    const NR_IO_URING_ENTER: u32 = 426;
    const NR_IO_URING_REGISTER: u32 = 427;
    const NR_OPEN_TREE: u32 = 428;
    const NR_MOVE_MOUNT: u32 = 429;
    const NR_FSOPEN: u32 = 430;
    const NR_FSCONFIG: u32 = 431;
    const NR_FSMOUNT: u32 = 432;
    const NR_CLONE3: u32 = 435;
    const NR_PIDFD_GETFD: u32 = 438;
    const NR_MOUNT_SETATTR: u32 = 442;

    /// The `x86_64` syscall table. See the deny-axes commentary above
    /// [`super::build_program_for`] for why each baseline entry is denied.
    pub(super) const SYSCALLS: AbiSyscalls = AbiSyscalls {
        audit_arch: AUDIT_ARCH_X86_64,
        deny_nr_ge: Some(super::X32_SYSCALL_BIT),
        nr_clone: NR_CLONE,
        nr_clone3: NR_CLONE3,
        create_denied_non_clone: &[NR_FORK, NR_VFORK],
        baseline_denied: &[
            NR_PTRACE,
            NR_PROCESS_VM_READV,
            NR_PROCESS_VM_WRITEV,
            NR_IO_URING_SETUP,
            NR_IO_URING_ENTER,
            NR_IO_URING_REGISTER,
            NR_PIDFD_GETFD,
            NR_BPF,
            NR_USERFAULTFD,
            NR_KEYCTL,
            NR_KEXEC_LOAD,
            NR_KEXEC_FILE_LOAD,
            NR_MOUNT,
            NR_UMOUNT2,
            NR_PIVOT_ROOT,
            NR_SETNS,
            NR_UNSHARE,
            NR_MOVE_MOUNT,
            NR_OPEN_TREE,
            NR_FSOPEN,
            NR_FSCONFIG,
            NR_FSMOUNT,
            NR_MOUNT_SETATTR,
        ],
        never_denied: &[NR_EXECVE, NR_EXECVEAT],
    };
}

/// `aarch64` syscall numbers (from `<asm-generic/unistd.h>`) and the table built
/// from them. `aarch64` has NO `fork`, `vfork`, or `open` — task creation is
/// `clone`/`clone3` only, file open is `openat` only — so `create_denied_non_clone`
/// is empty and the subprocess axis rests on the `clone` flag split.
#[cfg_attr(not(any(target_arch = "aarch64", test)), allow(dead_code))]
mod aarch64_abi {
    use super::{AUDIT_ARCH_AARCH64, AbiSyscalls};

    const NR_UMOUNT2: u32 = 39;
    const NR_MOUNT: u32 = 40;
    const NR_PIVOT_ROOT: u32 = 41;
    const NR_UNSHARE: u32 = 97;
    const NR_KEXEC_LOAD: u32 = 104;
    const NR_PTRACE: u32 = 117;
    const NR_KEYCTL: u32 = 219;
    const NR_CLONE: u32 = 220;
    const NR_EXECVE: u32 = 221;
    const NR_SETNS: u32 = 268;
    const NR_PROCESS_VM_READV: u32 = 270;
    const NR_PROCESS_VM_WRITEV: u32 = 271;
    const NR_BPF: u32 = 280;
    const NR_EXECVEAT: u32 = 281;
    const NR_USERFAULTFD: u32 = 282;
    const NR_KEXEC_FILE_LOAD: u32 = 294;
    const NR_IO_URING_SETUP: u32 = 425;
    const NR_IO_URING_ENTER: u32 = 426;
    const NR_IO_URING_REGISTER: u32 = 427;
    const NR_OPEN_TREE: u32 = 428;
    const NR_MOVE_MOUNT: u32 = 429;
    const NR_FSOPEN: u32 = 430;
    const NR_FSCONFIG: u32 = 431;
    const NR_FSMOUNT: u32 = 432;
    const NR_CLONE3: u32 = 435;
    const NR_PIDFD_GETFD: u32 = 438;
    const NR_MOUNT_SETATTR: u32 = 442;

    /// The `aarch64` syscall table. The baseline denies mirror `x86_64`'s exactly
    /// (same escape/exfiltration primitives, different numbers).
    pub(super) const SYSCALLS: AbiSyscalls = AbiSyscalls {
        audit_arch: AUDIT_ARCH_AARCH64,
        deny_nr_ge: None,
        nr_clone: NR_CLONE,
        nr_clone3: NR_CLONE3,
        create_denied_non_clone: &[],
        baseline_denied: &[
            NR_PTRACE,
            NR_PROCESS_VM_READV,
            NR_PROCESS_VM_WRITEV,
            NR_IO_URING_SETUP,
            NR_IO_URING_ENTER,
            NR_IO_URING_REGISTER,
            NR_PIDFD_GETFD,
            NR_BPF,
            NR_USERFAULTFD,
            NR_KEYCTL,
            NR_KEXEC_LOAD,
            NR_KEXEC_FILE_LOAD,
            NR_MOUNT,
            NR_UMOUNT2,
            NR_PIVOT_ROOT,
            NR_SETNS,
            NR_UNSHARE,
            NR_MOVE_MOUNT,
            NR_OPEN_TREE,
            NR_FSOPEN,
            NR_FSCONFIG,
            NR_FSMOUNT,
            NR_MOUNT_SETATTR,
        ],
        never_denied: &[NR_EXECVE, NR_EXECVEAT],
    };
}

/// The `x86_64` syscall table (see [`x86_64_abi`]).
#[cfg_attr(not(any(target_arch = "x86_64", test)), allow(dead_code))]
const X86_64_SYSCALLS: AbiSyscalls = x86_64_abi::SYSCALLS;

/// The `aarch64` syscall table (see [`aarch64_abi`]).
#[cfg_attr(not(any(target_arch = "aarch64", test)), allow(dead_code))]
const AARCH64_SYSCALLS: AbiSyscalls = aarch64_abi::SYSCALLS;

/// The syscall table matching the build target, or `None` on an unsupported ABI
/// (the caller then refuses, fail-closed). Only `x86_64` and `aarch64` have a
/// vetted table.
///
/// The `Option` is the fail-closed contract, not incidental: on an unvetted ABI
/// the `None` arm is the ONLY one compiled and the caller must refuse. On a
/// vetted-ABI build the `None` arm is `cfg`'d out, so clippy sees a
/// provably-`Some` return and would flag the wrapper — that flag is silenced
/// here because dropping the `Option` would erase the refuse path on the arch
/// where it is the whole point.
#[must_use]
#[cfg_attr(
    any(target_arch = "x86_64", target_arch = "aarch64"),
    allow(clippy::unnecessary_wraps)
)]
const fn active_abi() -> Option<AbiSyscalls> {
    #[cfg(target_arch = "x86_64")]
    {
        Some(X86_64_SYSCALLS)
    }
    #[cfg(target_arch = "aarch64")]
    {
        Some(AARCH64_SYSCALLS)
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        None
    }
}

/// `clone` flags (from <linux/sched.h>): `CLONE_VM | CLONE_THREAD` is exactly
/// the thread/process discriminator. `pthread_create` (and thus tokio's worker
/// threads and the runtime's `block_on` thread) sets both; a `fork`-style
/// process clone sets neither.
const CLONE_VM: u32 = 0x0000_0100;
const CLONE_THREAD: u32 = 0x0001_0000;

// The `CLONE_NEW*` namespace-creation flags (from <linux/sched.h>) a legacy
// `clone` can carry. `CLONE_NEWTIME` (0x80) is absent: in legacy `clone` that
// bit is part of `CSIGNAL`, and it creates a namespace only through `clone3` or
// `unshare`, both refused whole.
const CLONE_NEWNS: u32 = 0x0002_0000;
const CLONE_NEWCGROUP: u32 = 0x0200_0000;
const CLONE_NEWUTS: u32 = 0x0400_0000;
const CLONE_NEWIPC: u32 = 0x0800_0000;
const CLONE_NEWUSER: u32 = 0x1000_0000;
const CLONE_NEWPID: u32 = 0x2000_0000;
const CLONE_NEWNET: u32 = 0x4000_0000;

/// Every namespace-creating legacy-`clone` flag: a `clone` carrying any of them
/// is refused in every mode.
const CLONE_NEW_MASK: u32 = CLONE_NEWNS
    | CLONE_NEWCGROUP
    | CLONE_NEWUTS
    | CLONE_NEWIPC
    | CLONE_NEWUSER
    | CLONE_NEWPID
    | CLONE_NEWNET;
// IPE-RUST-AUDIT:ACCEPTED (Arthur Maciel) — compile-time `const` assertion (not a runtime panic); fails the BUILD if the namespace mask drifts from the seven `CLONE_NEW*` bits [ledger #boundary]
const _: () = assert!(CLONE_NEW_MASK == 0x7E02_0000);

// ── the deny axes (rationale shared by both ABIs) ───────────────────────────
//
// **Baseline denials** ([`AbiSyscalls::baseline_denied`]) are unconditional,
// independent of the capability set — escape / exfiltration primitives no
// legitimate declared effect needs:
//   - `ptrace`, `process_vm_readv`/`process_vm_writev`: cross-process memory
//     read / code injection against jail siblings.
//   - `io_uring_setup`/`enter`/`register`: file and network I/O *without* the
//     `openat`/`connect` syscalls a naive filter watches — a direct-I/O bypass
//     of the mount-scope and (belt-and-braces to the empty netns) the network.
//   - `pidfd_getfd`: steal an open fd from a jail sibling by its pidfd,
//     smuggling a descriptor past the mount scope.
//   - `bpf`: load kernel BPF programs — an in-kernel authority the jail never
//     grants.
//   - `userfaultfd`: hand userspace control over the jail's own page faults, a
//     lever for kernel-race and use-after-free exploitation.
//   - `keyctl`: reach the kernel keyring, a cross-process credential/secret store.
//   - `kexec_load`/`kexec_file_load`: stage a replacement kernel image — total
//     host takeover if the jail ever ran privileged.
//   - the mount family (`mount`/`umount2`/`pivot_root`/`setns`/`unshare`/
//     `move_mount`/`open_tree`/`fsopen`/`fsconfig`/`fsmount`/`mount_setattr`):
//     remount / namespace-re-enter escape levers.
//
// **Task-creation denials** ([`AbiSyscalls::create_denied_non_clone`]) apply
// only when `subprocess` is **absent**: `fork` and `vfork` on x86_64 (aarch64
// has neither — its list is empty). Legacy `clone` is handled separately below
// (allowed only for a thread — `CLONE_VM|CLONE_THREAD` — via the flag split).
//
// **Namespace denials** apply in BOTH modes: no jailed payload may create a
// namespace (a fresh user namespace unlocks kernel surface — netfilter through
// `CAP_NET_ADMIN` in a new netns — no jail needs). `unshare`/`setns` are in the
// baseline above. `clone3` is refused with `ENOSYS`: its flags live in a
// `struct clone_args` behind a pointer classic BPF cannot dereference, so a
// namespace check is not expressible for it, and `ENOSYS` makes glibc (>= 2.34,
// `__clone_internal`) fall back to legacy `clone` for threads and `posix_spawn`.
// Legacy `clone` is refused with `EPERM` when its flags carry any bit of
// [`CLONE_NEW_MASK`]; the kernel reads only the low 32 bits of legacy `clone`'s
// flags, so `arg0_lo` is the complete mask. Every task creation therefore goes
// through the inspectable `clone`, which also closes any raw-`clone3` process
// creation when `subprocess` is absent.
//
// **`execve`/`execveat` are deliberately never denied** (replace-not-spawn
// model): `execve` *replaces* the current process image, it does not create a
// child. A subprocess needs a `fork`/`vfork`/`clone`(process) FIRST, then an
// `execve` in the child — and those steps are denied above, so the common
// subprocess paths are contained without touching `execve`. Denying `execve`
// would also kill the jail's own launch: bubblewrap installs the filter and then
// `execve`s the confined payload (`prlimit`, then the app), so an `execve` deny
// is a universal false-deny. A lone `execve` grants no new authority: the filter
// survives it (kernel design), and `no_new_privs` + the read-only root leave the
// exec'd image equally confined.

/// Build the seccomp program for the run jail on the active build ABI.
///
/// `allow_subprocess` = whether the resolved capability set grants
/// `subprocess`; when `false`, the task-creation family is denied (threads
/// excepted, via the `clone` flag check). Namespace creation is refused in
/// both modes.
///
/// Returns `None` on any ABI other than `x86_64` or `aarch64` — the syscall
/// numbers are ABI-specific, so emitting them for an unvetted ABI would be a
/// mismatched, fail-open filter. The caller treats `None` as "no filter can be
/// built here" and refuses (fail-closed).
#[must_use]
pub fn subprocess_deny_program(allow_subprocess: bool) -> Option<Vec<SockFilter>> {
    let abi = active_abi()?;
    Some(build_program_for(abi, allow_subprocess))
}

/// The pure program builder for an explicit ABI, independent of the host arch so
/// both ABIs' bytes are unit-testable on any developer machine.
/// [`subprocess_deny_program`] is the arch-gated entry point that picks the ABI.
#[must_use]
fn build_program_for(abi: AbiSyscalls, allow_subprocess: bool) -> Vec<SockFilter> {
    // 1. Load the audit arch and refuse (kill) if it is not the one this filter
    //    was built for. A mismatched ABI has different syscall numbers, so an
    //    unchecked filter would be a silent no-op — fail-closed here instead. The
    //    JEQ skips the kill (jump +1) when the arch matches; else it falls
    //    through to the kill.
    let mut prog: Vec<SockFilter> = vec![
        stmt(BPF_LD | BPF_W | BPF_ABS, OFF_ARCH),
        jump(BPF_JMP | BPF_JEQ | BPF_K, abi.audit_arch, 1, 0),
        ret(SECCOMP_RET_KILL_PROCESS),
    ];

    // 2. Load the syscall number for the per-syscall decisions below.
    prog.push(stmt(BPF_LD | BPF_W | BPF_ABS, OFF_NR));

    // 2a. Kill any syscall number tagged for a secondary calling convention that
    //     shares this audit arch. The exact-match denials below compare plain
    //     numbers, so a tagged number (x86_64's x32 ABI sets the high bit) would
    //     miss every deny and reach the default allow — re-issuing a denied call.
    //     The JGE lands on the kill (jump +1) when nr >= the tag; else it falls
    //     through to the per-syscall logic.
    if let Some(floor) = abi.deny_nr_ge {
        prog.push(jump(BPF_JMP | BPF_JGE | BPF_K, floor, 0, 1));
        prog.push(ret(SECCOMP_RET_KILL_PROCESS));
    }

    // 3. Baseline denials (unconditional). Each: if nr == denied → EPERM.
    for &nr in abi.baseline_denied {
        prog.push(jump(BPF_JMP | BPF_JEQ | BPF_K, nr, 0, 1));
        prog.push(ret(SECCOMP_RET_ERRNO | EPERM));
    }

    // 4. Namespace denials (both modes). `clone3` → ENOSYS; a `clone` carrying
    //    any `CLONE_NEW*` bit → EPERM. Seven instructions, n0..n6:
    //   n0 JEQ clone3      jf=1 → not-clone3 skips to n2
    //   n1 ret ENOSYS
    //   n2 JEQ clone       jf=3 → not-clone skips to n6
    //   n3 LD arg0_lo
    //   n4 JSET NEW_MASK   jf=1 → no namespace bit → n6
    //   n5 ret EPERM
    //   n6 LD nr           (restore A for the blocks that follow)
    prog.push(jump(BPF_JMP | BPF_JEQ | BPF_K, abi.nr_clone3, 0, 1));
    prog.push(ret(SECCOMP_RET_ERRNO | ENOSYS));
    prog.push(jump(BPF_JMP | BPF_JEQ | BPF_K, abi.nr_clone, 0, 3));
    prog.push(stmt(BPF_LD | BPF_W | BPF_ABS, OFF_ARG0_LO));
    prog.push(jump(BPF_JMP | BPF_JSET | BPF_K, CLONE_NEW_MASK, 0, 1));
    prog.push(ret(SECCOMP_RET_ERRNO | EPERM));
    prog.push(stmt(BPF_LD | BPF_W | BPF_ABS, OFF_NR));

    // 5. Task-creation denials when subprocess is absent.
    if !allow_subprocess {
        for &nr in abi.create_denied_non_clone {
            prog.push(jump(BPF_JMP | BPF_JEQ | BPF_K, nr, 0, 1));
            prog.push(ret(SECCOMP_RET_ERRNO | EPERM));
        }
        // Legacy `clone`: allow ONLY a thread create (`CLONE_VM` AND
        // `CLONE_THREAD` both set); deny a process create. The discriminator
        // lives in the low 32 bits of arg0. `JSET` tests "any bit in the mask
        // set", so requiring BOTH bits is a chain: test `CLONE_THREAD`, then (on
        // its true path) test `CLONE_VM`; only the path where both are set
        // reaches ALLOW, every other clone falls through to EPERM.
        //
        // Six instructions, indices c0..c5 relative to the first push; the
        // seventh (c6) is the default-allow return below. Offsets are computed
        // to land on c5 (EPERM) or c6 (default ALLOW):
        //   c0 JEQ clone  jf=5 → not-clone skips to c6 (default allow)
        //   c1 LD arg0_lo
        //   c2 JSET THREAD jf=2 → thread-bit clear → c5 (EPERM)
        //   c3 JSET VM     jf=1 → vm-bit clear    → c5 (EPERM)
        //   c4 ret ALLOW          (both bits set: a thread)
        //   c5 ret EPERM
        prog.push(jump(BPF_JMP | BPF_JEQ | BPF_K, abi.nr_clone, 0, 5));
        prog.push(stmt(BPF_LD | BPF_W | BPF_ABS, OFF_ARG0_LO));
        prog.push(jump(BPF_JMP | BPF_JSET | BPF_K, CLONE_THREAD, 0, 2));
        prog.push(jump(BPF_JMP | BPF_JSET | BPF_K, CLONE_VM, 0, 1));
        prog.push(ret(SECCOMP_RET_ALLOW));
        prog.push(ret(SECCOMP_RET_ERRNO | EPERM));
    }

    // 6. Default: allow everything not denied above.
    prog.push(ret(SECCOMP_RET_ALLOW));
    prog
}

/// A statement (no jump): `jt`/`jf` are 0.
const fn stmt(code: u16, k: u32) -> SockFilter {
    SockFilter {
        code,
        jt: 0,
        jf: 0,
        k,
    }
}

/// A conditional jump.
const fn jump(code: u16, k: u32, jt: u8, jf: u8) -> SockFilter {
    SockFilter { code, jt, jf, k }
}

/// A return (the low 16 bits of `code` are `BPF_RET`; `k` is the action).
const fn ret(k: u32) -> SockFilter {
    SockFilter {
        code: BPF_RET | BPF_K,
        jt: 0,
        jf: 0,
        k,
    }
}

/// The whole program as the flat little-endian byte stream bubblewrap loads
/// from the seccomp fd.
#[must_use]
pub fn program_bytes(prog: &[SockFilter]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(prog.len() * 8);
    for insn in prog {
        bytes.extend_from_slice(&insn.to_bytes());
    }
    bytes
}

#[cfg(test)]
// The tests assert on the exact instruction sequence of a KNOWN-length program
// by index (`prog[c0]`, `prog[c0 + 2]`, …); a panic on an out-of-range index is
// itself a correct test failure (the program shape drifted), so raw indexing is
// the clearest, safe form here.
#[allow(clippy::indexing_slicing)]
mod tests {
    use super::*;

    /// Every vetted ABI table, so each property is asserted for both `x86_64` and
    /// `aarch64` on any developer host (the tables are pure data, not host-gated).
    const ABIS: &[AbiSyscalls] = &[X86_64_SYSCALLS, AARCH64_SYSCALLS];

    fn has_jeq(prog: &[SockFilter], nr: u32) -> bool {
        prog.iter()
            .any(|i| i.code == (BPF_JMP | BPF_JEQ | BPF_K) && i.k == nr)
    }

    /// Run `prog` on one syscall as the kernel's classic-BPF interpreter would,
    /// over exactly the instruction shapes the builder emits (`LD W ABS` of the
    /// nr, arch, or `arg0_lo`; `JEQ`/`JGE`/`JSET` `K`; `RET K`). Returns the
    /// seccomp action, or `None` on any other opcode, any other load offset, or
    /// a jump past the end — each a builder defect the caller's assert reports.
    fn decide(prog: &[SockFilter], arch: u32, nr: u32, arg0_lo: u32) -> Option<u32> {
        let mut acc: u32 = 0;
        let mut pc: usize = 0;
        loop {
            let insn = prog.get(pc)?;
            let next = pc.checked_add(1)?;
            match insn.code {
                c if c == BPF_LD | BPF_W | BPF_ABS => {
                    acc = match insn.k {
                        OFF_NR => nr,
                        OFF_ARCH => arch,
                        OFF_ARG0_LO => arg0_lo,
                        _ => return None,
                    };
                    pc = next;
                }
                c if c == BPF_RET | BPF_K => return Some(insn.k),
                c if c == BPF_JMP | BPF_JEQ | BPF_K
                    || c == BPF_JMP | BPF_JGE | BPF_K
                    || c == BPF_JMP | BPF_JSET | BPF_K =>
                {
                    let taken = if c == BPF_JMP | BPF_JEQ | BPF_K {
                        acc == insn.k
                    } else if c == BPF_JMP | BPF_JGE | BPF_K {
                        acc >= insn.k
                    } else {
                        acc & insn.k != 0
                    };
                    let off = if taken { insn.jt } else { insn.jf };
                    pc = next.checked_add(usize::from(off))?;
                }
                _ => return None,
            }
        }
    }

    /// `SIGCHLD` — the exit signal a `fork`-style process `clone` carries.
    const SIGCHLD: u32 = 17;
    /// `CLONE_SIGHAND` — part of the flag set `pthread_create` passes.
    const CLONE_SIGHAND: u32 = 0x0000_0800;
    /// The seven namespace flags, each tested alone.
    const NAMESPACE_FLAGS: [u32; 7] = [
        CLONE_NEWNS,
        CLONE_NEWCGROUP,
        CLONE_NEWUTS,
        CLONE_NEWIPC,
        CLONE_NEWUSER,
        CLONE_NEWPID,
        CLONE_NEWNET,
    ];

    #[test]
    fn clone3_is_not_implemented_in_both_modes_on_each_abi() {
        for &abi in ABIS {
            for allow in [true, false] {
                let prog = build_program_for(abi, allow);
                for arg0 in [0, CLONE_NEWUSER, CLONE_VM | CLONE_THREAD] {
                    assert_eq!(
                        decide(&prog, abi.audit_arch, abi.nr_clone3, arg0),
                        Some(SECCOMP_RET_ERRNO | ENOSYS),
                        "clone3 must be ENOSYS (arch={:#x}, allow={allow})",
                        abi.audit_arch
                    );
                }
            }
        }
    }

    #[test]
    fn a_clone_with_any_namespace_flag_is_refused_in_both_modes() {
        let thread = CLONE_VM | CLONE_THREAD | CLONE_SIGHAND;
        for &abi in ABIS {
            for allow in [true, false] {
                let prog = build_program_for(abi, allow);
                for flag in NAMESPACE_FLAGS {
                    for base in [SIGCHLD, thread] {
                        assert_eq!(
                            decide(&prog, abi.audit_arch, abi.nr_clone, flag | base),
                            Some(SECCOMP_RET_ERRNO | EPERM),
                            "clone flags {:#x} must be EPERM (arch={:#x}, allow={allow})",
                            flag | base,
                            abi.audit_arch
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn a_thread_clone_stays_allowed_and_a_process_clone_follows_the_subprocess_axis() {
        let thread = CLONE_VM | CLONE_THREAD | CLONE_SIGHAND;
        for &abi in ABIS {
            for allow in [true, false] {
                let prog = build_program_for(abi, allow);
                assert_eq!(
                    decide(&prog, abi.audit_arch, abi.nr_clone, thread),
                    Some(SECCOMP_RET_ALLOW),
                    "a thread clone must stay allowed (arch={:#x}, allow={allow})",
                    abi.audit_arch
                );
                let process = if allow {
                    SECCOMP_RET_ALLOW
                } else {
                    SECCOMP_RET_ERRNO | EPERM
                };
                assert_eq!(
                    decide(&prog, abi.audit_arch, abi.nr_clone, SIGCHLD),
                    Some(process),
                    "a process clone follows the subprocess axis (arch={:#x}, allow={allow})",
                    abi.audit_arch
                );
                for &nr in abi.never_denied {
                    assert_eq!(
                        decide(&prog, abi.audit_arch, nr, 0),
                        Some(SECCOMP_RET_ALLOW),
                        "never-denied nr {nr} must be allowed after the namespace block"
                    );
                }
            }
        }
    }

    #[test]
    fn the_namespace_mask_is_every_clone_new_flag() {
        let folded = NAMESPACE_FLAGS.iter().fold(0, |acc, f| acc | f);
        assert_eq!(folded, CLONE_NEW_MASK);
        assert_eq!(CLONE_NEW_MASK, 0x7E02_0000);
        assert_eq!(
            NAMESPACE_FLAGS.iter().copied().map(u32::count_ones).sum::<u32>(),
            CLONE_NEW_MASK.count_ones(),
            "each namespace flag is one distinct bit"
        );
        assert_eq!(
            CLONE_NEW_MASK & (CLONE_VM | CLONE_THREAD | CLONE_SIGHAND | SIGCHLD),
            0,
            "the mask must not catch a thread or a plain process clone"
        );
    }

    #[test]
    fn arch_guard_is_the_first_decision_and_kills_a_mismatch() {
        for &abi in ABIS {
            let prog = build_program_for(abi, false);
            // insn 0 loads the arch; insn 1 branches on it; insn 2 is the kill.
            assert_eq!(prog[0], stmt(BPF_LD | BPF_W | BPF_ABS, OFF_ARCH));
            assert_eq!(prog[1].code, BPF_JMP | BPF_JEQ | BPF_K);
            assert_eq!(
                prog[1].k, abi.audit_arch,
                "arch guard must compare against this ABI's audit arch"
            );
            assert_eq!(prog[2], ret(SECCOMP_RET_KILL_PROCESS));
        }
    }

    #[test]
    fn baseline_denials_are_present_in_both_modes() {
        for &abi in ABIS {
            for allow in [true, false] {
                let prog = build_program_for(abi, allow);
                for &nr in abi.baseline_denied {
                    assert!(
                        has_jeq(&prog, nr),
                        "baseline syscall {nr} missing (arch={:#x}, allow={allow})",
                        abi.audit_arch
                    );
                }
            }
        }
    }

    #[test]
    fn escape_primitives_are_baseline_denied_on_each_abi() {
        // pidfd_getfd/bpf/userfaultfd/keyctl/kexec_load/kexec_file_load are
        // unconditional escape/exfiltration levers with the correct per-ABI
        // number. pidfd_getfd is 438 on both ABIs; the rest differ. A wrong
        // number would deny the wrong call and leave the target open, so the
        // numbers are pinned here per ABI, and their presence in the emitted
        // program is checked in both modes.
        let expected: &[(u32, [u32; 6])] = &[
            // (audit_arch, [pidfd_getfd, bpf, userfaultfd, keyctl, kexec_load, kexec_file_load])
            (AUDIT_ARCH_X86_64, [438, 321, 323, 250, 246, 320]),
            (AUDIT_ARCH_AARCH64, [438, 280, 282, 219, 104, 294]),
        ];
        for &abi in ABIS {
            let nrs = expected
                .iter()
                .find(|(arch, _)| *arch == abi.audit_arch)
                .map(|(_, nrs)| nrs);
            assert!(
                nrs.is_some(),
                "no expected escape-primitive numbers for arch {:#x}",
                abi.audit_arch
            );
            if let Some(nrs) = nrs {
                for &nr in nrs {
                    assert!(
                        abi.baseline_denied.contains(&nr),
                        "escape nr {nr} missing from baseline table (arch={:#x})",
                        abi.audit_arch
                    );
                    for allow in [true, false] {
                        let prog = build_program_for(abi, allow);
                        assert!(
                            has_jeq(&prog, nr),
                            "escape nr {nr} not denied in program (arch={:#x}, allow={allow})",
                            abi.audit_arch
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn create_family_is_denied_only_when_subprocess_absent() {
        for &abi in ABIS {
            let denied = build_program_for(abi, false);
            let allowed = build_program_for(abi, true);
            for &nr in abi.create_denied_non_clone {
                assert!(
                    has_jeq(&denied, nr),
                    "create syscall {nr} must be denied when subprocess absent"
                );
                assert!(
                    !has_jeq(&allowed, nr),
                    "create syscall {nr} must NOT be denied when subprocess granted"
                );
            }
        }
    }

    #[test]
    fn clone_thread_discriminator_uses_both_clone_flags() {
        // The subprocess-absent program must test BOTH CLONE_THREAD and CLONE_VM
        // via JSET — a thread (both set) is allowed, a process (neither) is
        // EPERM'd. The clone flags are ABI-independent (linux/sched.h), so both
        // tables express the same split, each keyed on its own `clone` nr.
        for &abi in ABIS {
            let prog = build_program_for(abi, false);
            let jset_thread = prog
                .iter()
                .any(|i| i.code == (BPF_JMP | BPF_JSET | BPF_K) && i.k == CLONE_THREAD);
            let jset_vm = prog
                .iter()
                .any(|i| i.code == (BPF_JMP | BPF_JSET | BPF_K) && i.k == CLONE_VM);
            assert!(jset_thread && jset_vm, "clone flag split not expressed");
            // And this ABI's `clone` nr is matched (to enter the flag check).
            assert!(has_jeq(&prog, abi.nr_clone));
        }
    }

    #[test]
    fn never_denied_syscalls_stay_allowed_in_either_mode() {
        // execve/execveat must stay ALLOWED even when subprocess is absent:
        // bubblewrap execs the confined payload (execve replaces, never spawns).
        // This pins the removals so a future edit cannot silently re-add them
        // and reintroduce a universal false-deny.
        for &abi in ABIS {
            for allow in [true, false] {
                let prog = build_program_for(abi, allow);
                for &nr in abi.never_denied {
                    assert!(
                        !has_jeq(&prog, nr),
                        "never-denied nr {nr} must not be denied (arch={:#x}, allow={allow})",
                        abi.audit_arch
                    );
                }
            }
        }
    }

    #[test]
    fn a_granted_subprocess_program_has_only_the_namespace_check() {
        // With subprocess granted, the only clone-flag test is the namespace
        // mask — no thread/process discriminator, no create denials — on every
        // ABI.
        for &abi in ABIS {
            let prog = build_program_for(abi, true);
            let jsets: Vec<u32> = prog
                .iter()
                .filter(|i| i.code == (BPF_JMP | BPF_JSET | BPF_K))
                .map(|i| i.k)
                .collect();
            assert_eq!(
                jsets,
                vec![CLONE_NEW_MASK],
                "only the namespace JSET when subprocess is granted"
            );
        }
    }

    #[test]
    fn the_program_ends_with_a_default_allow() {
        for &abi in ABIS {
            for allow in [true, false] {
                let prog = build_program_for(abi, allow);
                assert_eq!(*prog.last().expect("non-empty"), ret(SECCOMP_RET_ALLOW));
            }
        }
    }

    #[test]
    fn instruction_encoding_is_eight_little_endian_bytes() {
        // A fixed instruction's byte encoding is pinned: the kernel ABI is
        // code(2) jt(1) jf(1) k(4), emitted native-endian (both supported ABIs
        // are little-endian).
        let insn = ret(SECCOMP_RET_ERRNO | EPERM);
        let bytes = insn.to_bytes();
        assert_eq!(bytes.len(), 8);
        // code = BPF_RET|BPF_K = 0x06, jt=0, jf=0, k=0x00050001.
        assert_eq!(&bytes[0..2], &0x06u16.to_ne_bytes());
        assert_eq!(bytes[2], 0);
        assert_eq!(bytes[3], 0);
        assert_eq!(&bytes[4..8], &0x0005_0001u32.to_ne_bytes());
    }

    #[test]
    fn arch_numbers_match_the_kernel_constants() {
        // A typo silently disables the whole filter for that ABI (every syscall
        // mismatches the arch and is killed — fail-closed — but the value must be
        // exact so a LEGITIMATE program on that ABI is not killed).
        assert_eq!(AUDIT_ARCH_X86_64, 0xC000_003E);
        assert_eq!(AUDIT_ARCH_AARCH64, 0xC000_00B7);
        assert_eq!(X86_64_SYSCALLS.audit_arch, AUDIT_ARCH_X86_64);
        assert_eq!(AARCH64_SYSCALLS.audit_arch, AUDIT_ARCH_AARCH64);
    }

    #[test]
    fn aarch64_has_no_fork_or_vfork_deny() {
        // aarch64 has NO fork/vfork syscall (asm-generic table): its
        // create-denied list is empty, so the subprocess axis rests entirely on
        // the clone flag split. x86_64 keeps fork(57)/vfork(58).
        assert!(AARCH64_SYSCALLS.create_denied_non_clone.is_empty());
        assert_eq!(X86_64_SYSCALLS.create_denied_non_clone, &[57, 58]);
    }

    #[test]
    fn aarch64_syscall_numbers_are_the_asm_generic_values() {
        // Pin the aarch64 numbers to the asm-generic/unistd.h table so a wrong
        // number (e.g. an accidental reuse of an x86_64 nr) is caught in review.
        // Asserted through the table's public fields (the NR consts are private
        // to the ABI module).
        let a = AARCH64_SYSCALLS;
        assert_eq!(a.nr_clone, 220);
        assert_eq!(a.nr_clone3, 435);
        assert_eq!(a.never_denied, &[221, 281], "execve/execveat");
        // Baseline: ptrace(117), pvm_readv/writev(270/271), io_uring(425/426/427),
        // pidfd_getfd(438), bpf(280), userfaultfd(282), keyctl(219),
        // kexec_load(104)/kexec_file_load(294),
        // mount(40)/umount2(39)/pivot_root(41)/setns(268)/unshare(97)/
        // move_mount(429)/open_tree(428)/fsopen(430)/fsconfig(431)/fsmount(432)/
        // mount_setattr(442) — the asm-generic values, in table order.
        assert_eq!(
            a.baseline_denied,
            &[
                117, 270, 271, 425, 426, 427, 438, 280, 282, 219, 104, 294, 40, 39, 41, 268, 97,
                429, 428, 430, 431, 432, 442
            ],
        );
    }

    #[test]
    fn x86_64_syscall_numbers_are_the_unistd_64_values() {
        // Pin the x86_64 numbers to the <asm/unistd_64.h> table so a wrong
        // number (e.g. an accidental reuse of an aarch64 nr) is caught in review.
        // Asserted through the table's public fields (the NR consts are private
        // to the ABI module).
        let a = X86_64_SYSCALLS;
        assert_eq!(a.nr_clone, 56);
        assert_eq!(a.nr_clone3, 435);
        assert_eq!(a.never_denied, &[59, 322], "execve/execveat");
        // Baseline: ptrace(101), pvm_readv/writev(310/311), io_uring(425/426/427),
        // pidfd_getfd(438), bpf(321), userfaultfd(323), keyctl(250),
        // kexec_load(246)/kexec_file_load(320),
        // mount(165)/umount2(166)/pivot_root(155)/setns(308)/unshare(272)/
        // move_mount(429)/open_tree(428)/fsopen(430)/fsconfig(431)/fsmount(432)/
        // mount_setattr(442) — the <asm/unistd_64.h> values, in table order.
        assert_eq!(
            a.baseline_denied,
            &[
                101, 310, 311, 425, 426, 427, 438, 321, 323, 250, 246, 320, 165, 166, 155, 308,
                272, 429, 428, 430, 431, 432, 442
            ],
        );
    }

    #[test]
    fn active_abi_is_some_only_on_a_vetted_arch() {
        // The build-target selector must return a table iff the host arch is one
        // whose numbers are vetted; anything else is None → the caller refuses.
        let selected = active_abi();
        if cfg!(any(target_arch = "x86_64", target_arch = "aarch64")) {
            assert!(selected.is_some(), "vetted arch must have a table");
        } else {
            assert!(selected.is_none(), "unvetted arch must refuse");
        }
    }

    #[test]
    fn program_bytes_is_dense_eight_per_instruction() {
        for &abi in ABIS {
            let prog = build_program_for(abi, false);
            let bytes = program_bytes(&prog);
            assert_eq!(bytes.len(), prog.len() * 8);
        }
    }

    #[test]
    fn clone_block_jump_offsets_land_on_the_right_returns() {
        // The clone thread/process split is the most fragile part — an
        // off-by-one in a jump offset silently allows a process create or kills a
        // thread. Locate the block by its `JEQ clone` head (the last one — the
        // first heads the namespace block) and verify each branch resolves to
        // the intended return, on every ABI.
        for &abi in ABIS {
            let prog = build_program_for(abi, false);
            let c0 = prog
                .iter()
                .rposition(|i| i.code == (BPF_JMP | BPF_JEQ | BPF_K) && i.k == abi.nr_clone)
                .expect("clone JEQ present");
            // c0 jf → default ALLOW (the last instruction).
            let not_clone_target = c0 + 1 + prog[c0].jf as usize;
            assert_eq!(prog[not_clone_target], ret(SECCOMP_RET_ALLOW));
            assert_eq!(
                not_clone_target,
                prog.len() - 1,
                "not-clone → default allow"
            );
            // c2 = JSET CLONE_THREAD, its jf → EPERM.
            let c2 = c0 + 2;
            assert_eq!(prog[c2].code, BPF_JMP | BPF_JSET | BPF_K);
            assert_eq!(prog[c2].k, CLONE_THREAD);
            let thread_clear_target = c2 + 1 + prog[c2].jf as usize;
            assert_eq!(prog[thread_clear_target], ret(SECCOMP_RET_ERRNO | EPERM));
            // c3 = JSET CLONE_VM, its jf → EPERM; its fall-through → ALLOW.
            let c3 = c0 + 3;
            assert_eq!(prog[c3].k, CLONE_VM);
            let vm_clear_target = c3 + 1 + prog[c3].jf as usize;
            assert_eq!(prog[vm_clear_target], ret(SECCOMP_RET_ERRNO | EPERM));
            // Fall-through of c3 (both bits set) is the ALLOW for a thread.
            assert_eq!(prog[c3 + 1], ret(SECCOMP_RET_ALLOW));
        }
    }

    #[test]
    fn x86_64_kills_x32_tagged_syscall_numbers_before_any_compare() {
        // On x86_64 the x32 ABI reports the same audit arch but tags its numbers
        // with X32_SYSCALL_BIT, so an exact-match denylist would let
        // syscall(0x4000_0000|nr) fall through to the default allow. The filter
        // must JGE-kill every tagged number, and that guard must precede every
        // per-syscall JEQ (else a plain-number match could be reached on a tagged
        // number only by luck of ordering).
        assert_eq!(X86_64_SYSCALLS.deny_nr_ge, Some(X32_SYSCALL_BIT));
        assert_eq!(X32_SYSCALL_BIT, 0x4000_0000);
        for allow in [true, false] {
            let prog = build_program_for(X86_64_SYSCALLS, allow);
            let jge = prog
                .iter()
                .position(|i| i.code == (BPF_JMP | BPF_JGE | BPF_K) && i.k == X32_SYSCALL_BIT)
                .expect("x32 JGE guard present on x86_64");
            // Its true branch (jump +jt) lands on a KILL_PROCESS return.
            let kill_target = jge + 1 + prog[jge].jt as usize;
            assert_eq!(prog[kill_target], ret(SECCOMP_RET_KILL_PROCESS));
            // The guard precedes every per-syscall JEQ.
            let first_jeq = prog
                .iter()
                .position(|i| {
                    i.code == (BPF_JMP | BPF_JEQ | BPF_K) && i.k != X86_64_SYSCALLS.audit_arch
                })
                .expect("at least one syscall JEQ");
            assert!(
                jge < first_jeq,
                "x32 kill guard must precede every syscall compare"
            );
        }
    }

    #[test]
    fn aarch64_has_no_secondary_abi_kill_guard() {
        // aarch64 shares its audit arch with no high-bit-tagged secondary ABI, so
        // it needs no JGE guard (and adding one could kill legitimate high-numbered
        // syscalls).
        assert_eq!(AARCH64_SYSCALLS.deny_nr_ge, None);
        for allow in [true, false] {
            let prog = build_program_for(AARCH64_SYSCALLS, allow);
            assert!(
                !prog.iter().any(|i| i.code == (BPF_JMP | BPF_JGE | BPF_K)),
                "aarch64 must emit no JGE range guard"
            );
        }
    }

    #[test]
    fn arch_gate_precedes_every_syscall_compare() {
        // No syscall-number compare may appear before the arch guard, or a
        // wrong-ABI process could match a number before being killed.
        for &abi in ABIS {
            let prog = build_program_for(abi, false);
            let first_nr_load = prog
                .iter()
                .position(|i| *i == stmt(BPF_LD | BPF_W | BPF_ABS, OFF_NR))
                .expect("NR load present");
            // The arch load+branch+kill occupy indices 0,1,2; the NR load is after.
            assert!(first_nr_load >= 3, "NR load must follow the arch guard");
        }
    }
}
