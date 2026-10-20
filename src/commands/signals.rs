//! Signal forwarding for a child murk waits on (`murk agent exec`'s masked
//! command, `murk edit`'s editor).
//!
//! While installed, SIGINT, SIGTERM, SIGHUP and SIGQUIT do not kill murk. One
//! sent by another process (`kill <pid>`) is forwarded to the child, or to the
//! child's whole process group once [`set_group`] names one. A signal the
//! child sends murk is not echoed back to it, even one sent before murk
//! knows the child's pid. A child sharing murk's process group already got
//! what the terminal sends that group, so terminal signals are not forwarded
//! to it again. [`stop_forwarding`] restores the default actions and
//! re-raises a signal caught while no child was running.

use std::sync::atomic::{AtomicI32, AtomicU64, Ordering};

/// The signals forwarded to the child.
const FORWARDED: [libc::c_int; 4] = [libc::SIGINT, libc::SIGTERM, libc::SIGHUP, libc::SIGQUIT];

/// Where a signal is forwarded, as a `kill(2)` target: the child's pid, the
/// negated id of its own process group, or 0 when there is none (not spawned
/// yet, or gone).
static CHILD: AtomicI32 = AtomicI32::new(0);
/// The last forwardable signal that arrived with no child to deliver it to,
/// packed with its sender by [`pack`] in one value, so a handler can never
/// pair one signal with another's sender; 0 when there is none. The sender
/// matters because a child that signals murk the moment it starts can do so
/// before murk knows its pid, and must not get the signal back.
///
/// This is one slot, not a queue: if several forwardable signals arrive
/// before the child is registered, the last one wins and earlier ones are
/// dropped.
///
/// Invariant: the value in the slot is acted on exactly once: delivered,
/// deliberately skipped as the child's own, or re-raised by
/// [`stop_forwarding`] when no child was ever registered for it. Whoever
/// claims it with `swap(0)` acts on it; the other side finds 0. A handler
/// that saw no child publishes the signal, then re-reads [`CHILD`];
/// [`set_target`] publishes the child, then claims [`PENDING`]. All four
/// accesses are SeqCst, so in their single total order at least one side
/// sees the other's write: a signal stored just after `set_target`'s swap
/// is claimed by the handler's own re-check, never left behind.
static PENDING: AtomicU64 = AtomicU64::new(0);

/// One [`PENDING`] value: the sender's pid in the high half, the signal in
/// the low half (never 0, so a packed value is never 0 either).
fn pack(sig: libc::c_int, sender: libc::pid_t) -> u64 {
    (u64::from(sender as u32) << 32) | u64::from(sig as u32)
}

/// The signal and sender a non-zero [`PENDING`] value holds.
fn unpack(pending: u64) -> (libc::c_int, libc::pid_t) {
    (
        pending as u32 as libc::c_int,
        (pending >> 32) as u32 as libc::pid_t,
    )
}

/// The sender of the signal `info` describes; 0 for the kernel.
fn sender(info: *const libc::siginfo_t) -> libc::pid_t {
    if info.is_null() {
        return 0;
    }
    // SAFETY: with SA_SIGINFO the kernel passes a valid siginfo_t (null is
    // checked anyway); si_pid is defined for these signals.
    unsafe { (*info).si_pid() }
}

/// Async-signal-safe handler: atomics and `kill(2)` only.
extern "C" fn forward(sig: libc::c_int, info: *mut libc::siginfo_t, _ctx: *mut libc::c_void) {
    let target = CHILD.load(Ordering::SeqCst);
    let sender = sender(info);
    // No child to deliver to (not spawned yet, or already exited): keep the
    // signal for `set_child` to forward or `stop_forwarding` to re-raise,
    // unless a child was registered meanwhile (see `PENDING`).
    if target == 0 {
        PENDING.store(pack(sig, sender), Ordering::SeqCst);
        let target = CHILD.load(Ordering::SeqCst);
        if target != 0 {
            // No getpgid here: it is not async-signal-safe. So only the
            // group's leader counts as the child, and a signal another member
            // sent before `set_group` would be forwarded to the group.
            deliver_pending(target, PENDING.swap(0, Ordering::SeqCst), |_| false);
        }
        return;
    }
    // Sender 0 is the kernel: a terminal key or hangup, delivered to the
    // whole foreground process group, so a child in murk's group already has
    // it. A signal from the child itself is not echoed back.
    if (sender == 0 && target > 0) || sender == target.abs() {
        return;
    }
    // SAFETY: kill(2) is async-signal-safe.
    unsafe {
        libc::kill(target, sig);
    }
}

/// Deliver a claimed [`PENDING`] value (0: nothing to do) to `target`,
/// unless the child sent it itself before murk knew its pid: the target's
/// pid or group leader, or, for a group, a sender `in_group` accepts.
/// Async-signal-safe if `in_group` is.
fn deliver_pending(target: libc::pid_t, pending: u64, in_group: impl Fn(libc::pid_t) -> bool) {
    if pending == 0 {
        return;
    }
    let (sig, from) = unpack(pending);
    if from != 0 && (from == target.abs() || (target < 0 && in_group(from))) {
        return;
    }
    // SAFETY: kill(2) is async-signal-safe; the target is our own, not yet
    // reaped, child or its group.
    unsafe {
        libc::kill(target, sig);
    }
}

/// Catch the forwarded signals so they don't kill murk while the child runs.
/// A caught signal resets to its default in the child on exec.
pub(crate) fn install() {
    for sig in FORWARDED {
        // SAFETY: a zeroed sigaction is a valid starting value; the handler
        // is async-signal-safe and lives for the whole process.
        unsafe {
            let mut action: libc::sigaction = std::mem::zeroed();
            action.sa_sigaction = forward as *const () as libc::sighandler_t;
            action.sa_flags = libc::SA_SIGINFO | libc::SA_RESTART;
            // A forwarded signal waits until the handler running on its
            // thread is done, rather than interrupting it mid-update.
            libc::sigemptyset(&raw mut action.sa_mask);
            for blocked in FORWARDED {
                libc::sigaddset(&raw mut action.sa_mask, blocked);
            }
            libc::sigaction(sig, &raw const action, std::ptr::null_mut());
        }
    }
}

/// Record the child's pid, then forward any signal that arrived first.
pub(crate) fn set_child(pid: u32) {
    set_target(pid as libc::pid_t);
}

/// Forward to the whole process group `pgid` (a child that leads its own
/// group), then forward any signal that arrived first. [`clear`] stops it.
pub(crate) fn set_group(pgid: libc::pid_t) {
    set_target(-pgid);
}

/// Stop forwarding; signals caught from now on are kept for
/// [`stop_forwarding`] to re-raise.
pub(crate) fn clear() {
    CHILD.store(0, Ordering::SeqCst);
}

fn set_target(target: libc::pid_t) {
    CHILD.store(target, Ordering::SeqCst);
    deliver_pending(target, PENDING.swap(0, Ordering::SeqCst), |from| {
        // SAFETY: plain syscall; a sender that has gone fails with -1.
        unsafe { libc::getpgid(from) == -target }
    });
}

/// Block until the child has exited, without reaping it, so the pid stays
/// ours until forwarding is turned off.
pub(crate) fn wait_exited(pid: u32) {
    loop {
        // SAFETY: waitid writes into `info`, which outlives the call.
        let rc = unsafe {
            let mut info: libc::siginfo_t = std::mem::zeroed();
            libc::waitid(
                libc::P_PID,
                pid as libc::id_t,
                &raw mut info,
                libc::WEXITED | libc::WNOWAIT,
            )
        };
        if rc == 0 || std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted {
            break;
        }
    }
    CHILD.store(0, Ordering::SeqCst);
}

/// The child is reaped: give the forwarded signals their default action
/// back, then re-raise one caught since the child exited. Default first, so
/// a signal arriving after the swap kills murk directly instead of landing
/// in `PENDING` unseen.
pub(crate) fn stop_forwarding() {
    for sig in FORWARDED {
        // SAFETY: plain syscall on this process.
        unsafe {
            libc::signal(sig, libc::SIG_DFL);
        }
    }
    let pending = PENDING.swap(0, Ordering::SeqCst);
    if pending != 0 {
        raise_default(unpack(pending).0);
    }
}

/// Die from `sig` the way the child did: default disposition, then raise.
/// Returns only if the signal did not end the process.
pub(crate) fn raise_default(sig: libc::c_int) {
    // SAFETY: plain syscalls on this process.
    unsafe {
        libc::signal(sig, libc::SIG_DFL);
        let mut set: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&raw mut set);
        libc::sigaddset(&raw mut set, sig);
        libc::pthread_sigmask(libc::SIG_UNBLOCK, &raw const set, std::ptr::null_mut());
        libc::raise(sig);
    }
}
