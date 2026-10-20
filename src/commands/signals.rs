//! Signal forwarding for a child murk waits on (`murk agent exec`'s masked
//! command, `murk edit`'s editor).
//!
//! While installed, SIGINT, SIGTERM, SIGHUP and SIGQUIT do not kill murk. One
//! sent by another process (`kill <pid>`) is forwarded to the child, or to the
//! child's whole process group once [`set_group`] names one. A child sharing
//! murk's process group already got what the terminal sends that group, so
//! terminal signals are not forwarded to it again. [`stop_forwarding`]
//! restores the default actions and re-raises a signal caught while no child
//! was running.

use std::sync::atomic::{AtomicI32, Ordering};

/// The signals forwarded to the child.
const FORWARDED: [libc::c_int; 4] = [libc::SIGINT, libc::SIGTERM, libc::SIGHUP, libc::SIGQUIT];

/// Where a signal is forwarded, as a `kill(2)` target: the child's pid, the
/// negated id of its own process group, or 0 when there is none (not spawned
/// yet, or gone).
static CHILD: AtomicI32 = AtomicI32::new(0);
/// A forwardable signal that arrived before the child existed.
static PENDING: AtomicI32 = AtomicI32::new(0);

/// Async-signal-safe handler: atomics and `kill(2)` only.
extern "C" fn forward(sig: libc::c_int, info: *mut libc::siginfo_t, _ctx: *mut libc::c_void) {
    let target = CHILD.load(Ordering::SeqCst);
    // No child to deliver to (not spawned yet, or already exited): keep the
    // signal for `set_child` to forward or `stop_forwarding` to re-raise.
    if target == 0 {
        PENDING.store(sig, Ordering::SeqCst);
        return;
    }
    // SAFETY: with SA_SIGINFO the kernel passes a valid siginfo_t (null is
    // checked anyway); si_pid is defined for these signals.
    let sender = if info.is_null() {
        0
    } else {
        unsafe { (*info).si_pid() }
    };
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
            libc::sigemptyset(&raw mut action.sa_mask);
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
    let early = PENDING.swap(0, Ordering::SeqCst);
    if early != 0 {
        // SAFETY: plain syscall on our own, not yet reaped, child or its group.
        unsafe {
            libc::kill(target, early);
        }
    }
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
        raise_default(pending);
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
