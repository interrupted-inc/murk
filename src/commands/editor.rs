// SPDX-FileCopyrightText: murk contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! `murk edit`'s editor session: write the plaintext to a scratch file, run
//! `$EDITOR` on it, read it back, and wipe the file on every way out.
//!
//! Nothing here exits the process, so the wipe always runs. On Unix:
//!
//! - **The editor runs through `sh`**, as with git, so `EDITOR` may carry
//!   arguments (`code --wait`); `exec` keeps the common case to one process.
//! - **It leads a process group of its own**, which murk hands the terminal
//!   while it runs, the way a shell runs a job. Keys like Ctrl-C reach the
//!   editor only, and a signal sent to murk (`kill <pid>`) is forwarded to the
//!   editor's whole group, so a wrapper's children get it too.
//! - **Ctrl-Z** stops the editor; murk then takes the terminal back and stops
//!   itself so the shell sees the job stop, and on `fg` resumes the editor.
//! - **Before the wipe, the whole group is gone**: whatever outlives the
//!   editor gets SIGTERM, then SIGKILL after [`GRACE`], so no leftover process
//!   can save the plaintext again after murk removed it. A process that leaves
//!   the group (a daemon, or a hand-off to an already running app instance) is
//!   out of reach.

use super::secrets::overwrite_and_remove;
#[cfg(unix)]
use super::signals;
use std::fs;
use std::path::Path;
use std::process::{self, ExitStatus};
use zeroize::Zeroizing;

/// Why [`edit_in_scratch_file`] returned no text.
pub(crate) enum EditAbort {
    /// Report the message and exit 1.
    Failed(String),
    /// The editor was killed by this signal.
    #[cfg(unix)]
    Signaled(i32),
}

use EditAbort::Failed;

/// The plaintext scratch file. Dropping it overwrites and removes it, so every
/// return from [`edit_in_scratch_file`], and an unwinding panic, wipes it.
struct ScratchFile(tempfile::TempPath);

impl Drop for ScratchFile {
    fn drop(&mut self) {
        overwrite_and_remove(&self.0);
    }
}

/// Signal handling while the scratch file exists (see [`super::signals`]).
/// Dropping restores the defaults and re-raises a signal caught while no
/// editor ran.
#[cfg(unix)]
struct EditorSignals;

#[cfg(unix)]
impl EditorSignals {
    fn install() -> Self {
        signals::install();
        Self
    }
}

#[cfg(unix)]
impl Drop for EditorSignals {
    fn drop(&mut self) {
        signals::stop_forwarding();
    }
}

/// Write `buffer` to a scratch file in `dir`, open it in the editor, and return
/// the edited text. The caller reports errors once the scratch file is gone.
pub(crate) fn edit_in_scratch_file(
    dir: &Path,
    buffer: &str,
) -> Result<Zeroizing<String>, EditAbort> {
    use std::io::Write;

    // Declared before the scratch file so it drops after the wipe: until then
    // no signal can end murk with the plaintext on disk.
    #[cfg(unix)]
    let _signals = EditorSignals::install();

    let (mut file, path) = tempfile::Builder::new()
        .prefix("murk-edit-")
        .suffix(".env")
        .tempfile_in(dir)
        .map_err(|e| Failed(format!("creating tempfile: {e}")))?
        .into_parts();
    let path = ScratchFile(path);

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = file.set_permissions(std::fs::Permissions::from_mode(0o600));
    }
    file.write_all(buffer.as_bytes())
        .and_then(|()| file.flush())
        .map_err(|e| Failed(format!("writing tempfile: {e}")))?;
    drop(file);

    let editor = std::env::var("EDITOR")
        .or_else(|_| std::env::var("VISUAL"))
        .unwrap_or_else(|_| "vi".into());
    let status = run_editor(&editor, &path.0)?;

    #[cfg(unix)]
    if let Some(sig) = std::os::unix::process::ExitStatusExt::signal(&status) {
        return Err(EditAbort::Signaled(sig));
    }
    if !status.success() {
        return Err(Failed("editor exited with error — aborting".into()));
    }

    fs::read_to_string(&path.0)
        .map(Zeroizing::new)
        .map_err(|e| Failed(format!("reading tempfile: {e}")))
}

/// The editor must not see the key.
fn strip_key(cmd: &mut process::Command) {
    cmd.env_remove("MURK_KEY");
    cmd.env_remove("MURK_KEY_FILE");
}

#[cfg(not(unix))]
fn run_editor(editor: &str, path: &Path) -> Result<ExitStatus, EditAbort> {
    let mut cmd = process::Command::new(editor);
    cmd.arg(path);
    strip_key(&mut cmd);
    cmd.status()
        .map_err(|e| Failed(format!("launching {editor}: {e}")))
}

/// How long the editor's leftover processes get after SIGTERM, and again
/// after SIGKILL, before murk wipes the file regardless.
#[cfg(unix)]
const GRACE: std::time::Duration = std::time::Duration::from_secs(2);

/// Run the editor in its own process group (see the module docs) and return
/// once the leader and everything left in its group have exited.
#[cfg(unix)]
fn run_editor(editor: &str, path: &Path) -> Result<ExitStatus, EditAbort> {
    use std::os::unix::process::{CommandExt, ExitStatusExt};

    let tty = terminal();
    let handoff = tty.filter(|&fd| in_foreground(fd));

    let mut cmd = process::Command::new("sh");
    cmd.arg("-c")
        .arg(format!("exec {editor} \"$@\""))
        .arg("sh")
        .arg(path);
    strip_key(&mut cmd);
    // SAFETY: the hook runs between fork and exec and makes only
    // async-signal-safe calls (setpgid, getpid, pthread_sigmask, tcsetpgrp).
    unsafe {
        cmd.pre_exec(move || {
            libc::setpgid(0, 0);
            if let Some(fd) = handoff {
                give_terminal(fd, libc::getpid());
            }
            Ok(())
        });
    }
    let child = cmd
        .spawn()
        .map_err(|e| Failed(format!("launching {editor}: {e}")))?;
    let pgid = child.id() as libc::pid_t;
    // Repeat both steps here, as a shell does, so it doesn't matter whether
    // the parent or the child gets there first.
    // SAFETY: plain syscall on our own child.
    unsafe {
        libc::setpgid(pgid, pgid);
    }
    if let Some(fd) = handoff {
        give_terminal(fd, pgid);
    }
    signals::set_group(pgid);

    let waited = wait_leader(pgid, tty);
    if let Some(fd) = tty {
        take_terminal(fd, pgid);
    }
    end_group(pgid);
    signals::clear();

    waited
        .map(ExitStatus::from_raw)
        .map_err(|e| Failed(format!("waiting for {editor}: {e}")))
}

/// Reap the editor (the group leader) and return its raw wait status. A stop
/// (Ctrl-Z) suspends murk too, and resumes the editor once murk resumes.
#[cfg(unix)]
fn wait_leader(pgid: libc::pid_t, tty: Option<libc::c_int>) -> std::io::Result<libc::c_int> {
    loop {
        let mut status = 0;
        // SAFETY: waitpid writes into `status`, which outlives the call.
        if unsafe { libc::waitpid(pgid, &raw mut status, libc::WUNTRACED) } == -1 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(err);
        }
        if !libc::WIFSTOPPED(status) {
            return Ok(status);
        }
        if let Some(fd) = tty {
            take_terminal(fd, pgid);
        }
        // SAFETY: plain syscalls. SIGTSTP stops murk until the shell resumes
        // it; then the editor gets the terminal back if murk has it.
        unsafe {
            libc::raise(libc::SIGTSTP);
        }
        if let Some(fd) = tty.filter(|&fd| in_foreground(fd)) {
            give_terminal(fd, pgid);
        }
        // SAFETY: plain syscall on our own child's group.
        unsafe {
            libc::kill(-pgid, libc::SIGCONT);
        }
    }
}

/// Terminate whatever is left of the editor's group and wait for it to be
/// empty: SIGTERM, then SIGKILL, each followed by up to [`GRACE`].
#[cfg(unix)]
fn end_group(pgid: libc::pid_t) {
    use std::time::{Duration, Instant};
    for sig in [libc::SIGTERM, libc::SIGKILL] {
        if !group_alive(pgid) {
            return;
        }
        // SAFETY: plain syscalls. SIGCONT wakes a stopped process so it can
        // act on SIGTERM.
        unsafe {
            libc::kill(-pgid, sig);
            libc::kill(-pgid, libc::SIGCONT);
        }
        let deadline = Instant::now() + GRACE;
        while group_alive(pgid) && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}

#[cfg(unix)]
fn group_alive(pgid: libc::pid_t) -> bool {
    // SAFETY: signal 0 only checks that the group exists.
    let alive = unsafe { libc::kill(-pgid, 0) } == 0;
    alive || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

/// The first of stdin, stdout and stderr that is a terminal.
#[cfg(unix)]
fn terminal() -> Option<libc::c_int> {
    // SAFETY: isatty only inspects the descriptor.
    [0, 1, 2]
        .into_iter()
        .find(|&fd| unsafe { libc::isatty(fd) } == 1)
}

/// Whether murk's process group owns the terminal (murk is a foreground job).
#[cfg(unix)]
fn in_foreground(fd: libc::c_int) -> bool {
    // SAFETY: plain syscalls.
    unsafe { libc::tcgetpgrp(fd) == libc::getpgrp() }
}

/// Give the terminal back to murk's group, if the editor's group has it.
#[cfg(unix)]
fn take_terminal(fd: libc::c_int, pgid: libc::pid_t) {
    // SAFETY: plain syscalls.
    if unsafe { libc::tcgetpgrp(fd) } == pgid {
        give_terminal(fd, unsafe { libc::getpgrp() });
    }
}

/// Make `pgid` the terminal's foreground group. SIGTTOU is blocked meanwhile:
/// a background process calling tcsetpgrp would otherwise be stopped by it.
#[cfg(unix)]
fn give_terminal(fd: libc::c_int, pgid: libc::pid_t) {
    // SAFETY: plain, async-signal-safe syscalls on stack-local signal sets.
    unsafe {
        let mut block: libc::sigset_t = std::mem::zeroed();
        let mut old: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&raw mut block);
        libc::sigaddset(&raw mut block, libc::SIGTTOU);
        libc::pthread_sigmask(libc::SIG_BLOCK, &raw const block, &raw mut old);
        libc::tcsetpgrp(fd, pgid);
        libc::pthread_sigmask(libc::SIG_SETMASK, &raw const old, std::ptr::null_mut());
    }
}
