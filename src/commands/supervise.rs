// SPDX-FileCopyrightText: murk contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Supervised child for `murk agent exec`: spawn the command with piped stdout
//! and stderr, mask the injected secret values in both streams, and pass the
//! child's exit status through.
//!
//! Plain `murk exec` still replaces itself with the child (`execve`), so it
//! never sees the output. Agent exec cannot: masking needs murk in the middle.
//! What that changes for the child:
//!
//! - **stdout and stderr are pipes, not the terminal.** Programs that check
//!   `isatty` may drop colour, progress bars, or line buffering. stdin is still
//!   inherited, so prompts that read the terminal keep working.
//! - **murk waits for both streams to close**, not only for the child to exit.
//!   A background process that keeps the pipes open keeps murk running; its
//!   output is masked too.
//! - **Signals.** The child stays in murk's process group, so a key the terminal
//!   turns into a signal (Ctrl-C, Ctrl-\, a hangup) reaches both directly, as it
//!   did before. SIGINT, SIGTERM, SIGHUP and SIGQUIT sent to murk alone by
//!   another process (`kill <pid>`, a harness timeout) are forwarded to the
//!   child. Terminal-generated signals are not forwarded, so the child does not
//!   see a Ctrl-C twice. Once the child has exited, these signals get their
//!   default action back (one caught in between is re-raised), so murk stays
//!   killable while a background process still holds the pipes.
//! - **Exit status.** murk exits with the child's code. If the child died from
//!   a signal, murk re-raises that signal on itself (falling back to `128 + N`),
//!   so the caller sees the same status.
//!
//! The masking is an accident guard, not a boundary: see `murk_cli::mask`.

use super::die;
#[cfg(unix)]
use super::signals;
use murk_cli::mask::Masker;
use std::io::{self, Read, Write};
use std::process::{self, Command, ExitStatus, Stdio};
use zeroize::Zeroize;

/// Read size for each output stream. A read returns as soon as the child has
/// written anything, so this bounds a chunk, not the latency.
const CHUNK: usize = 8 * 1024;

/// Spawn `cmd` with masked stdout and stderr, wait for it, and exit the way it
/// did. Never returns.
pub(crate) fn run_masked(mut cmd: Command, masker: &Masker) -> ! {
    cmd.stdin(Stdio::inherit())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    #[cfg(unix)]
    signals::install();

    let program = cmd.get_program().to_string_lossy().into_owned();
    let mut child = cmd
        .spawn()
        .unwrap_or_else(|e| die(&format_args!("{program}: {e}"), 1));
    // The env block in `cmd` holds plaintext values; it is not needed any more.
    drop(cmd);

    #[cfg(unix)]
    signals::set_child(child.id());

    let child_out = child.stdout.take().expect("stdout is piped");
    let child_err = child.stderr.take().expect("stderr is piped");

    // Drain both streams at once: reading one to EOF before the other deadlocks
    // as soon as the child fills the other pipe's buffer.
    let status = std::thread::scope(|s| {
        s.spawn(|| pump(child_out, io::stdout(), masker));
        s.spawn(|| pump(child_err, io::stderr(), masker));
        wait(&mut child)
    });

    exit_like(status)
}

/// Copy `src` to `dst` through a [`MaskStream`](murk_cli::mask::MaskStream),
/// writing each chunk as soon as it is read. Stops early if `dst` fails (for
/// example a closed pipe): dropping `src` then closes the child's end, so the
/// child gets `SIGPIPE`/`EPIPE` on its next write, as it would have when it
fn pump(mut src: impl Read, mut dst: impl Write, masker: &Masker) {
    let mut stream = masker.stream();
    let mut buf = vec![0u8; CHUNK];
    loop {
        let n = match src.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => break,
        };
        let out = stream.push(&buf[..n]);
        if dst.write_all(&out).and_then(|()| dst.flush()).is_err() {
            buf.zeroize();
            return;
        }
    }
    buf.zeroize();
    let _ = dst.write_all(&stream.finish());
    let _ = dst.flush();
}

/// Wait for the child. On Unix, stop forwarding signals before it is reaped,
/// so a forwarded signal can never reach a recycled pid, then hand the
/// forwarded signals back their default action.
fn wait(child: &mut process::Child) -> ExitStatus {
    #[cfg(unix)]
    signals::wait_exited(child.id());
    let status = child
        .wait()
        .unwrap_or_else(|e| die(&format_args!("waiting for the command: {e}"), 1));
    #[cfg(unix)]
    signals::stop_forwarding();
    status
}

/// Exit with the child's status: its code, or its terminating signal.
fn exit_like(status: ExitStatus) -> ! {
    let _ = io::stdout().flush();
    let _ = io::stderr().flush();
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        if let Some(sig) = status.signal() {
            signals::raise_default(sig);
            process::exit(128 + sig);
        }
    }
    process::exit(status.code().unwrap_or(1));
}
