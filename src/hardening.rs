// SPDX-FileCopyrightText: murk contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Process hardening: best-effort defense-in-depth measures.

/// Disable core dumps for this process.
///
/// Sets `RLIMIT_CORE` to 0 on Unix. A core file written after a crash while
/// murk holds decrypted secret material is the worst possible leak — disabling
/// it up front removes the failure mode regardless of system defaults, which
/// vary across Linux distros, macOS, and BSDs.
///
/// Best-effort: a failed syscall is swallowed rather than blocking the
/// command. Idempotent — a second call on a process that's already at zero is
/// a no-op. On non-Unix targets this is a no-op.
pub fn disable_core_dumps() {
    #[cfg(unix)]
    {
        let limit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: setrlimit reads through the pointer for the duration of
        // the call; `limit` lives for that scope. Return code is intentionally
        // ignored — see the doc comment.
        unsafe {
            libc::setrlimit(libc::RLIMIT_CORE, &raw const limit);
        }
    }
}

/// Make this process non-dumpable, so another process running as the same
/// user cannot attach a debugger to it or read its memory or environment
/// through `/proc/<pid>/` while it holds a key or decrypted secrets.
///
/// Linux only: `prctl(PR_SET_DUMPABLE, 0)`. The flag is reset on `execve`, so
/// children murk runs (`murk exec`, the editor) are unaffected. It also stops
/// core dumps, overlapping [`disable_core_dumps`]. Elsewhere this is a no-op:
/// macOS's `PT_DENY_ATTACH` is deliberately not used (it only blocks a
/// cooperating debugger and is a well-known anti-debugging trick, not a
/// boundary); see `THREAT_MODEL.md`. Best-effort like the rest of this module.
pub fn deny_same_user_inspection() {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        // SAFETY: PR_SET_DUMPABLE takes plain integer arguments and touches no
        // memory of ours. The return code is intentionally ignored.
        unsafe {
            libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);
        }
    }
}

/// The effective strict setting: strict is ON when either the operator set a
/// truthy `MURK_STRICT` or this is an [`agent_context`] (`MURK_AGENT`). There is
/// deliberately no way to turn strict OFF from inside an agent context — an
/// operator who wants convenience simply doesn't opt into agent context. Strict
/// mode trades convenience for a safer default: don't write a secret to disk (see
/// [`is_ram_backed`]) and don't fall back to the operator's stored key (see
/// `env::resolve_key_with_source`). This is the toggle the strict gates read.
pub fn strict_mode() -> bool {
    effective_strict_from(
        &std::env::var("MURK_STRICT").unwrap_or_default(),
        &std::env::var("MURK_AGENT").unwrap_or_default(),
    )
}

/// Whether murk is running on behalf of an AI agent, via the explicit
/// `MURK_AGENT` opt-in. Agent context forces strict mode (see [`strict_mode`]) so
/// the honest path never falls back to the operator's stored key. `murk agent
/// exec` sets it (alongside `MURK_STRICT`) for the child. This is a safe default,
/// not a sandbox: a child that controls its own environment or can read
/// `~/.config/murk/keys` directly is outside murk's boundary — real containment
/// is OS-level isolation (see the note in `docs/ai-agents.md`).
pub fn agent_context() -> bool {
    strict_from(&std::env::var("MURK_AGENT").unwrap_or_default())
}

/// Whether murk appears to be running in CI (the conventional `CI` variable set
/// truthy). Advisory only: CI context drives a nudge toward the scoped agent
/// path but — unlike [`agent_context`] — does not by itself flip strict mode, so
/// existing pipelines are never silently changed.
pub fn ci_context() -> bool {
    truthy(&std::env::var("CI").unwrap_or_default())
}

/// Whether the operator opted into self-scoping: honoring the vault's agent
/// allow-tag policy for their OWN key, as if they were an agent. On via an
/// explicit `MURK_SELF_SCOPE`, or implicitly in an [`agent_context`] (declaring
/// `MURK_AGENT` binds you to the policy even with your own key). A no-op on a
/// vault with no policy set.
pub fn self_scope() -> bool {
    strict_from(&std::env::var("MURK_SELF_SCOPE").unwrap_or_default()) || agent_context()
}

/// Whether a restricting flag (`MURK_STRICT`, `MURK_AGENT`, `MURK_SELF_SCOPE`)
/// is on. It fails closed: only unset, empty, `0`, `false`, `no` and `off`
/// (case-insensitive, trimmed) are off, so `on`, `enabled`, `2` or a typo turn
/// the restriction on rather than silently leaving it off. Split out so the
/// rules are testable without mutating process-global env state.
fn strict_from(val: &str) -> bool {
    !matches!(
        val.trim().to_ascii_lowercase().as_str(),
        "" | "0" | "false" | "no" | "off"
    )
}

/// Conventional truthiness (`1`, `true`, `yes`; case-insensitive, trimmed) for
/// `CI`, which murk only reads to decide whether to print an advisory and which
/// CI systems set to values of their own.
fn truthy(val: &str) -> bool {
    matches!(
        val.trim().to_ascii_lowercase().as_str(),
        "1" | "true" | "yes"
    )
}

/// Pure effective-strict decision from raw env values, split out for testing.
/// Strict is on when `MURK_STRICT` is truthy OR `MURK_AGENT` (agent context) is
/// truthy; agent context cannot be overridden off.
fn effective_strict_from(strict: &str, agent: &str) -> bool {
    strict_from(strict) || strict_from(agent)
}

/// Whether `path` lives on a RAM-backed filesystem (tmpfs/ramfs), meaning data
/// written there never hits persistent storage.
///
/// Used to fail closed in strict mode before `murk edit` writes a decrypted
/// secret to a scratch file: a best-effort overwrite-and-unlink can't undo a
/// write to a journaled or copy-on-write disk, and editors leave their own swap
/// files behind, so the only real guarantee is to never write to disk at all.
///
/// On Linux a tmpfs/ramfs mount is identified by its `statfs` magic number. On
/// macOS there is no tmpfs by default, so this returns `false` for the usual
/// `/tmp` — which is the honest answer. On non-Unix targets this returns
/// `false` (assume disk-backed; we can't prove otherwise).
pub fn is_ram_backed(path: &std::path::Path) -> bool {
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::ffi::OsStrExt;
        // TMPFS_MAGIC and RAMFS_MAGIC from <linux/magic.h>.
        const TMPFS_MAGIC: libc::c_long = 0x0102_1994;
        const RAMFS_MAGIC: libc::c_long = 0x858_458f6_u64 as libc::c_long;

        let Ok(c_path) = std::ffi::CString::new(path.as_os_str().as_bytes()) else {
            return false;
        };
        // SAFETY: zeroed statfs is a valid initial state; statfs writes into it
        // for the duration of the call, and `c_path` outlives the call.
        let mut buf: libc::statfs = unsafe { std::mem::zeroed() };
        let rc = unsafe { libc::statfs(c_path.as_ptr(), &raw mut buf) };
        rc == 0 && matches!(buf.f_type as libc::c_long, TMPFS_MAGIC | RAMFS_MAGIC)
    }
    #[cfg(target_os = "macos")]
    {
        use std::os::unix::ffi::OsStrExt;
        let Ok(c_path) = std::ffi::CString::new(path.as_os_str().as_bytes()) else {
            return false;
        };
        // SAFETY: as above; macOS statfs reports the filesystem type by name.
        let mut buf: libc::statfs = unsafe { std::mem::zeroed() };
        let rc = unsafe { libc::statfs(c_path.as_ptr(), &raw mut buf) };
        if rc != 0 {
            return false;
        }
        // f_fstypename is a fixed-size [c_char] holding a NUL-terminated name.
        let name: Vec<u8> = buf
            .f_fstypename
            .iter()
            .take_while(|&&c| c != 0)
            .map(|&c| c.cast_unsigned())
            .collect();
        name == b"tmpfs"
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = path;
        false
    }
}

/// Whether this process's stdout is a regular file (as opposed to a pipe,
/// terminal, or device).
///
/// Strict mode uses this to catch `murk export > secrets.env` style redirects
/// that would persist plaintext secrets to disk, while still allowing the
/// `eval "$(murk export)"` pipe that direnv relies on. Unix-only; returns
/// `false` elsewhere (can't determine — don't block).
pub fn stdout_is_regular_file() -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::io::{AsRawFd, FromRawFd};
        // Borrow stdout's fd as a File to read its metadata. ManuallyDrop keeps
        // dropping the File from closing the real stdout — we only borrowed it.
        let fd = std::io::stdout().as_raw_fd();
        let f = std::mem::ManuallyDrop::new(unsafe { std::fs::File::from_raw_fd(fd) });
        f.metadata().is_ok_and(|m| m.is_file())
    }
    #[cfg(not(unix))]
    {
        false
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn disables_core_dumps() {
        disable_core_dumps();

        let mut current = libc::rlimit {
            rlim_cur: 1,
            rlim_max: 1,
        };
        // SAFETY: getrlimit writes into `&mut current` for the duration of
        // the call.
        let rc = unsafe { libc::getrlimit(libc::RLIMIT_CORE, &raw mut current) };
        assert_eq!(rc, 0, "getrlimit failed");
        assert_eq!(current.rlim_cur, 0);
        assert_eq!(current.rlim_max, 0);
    }

    #[test]
    fn strict_truthiness() {
        for on in [
            "1", "true", "yes", "YES", " True ", "Yes", "on", "enabled", "2", "ture",
        ] {
            assert!(strict_from(on), "{on:?} should enable strict mode");
        }
        for off in ["", " ", "0", "false", "no", "off", "OFF", " False "] {
            assert!(!strict_from(off), "{off:?} should not enable strict mode");
        }
    }

    #[test]
    fn effective_strict_from_decision_table() {
        // (MURK_STRICT, MURK_AGENT, expected effective strict)
        let cases = [
            ("1", "", true),
            ("yes", "", true),
            ("", "1", true),
            ("true", "true", true),
            // Security-critical rows: agent context is NOT overridable —
            // a truthy MURK_AGENT forces strict even when MURK_STRICT is
            // explicitly falsy.
            ("0", "1", true),
            ("false", "1", true),
            ("bogus", "1", true),
            ("", "", false),
            ("0", "", false),
            ("", "0", false),
            // A value murk does not recognise fails closed.
            ("bogus", "", true),
            ("off", "enabled", true),
            ("off", "no", false),
        ];
        for (strict, agent, expected) in cases {
            assert_eq!(
                effective_strict_from(strict, agent),
                expected,
                "strict={strict:?} agent={agent:?}"
            );
        }
    }

    #[test]
    fn nonexistent_path_is_not_ram_backed() {
        // statfs fails on a missing path; we must not report it as RAM-backed.
        assert!(!is_ram_backed(std::path::Path::new(
            "/no/such/murk/path/exists"
        )));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn dev_shm_is_ram_backed() {
        let shm = std::path::Path::new("/dev/shm");
        if shm.is_dir() {
            assert!(is_ram_backed(shm), "/dev/shm should be tmpfs");
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_tmp_is_not_ram_backed() {
        // macOS has no tmpfs by default; the disk-backed temp dir must read false.
        assert!(!is_ram_backed(&std::env::temp_dir()));
    }

    #[test]
    fn agent_context_tracks_murk_agent() {
        let _env = crate::testutil::ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let prev = std::env::var("MURK_AGENT").ok();

        unsafe { std::env::set_var("MURK_AGENT", "1") };
        assert!(agent_context(), "MURK_AGENT=1 is agent context");
        unsafe { std::env::remove_var("MURK_AGENT") };
        assert!(!agent_context(), "unset MURK_AGENT is not agent context");

        unsafe {
            match prev {
                Some(v) => std::env::set_var("MURK_AGENT", v),
                None => std::env::remove_var("MURK_AGENT"),
            }
        }
    }

    #[test]
    fn ci_context_tracks_ci_env() {
        let _env = crate::testutil::ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let prev = std::env::var("CI").ok();

        unsafe { std::env::set_var("CI", "1") };
        assert!(ci_context(), "CI=1 is CI context");
        unsafe { std::env::remove_var("CI") };
        assert!(!ci_context(), "unset CI is not CI context");

        unsafe {
            match prev {
                Some(v) => std::env::set_var("CI", v),
                None => std::env::remove_var("CI"),
            }
        }
    }

    #[test]
    fn self_scope_from_opt_in_or_agent_context() {
        let _env = crate::testutil::ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let prev_ss = std::env::var("MURK_SELF_SCOPE").ok();
        let prev_agent = std::env::var("MURK_AGENT").ok();
        unsafe { std::env::remove_var("MURK_AGENT") };

        // Explicit self-scope opt-in, no agent context → on (guards `||`).
        unsafe { std::env::set_var("MURK_SELF_SCOPE", "1") };
        assert!(self_scope(), "explicit MURK_SELF_SCOPE opt-in");

        // Neither opt-in nor agent context → off.
        unsafe { std::env::remove_var("MURK_SELF_SCOPE") };
        assert!(!self_scope(), "no opt-in and no agent context");

        // Agent context alone implies self-scope (binds you to the policy).
        unsafe { std::env::set_var("MURK_AGENT", "1") };
        assert!(self_scope(), "agent context implies self-scope");

        unsafe {
            match prev_ss {
                Some(v) => std::env::set_var("MURK_SELF_SCOPE", v),
                None => std::env::remove_var("MURK_SELF_SCOPE"),
            }
            match prev_agent {
                Some(v) => std::env::set_var("MURK_AGENT", v),
                None => std::env::remove_var("MURK_AGENT"),
            }
        }
    }
}
