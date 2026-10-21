// SPDX-FileCopyrightText: murk contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! In-process MCP (Model Context Protocol) stdio server — `murk mcp`.
//!
//! Serves murk secrets to AI-agent harnesses (omp, Claude Code, Cursor, ...)
//! over the MCP stdio transport, calling the murk-cli library in-process. The
//! caller-side security gate — this must be a scoped *grant* identity, not the
//! operator's key — lives in [`crate::cmd_mcp`]; by the time [`serve`] runs the
//! identity is already trusted and bounded to the grant's scope.
//!
//! stdout is the JSON-RPC channel: **never** write to it (no `println!`). Every
//! diagnostic goes to stderr via `tracing`. tokio is confined to this module —
//! the rest of murk stays synchronous.
//!
//! Tools: `murk_plan` (value-free, grant-scoped schema) and `murk_get` (scoped
//! read) are always on and fail closed. `murk_exec` (run a command with scoped
//! secrets injected) is opt-in via `murk mcp --allow-exec` — off by default,
//! since command execution is a wider blast radius than a scoped read.

use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use murk_cli::types::{Murk, Vault};
use rmcp::{
    ErrorData as McpError, ServerHandler, ServiceExt,
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    model::{CallToolResult, ContentBlock, Implementation, ServerCapabilities, ServerConfig},
    tool, tool_handler, tool_router,
    transport::stdio,
};
use schemars::JsonSchema;
use serde::Deserialize;
use tokio::io::AsyncReadExt;
use tokio::process::{Child, Command as TokioCommand};

/// The decrypted, grant-scoped vault state the tools read from. Loaded once by
/// [`crate::cmd_mcp`] after the identity guard passes, then shared read-only for
/// the server's lifetime. Holds decrypted secret material (bounded to the grant),
/// so its lifetime is the connection's lifetime — the same tradeoff any
/// long-running secrets server makes.
pub struct McpState {
    pub vault: Vault,
    pub murk: Murk,
    /// The grant identity's public key — the reader `get_secret` resolves values
    /// for, and the subject of the agent-policy check.
    pub pubkey: String,
}

/// The murk MCP server handler. Cheap to clone — the state is behind an `Arc` and
/// the generated `#[tool_handler]` dispatch reads the router per request.
#[derive(Clone)]
pub struct MurkMcp {
    state: Arc<McpState>,
    tool_router: ToolRouter<Self>,
}

/// `murk_plan` arguments.
#[derive(Debug, Deserialize, JsonSchema)]
struct PlanRequest {
    /// Optional tag filter. When non-empty, only keys carrying at least one of
    /// these tags are listed; omitted or empty lists the whole schema.
    #[serde(default)]
    tags: Vec<String>,
}

/// `murk_get` arguments.
#[derive(Debug, Deserialize, JsonSchema)]
struct GetRequest {
    /// The secret key name to read. Must be within this grant's scope and
    /// permitted by the vault's agent policy, or the call fails closed.
    key: String,
}

/// `murk_exec` arguments.
#[derive(Debug, Deserialize, JsonSchema)]
struct ExecRequest {
    /// Secret keys to inject into the command's environment. Each must be within
    /// this grant's scope and allowed by the agent policy, or the call fails
    /// closed. Must name at least one key.
    only: Vec<String>,
    /// The command to run: `command[0]` is the program, the rest are arguments
    /// (e.g. `["npm", "test"]`). Runs with no shell — there is no shell
    /// interpolation — and a cleaned environment plus the injected secrets.
    command: Vec<String>,
}

#[tool_router]
impl MurkMcp {
    fn new(state: Arc<McpState>, allow_exec: bool) -> Self {
        let mut tool_router = Self::tool_router();
        // murk_exec is opt-in: unless the operator launched with --allow-exec,
        // drop it entirely so it never appears in tools/list or accepts a call.
        if !allow_exec {
            tool_router.remove_route("murk_exec");
        }
        Self { state, tool_router }
    }

    /// The secret *schema* for keys this grant may read — key names, descriptions,
    /// examples, tags — with no secret values. Bounded to the grant: only keys the
    /// grant can actually read *and* that the agent policy allows appear, so a
    /// scoped agent cannot enumerate out-of-scope key names or metadata.
    #[tool(
        description = "List the schema (key names, descriptions, examples, tags) of the secrets this grant may read, as JSON. Bounded to the grant's scope; never returns secret values."
    )]
    async fn murk_plan(
        &self,
        Parameters(PlanRequest { tags }): Parameters<PlanRequest>,
    ) -> Result<CallToolResult, McpError> {
        let st = &self.state;
        let mut plan = murk_cli::agent_plan(&st.vault, &tags);
        // Bound the plan to exactly the set murk_get would serve: keys allowed by
        // the agent policy AND readable under this grant. Without this a one-key
        // grant could enumerate every key's name/description/example/tags.
        plan.entries.retain(|e| {
            murk_cli::is_agent_key_allowed(&st.vault, &e.key)
                && murk_cli::get_secret(&st.murk, &e.key, &st.pubkey).is_some()
        });
        match serde_json::to_string_pretty(&plan) {
            Ok(json) => Ok(CallToolResult::success(vec![ContentBlock::text(json)])),
            Err(e) => Ok(CallToolResult::error(vec![ContentBlock::text(format!(
                "failed to render plan: {e}"
            ))])),
        }
    }

    /// Read one secret value by key. Fails closed: a key forbidden by the vault's
    /// agent policy, or outside this grant's scope, returns an error result —
    /// never the value.
    #[tool(
        description = "Read a single secret value by key. Fails closed: keys forbidden by the vault's agent policy or outside this grant's scope return an error, never the value."
    )]
    async fn murk_get(
        &self,
        Parameters(GetRequest { key }): Parameters<GetRequest>,
    ) -> Result<CallToolResult, McpError> {
        let st = &self.state;

        // Defense-in-depth policy gate: apply the vault's agent allow-tag policy
        // at read time (the cryptographic bound is the grant recipient set; this
        // refuses a forbidden key even if an old scoped ciphertext lingers).
        if let Err(e) = murk_cli::enforce_agent_policy(
            &st.vault,
            &st.murk,
            &st.pubkey,
            std::slice::from_ref(&key),
        ) {
            return Ok(CallToolResult::error(vec![ContentBlock::text(
                e.to_string(),
            )]));
        }

        match murk_cli::get_secret(&st.murk, &key, &st.pubkey) {
            Some(value) => Ok(CallToolResult::success(vec![ContentBlock::text(
                value.to_string(),
            )])),
            None => Ok(CallToolResult::error(vec![ContentBlock::text(format!(
                "{key}: not found or outside this grant's scope"
            ))])),
        }
    }

    /// Run a command with the named secrets injected into its environment and
    /// return the captured output, with every injected value masked as
    /// `***KEY***`. Opt-in via `murk mcp --allow-exec`. Fails closed: every
    /// requested key must be in this grant's scope and allowed by the agent
    /// policy. No shell, a cleaned environment, and bounded output + runtime.
    #[tool(
        description = "Run a command with scoped secrets injected into its environment (no shell), returning captured stdout/stderr and the exit code as JSON. Injected values in the output are replaced with ***KEY*** (values under 4 bytes are not masked). Requires `only` (keys to inject) and `command` (argv). Fails closed on any key outside this grant's scope or the agent policy."
    )]
    async fn murk_exec(
        &self,
        Parameters(ExecRequest { only, command }): Parameters<ExecRequest>,
    ) -> Result<CallToolResult, McpError> {
        let st = &self.state;
        if command.is_empty() {
            return Ok(tool_err("command must not be empty"));
        }
        if only.is_empty() {
            return Ok(tool_err(
                "only must name at least one key — murk_exec never runs with an unscoped environment",
            ));
        }
        // Policy gate for every requested key (retroactive allow-tag enforcement).
        if let Err(e) = murk_cli::enforce_agent_policy(&st.vault, &st.murk, &st.pubkey, &only) {
            return Ok(tool_err(&e.to_string()));
        }
        // Resolve each key under the grant; fail closed on anything out of scope.
        let mut secrets: Vec<(String, String)> = Vec::with_capacity(only.len());
        for key in &only {
            let Some(value) = murk_cli::get_secret(&st.murk, key, &st.pubkey) else {
                return Ok(tool_err(&format!(
                    "{key}: not found or outside this grant's scope"
                )));
            };
            // A NUL in the key or value, or an `=` in the key, makes std's
            // `Command::env` panic. Secret values are arbitrary bytes, so validate
            // before injecting and fail the call rather than crash the server.
            // (Vault key names are already `[A-Za-z0-9_]`; the key check is
            // defense in depth.)
            if key.is_empty() || key.contains(['=', '\0']) {
                return Ok(tool_err(&format!(
                    "{key}: not a valid environment variable name"
                )));
            }
            // An agent must never be handed a vault-chosen PATH, LD_PRELOAD,
            // GIT_SSH_COMMAND or MURK_STRICT; there is no override here.
            if murk_cli::is_reserved_env_name(key) {
                return Ok(tool_err(&format!(
                    "{key}: reserved environment name (it changes how programs, shells or murk run) — murk_exec never injects it"
                )));
            }
            if value.contains('\0') {
                return Ok(tool_err(&format!(
                    "{key}: value contains a NUL byte and cannot be injected as an environment variable"
                )));
            }
            secrets.push((key.clone(), value.to_string()));
        }
        run_command(&command, &secrets).await
    }
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for MurkMcp {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new("murk-mcp", env!("CARGO_PKG_VERSION")))
            .with_instructions(
                "murk secrets for AI agents, bounded to this grant's scope. Use murk_plan \
                 for the value-free schema and murk_get to read an in-scope key; both fail \
                 closed on anything outside the grant."
                    .to_string(),
            )
    }
}

/// Serve the MCP stdio server until the client disconnects (stdin EOF).
///
/// tokio is confined here via `#[tokio::main]`; the caller stays synchronous.
/// All logging is routed to stderr — stdout carries the JSON-RPC stream.
#[tokio::main]
pub async fn serve(state: McpState, allow_exec: bool) -> Result<(), Box<dyn std::error::Error>> {
    init_tracing();
    tracing::info!("murk mcp: serving over stdio");

    let service = MurkMcp::new(Arc::new(state), allow_exec)
        .serve(stdio())
        .await
        .inspect_err(|e| tracing::error!("murk mcp: failed to start: {e:?}"))?;

    service.waiting().await?;
    tracing::info!("murk mcp: client disconnected, shutting down");
    Ok(())
}

/// Install a stderr-only `tracing` subscriber. stdout is reserved for the
/// JSON-RPC transport, so log output must never land there. Best-effort: a
/// second call (or a subscriber already installed by a harness) is a no-op
/// rather than a panic.
fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_target(false)
        .try_init();
}

/// Timeout for a `murk_exec` command; a slow or hung child is killed at this bound.
const EXEC_TIMEOUT: Duration = Duration::from_secs(120);
/// Per-stream output cap (stdout and stderr each). Bounds memory — a child that
/// writes past this is killed rather than buffered without limit.
const OUTPUT_CAP: usize = 1 << 20; // 1 MiB

/// A tool-level error result (`isError=true`) carrying a caller-visible message.
fn tool_err(msg: &str) -> CallToolResult {
    CallToolResult::error(vec![ContentBlock::text(msg.to_string())])
}

/// Read up to `cap` bytes from `r` (plus one, to detect overflow). Returns the
/// bytes truncated to `cap` and whether the stream exceeded it.
async fn read_capped<R: tokio::io::AsyncRead + Unpin>(
    r: R,
    cap: usize,
) -> std::io::Result<(Vec<u8>, bool)> {
    let mut buf = Vec::new();
    r.take(cap as u64 + 1).read_to_end(&mut buf).await?;
    let over = buf.len() > cap;
    buf.truncate(cap);
    Ok((buf, over))
}

/// A spawned `murk_exec` child that dies together with its whole process tree.
///
/// `Child::start_kill` and `kill_on_drop` signal only the direct child, so a
/// backgrounded grandchild (`sh -c '(sleep 300 &)'`) would outlive the call with
/// the injected secrets still in its environment. On unix the child is spawned as
/// the leader of a new process group (`process_group(0)`, so pgid == pid) and
/// [`ExecChild::kill`] SIGKILLs that whole group. Dropping the guard before the
/// child is reaped (an early return, or the request future being cancelled) does
/// the same. A descendant that calls `setsid`/`setpgid` leaves the group and
/// escapes; this is cleanup, not a sandbox.
struct ExecChild {
    inner: Child,
}

impl ExecChild {
    /// SIGKILL the child and, on unix, every process in its group. Once the
    /// child has been reaped this is a no-op: its pid (the pgid) may be recycled
    /// by then, so signalling it could hit an unrelated process.
    fn kill(&mut self) {
        #[cfg(unix)]
        {
            let pgid = self
                .inner
                .id()
                .and_then(|pid| libc::pid_t::try_from(pid).ok())
                .filter(|pid| *pid > 1);
            if let Some(pgid) = pgid {
                // SAFETY: killpg takes two integers and touches no memory. The
                // child is unreaped (`id()` is `Some`), so `pgid` is its own live
                // or zombie pid and cannot name an unrelated group; the group
                // leader's pid is reserved until reaped. An error (group already
                // gone) is irrelevant.
                unsafe {
                    libc::killpg(pgid, libc::SIGKILL);
                }
            }
        }
        let _ = self.inner.start_kill();
    }
}

impl Drop for ExecChild {
    fn drop(&mut self) {
        self.kill();
    }
}

/// [`run_command_within`] under the production [`EXEC_TIMEOUT`].
async fn run_command(
    command: &[String],
    secrets: &[(String, String)],
) -> Result<CallToolResult, McpError> {
    run_command_within(command, secrets, EXEC_TIMEOUT).await
}

/// Spawn `command` with a cleaned environment plus `secrets`, capturing stdout/
/// stderr under [`OUTPUT_CAP`] and `timeout`. stdin is null and both output
/// streams are piped, so the child never touches the server's JSON-RPC channel. A
/// stream past the cap, or a run past the timeout, kills the child and its
/// process group. The timeout bounds the whole call: the child's exit is awaited
/// under the same deadline as the output, so a child that closes its pipes and
/// keeps running is still killed on time.
async fn run_command_within(
    command: &[String],
    secrets: &[(String, String)],
    timeout: Duration,
) -> Result<CallToolResult, McpError> {
    let mut cmd = TokioCommand::new(&command[0]);
    cmd.args(&command[1..]);
    cmd.env_clear();
    // Preserve the minimum a subprocess needs, matching `murk exec --clean-env`.
    #[cfg(windows)]
    let preserve: &[&str] = &[
        "PATH",
        "PATHEXT",
        "SystemRoot",
        "SystemDrive",
        "ComSpec",
        "WINDIR",
        "TEMP",
        "TMP",
        "APPDATA",
        "LOCALAPPDATA",
        "USERPROFILE",
        "HOMEDRIVE",
        "HOMEPATH",
    ];
    #[cfg(not(windows))]
    let preserve: &[&str] = &["PATH", "HOME", "TERM"];
    for var in preserve {
        if let Ok(val) = std::env::var(var) {
            cmd.env(var, val);
        }
    }
    // Mark the child as a strict agent context so a nested `murk` won't fall back
    // to a stored key. A safe default, not a sandbox (see docs/ai-agents.md).
    cmd.env("MURK_AGENT", "1");
    cmd.env("MURK_STRICT", "1");
    // The env block necessarily copies plaintext secret values into the child;
    // that copy is outside our control and is not zeroized (documented boundary).
    for (k, v) in secrets {
        cmd.env(k, v);
    }
    // The child must never inherit the server's stdio (stdin/stdout are the
    // JSON-RPC channel): null stdin, capture stdout/stderr.
    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    // A group of its own (pgid == child pid) lets the whole tree be killed; see
    // [`ExecChild`].
    #[cfg(unix)]
    cmd.process_group(0);

    let mut child = match cmd.spawn() {
        Ok(c) => ExecChild { inner: c },
        Err(e) => return Ok(tool_err(&format!("failed to run {}: {e}", command[0]))),
    };

    let so = child.inner.stdout.take().expect("stdout piped");
    let se = child.inner.stderr.take().expect("stderr piped");
    let out_fut = read_capped(so, OUTPUT_CAP);
    let err_fut = read_capped(se, OUTPUT_CAP);
    tokio::pin!(out_fut, err_fut);
    let deadline = tokio::time::Instant::now() + timeout;
    let expiry = tokio::time::sleep_until(deadline);
    tokio::pin!(expiry);

    let mut ob: Option<Vec<u8>> = None;
    let mut eb: Option<Vec<u8>> = None;
    let mut over_cap = false;
    let mut timed_out = false;

    // Drain both streams concurrently. If either exceeds the cap, kill the child
    // immediately (its other pipe then closes, so the paired read finishes fast)
    // rather than sitting blocked on a full pipe until the timeout.
    while ob.is_none() || eb.is_none() {
        tokio::select! {
            r = &mut out_fut, if ob.is_none() => {
                let (b, o) = match r {
                    Ok(v) => v,
                    Err(e) => return Ok(tool_err(&format!("reading stdout: {e}"))),
                };
                if o { over_cap = true; child.kill(); }
                ob = Some(b);
            }
            r = &mut err_fut, if eb.is_none() => {
                let (b, o) = match r {
                    Ok(v) => v,
                    Err(e) => return Ok(tool_err(&format!("reading stderr: {e}"))),
                };
                if o { over_cap = true; child.kill(); }
                eb = Some(b);
            }
            _ = &mut expiry => { timed_out = true; child.kill(); break; }
        }
    }

    // The pipes can close (or be closed by the child) long before the process
    // exits, so waiting for the exit needs the same deadline as the read loop.
    let mut status = None;
    if !timed_out {
        match tokio::time::timeout_at(deadline, child.inner.wait()).await {
            Ok(s) => status = s.ok(),
            Err(_) => {
                timed_out = true;
                child.kill();
            }
        }
    }

    if timed_out {
        // Reap the killed child; SIGKILL can't be caught, so this returns promptly.
        let _ = child.inner.wait().await;
        return Ok(tool_err(&format!(
            "command timed out after {}s and was killed",
            timeout.as_secs()
        )));
    }

    // Scrub the injected values before the output reaches the agent. An
    // accident guard (an `env` dump, a debug line), not a boundary: encoded,
    // partial, or file-written values get through. See `murk_cli::mask`.
    // Over the cap, both streams may end mid-value (one was cut, the other
    // killed), so a trailing possible value prefix is dropped too.
    let masker = murk_cli::mask::Masker::new(secrets.iter().map(|(k, v)| (k, v.as_bytes())));
    let scrub = |b: Option<Vec<u8>>| {
        let b = b.unwrap_or_default();
        let masked = if over_cap {
            masker.mask_truncated(&b)
        } else {
            masker.mask(&b)
        };
        String::from_utf8_lossy(&masked).into_owned()
    };
    let stdout = scrub(ob);
    let stderr = scrub(eb);
    let payload = serde_json::json!({
        "exit_code": status.and_then(|s| s.code()),
        "stdout": stdout,
        "stderr": stderr,
        "truncated": over_cap,
    });
    let text = serde_json::to_string_pretty(&payload).unwrap_or_else(|_| "{}".to_string());

    if status.is_some_and(|s| s.success()) && !over_cap {
        Ok(CallToolResult::success(vec![ContentBlock::text(text)]))
    } else {
        Ok(CallToolResult::error(vec![ContentBlock::text(text)]))
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::path::Path;
    use std::time::Instant;

    fn argv(script: &str) -> Vec<String> {
        vec!["sh".into(), "-c".into(), script.into()]
    }

    fn text_of(result: &CallToolResult) -> String {
        result
            .content
            .iter()
            .filter_map(ContentBlock::as_text)
            .map(|t| t.text.as_str())
            .collect()
    }

    /// Poll for the pid a script wrote to `path` (the file may exist but be empty
    /// until the shell finishes the redirect).
    async fn read_pid(path: &Path) -> libc::pid_t {
        for _ in 0..200 {
            if let Some(pid) = std::fs::read_to_string(path)
                .ok()
                .and_then(|s| s.trim().parse().ok())
            {
                return pid;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        panic!("script never wrote a pid to {}", path.display());
    }

    fn is_running(pid: libc::pid_t) -> bool {
        // SAFETY: signal 0 only probes for the process; no signal is sent.
        if unsafe { libc::kill(pid, 0) } != 0 {
            return false;
        }
        // kill(pid, 0) also succeeds for a zombie whose reaper is slow (or absent
        // in a container), so consult the process state. If `ps` is unavailable,
        // fall back to "running", the conservative answer for these assertions.
        let state = std::process::Command::new("ps")
            .args(["-o", "stat=", "-p", &pid.to_string()])
            .output()
            .ok()
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string());
        match state {
            Some(s) => !s.is_empty() && !s.starts_with('Z'),
            None => true,
        }
    }

    /// Assert `pid` is gone within a few seconds; SIGKILL the straggler first so a
    /// failing run doesn't leave a long `sleep` behind.
    async fn assert_dies(pid: libc::pid_t, what: &str) {
        for _ in 0..100 {
            if !is_running(pid) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        // SAFETY: plain SIGKILL to a pid this test spawned.
        unsafe { libc::kill(pid, libc::SIGKILL) };
        panic!("{what} (pid {pid}) survived");
    }

    #[tokio::test]
    async fn timeout_covers_a_child_that_closes_its_pipes_then_keeps_running() {
        let start = Instant::now();
        let res = run_command_within(
            &argv("exec >&- 2>&-; exec sleep 30"),
            &[],
            Duration::from_secs(1),
        )
        .await
        .unwrap();
        assert!(
            start.elapsed() < Duration::from_secs(15),
            "the wait for exit ignored the deadline: returned after {:?}",
            start.elapsed()
        );
        assert_eq!(res.is_error, Some(true), "{}", text_of(&res));
        assert!(
            text_of(&res).contains("timed out after 1s"),
            "{}",
            text_of(&res)
        );
    }

    #[tokio::test]
    async fn timeout_kills_a_backgrounded_grandchild() {
        let dir = tempfile::tempdir().unwrap();
        let pidfile = dir.path().join("pid");
        // The grandchild inherits the output pipes, so the read loop runs to the
        // deadline; the leader itself exits immediately.
        let script = format!(
            "sleep 300 & echo $! > '{}'; echo started",
            pidfile.display()
        );
        let res = run_command_within(&argv(&script), &[], Duration::from_secs(2))
            .await
            .unwrap();
        assert_eq!(res.is_error, Some(true), "{}", text_of(&res));
        assert!(text_of(&res).contains("timed out"), "{}", text_of(&res));
        assert_dies(read_pid(&pidfile).await, "backgrounded grandchild").await;
    }

    #[tokio::test]
    async fn output_cap_kills_a_backgrounded_grandchild() {
        let dir = tempfile::tempdir().unwrap();
        let pidfile = dir.path().join("pid");
        // Past the cap the call must finish by killing the tree. Were only the
        // leader killed, the grandchild would keep stderr open and the call would
        // run to the (here generous) deadline and report a timeout instead.
        let script = format!(
            "sleep 300 & echo $! > '{}'; head -c 2000000 /dev/zero",
            pidfile.display()
        );
        let res = run_command_within(&argv(&script), &[], Duration::from_secs(20))
            .await
            .unwrap();
        assert_eq!(res.is_error, Some(true), "{}", text_of(&res));
        assert!(
            text_of(&res).contains("\"truncated\": true"),
            "expected an over-cap result, got: {}",
            text_of(&res)
        );
        assert_dies(read_pid(&pidfile).await, "backgrounded grandchild").await;
    }

    #[tokio::test]
    async fn cancelling_the_call_kills_a_backgrounded_grandchild() {
        let dir = tempfile::tempdir().unwrap();
        let pidfile = dir.path().join("pid");
        let script = format!("sleep 300 & echo $! > '{}'; wait", pidfile.display());
        let call = tokio::spawn(async move {
            run_command_within(&argv(&script), &[], Duration::from_secs(120)).await
        });
        let pid = read_pid(&pidfile).await;
        // Dropping the in-flight call (a client cancelling the request) must
        // take the tree down with it.
        call.abort();
        let _ = call.await;
        assert_dies(pid, "backgrounded grandchild").await;
    }
}
