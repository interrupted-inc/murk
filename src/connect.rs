// SPDX-FileCopyrightText: murk contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Wiring `murk mcp` into AI-editor MCP client configs — the engine behind
//! `murk agent connect` / `murk agent disconnect`.
//!
//! Every client stores MCP servers in its own file with its own root key
//! (`mcpServers`, or `servers` for VS Code) and its own formatting, and those
//! files are frequently hand-edited and full of `//` comments. So we never
//! reserialize the whole document: we surgically upsert (or remove) only the
//! `murk` entry, leaving every other server, key, and comment byte-for-byte
//! intact. The only thing written into a config is a `MURK_KEY_FILE` *path* plus
//! `MURK_AGENT=1` and an empty `MURK_KEY` — never inline key material — so even a
//! committed config leaks nothing but a machine-local path. The empty `MURK_KEY`
//! masks one the client may pass down from its own environment: murk refuses
//! both variables set, and an empty one counts as unset.

use crate::error::MurkError;
use std::path::{Path, PathBuf};

/// The stdio server entry we write for `murk`.
pub(crate) struct ServerSpec {
    /// Extra args after `mcp` (e.g. `--allow-exec`).
    pub extra_args: Vec<String>,
    /// Absolute path to the grant key file (`MURK_KEY_FILE`).
    pub key_file: String,
    /// Whether to emit `"type": "stdio"` (VS Code's schema requires it).
    pub typed_stdio: bool,
}

/// JSON-escape and quote a string via serde_json, so paths with backslashes or
/// quotes (Windows, odd homedirs) are always valid JSON.
fn quote(s: &str) -> String {
    serde_json::to_string(s).unwrap_or_else(|_| format!("{s:?}"))
}

/// Render the `murk` server *value* object (`{ ... }`), inner lines indented at
/// `member_indent + unit`, closing brace aligned to `member_indent`.
fn render_value(spec: &ServerSpec, member_indent: &str, unit: &str) -> String {
    use std::fmt::Write as _;
    let i1 = format!("{member_indent}{unit}");
    let i2 = format!("{i1}{unit}");
    let mut args = vec![quote("mcp")];
    args.extend(spec.extra_args.iter().map(|a| quote(a)));

    let mut out = String::from("{\n");
    if spec.typed_stdio {
        let _ = writeln!(out, "{i1}\"type\": \"stdio\",");
    }
    let _ = writeln!(out, "{i1}\"command\": \"murk\",");
    let _ = writeln!(out, "{i1}\"args\": [{}],", args.join(", "));
    let _ = writeln!(out, "{i1}\"env\": {{");
    let _ = writeln!(out, "{i2}\"MURK_KEY_FILE\": {},", quote(&spec.key_file));
    let _ = writeln!(out, "{i2}\"MURK_KEY\": \"\",");
    let _ = writeln!(out, "{i2}\"MURK_AGENT\": \"1\"");
    let _ = writeln!(out, "{i1}}}");
    let _ = write!(out, "{member_indent}}}");
    out
}

/// Render a full `"name": { ... }` member at `member_indent`.
fn render_member(name: &str, spec: &ServerSpec, member_indent: &str, unit: &str) -> String {
    format!(
        "{member_indent}{}: {}",
        quote(name),
        render_value(spec, member_indent, unit)
    )
}

// ---- JSONC scanner (string- and comment-aware) -----------------------------

/// Skip whitespace and `//` / `/* */` comments from `i`; return the next
/// significant byte index.
fn skip_trivia(b: &[u8], mut i: usize) -> usize {
    loop {
        while i < b.len() && b[i].is_ascii_whitespace() {
            i += 1;
        }
        if i + 1 < b.len() && b[i] == b'/' && b[i + 1] == b'/' {
            i += 2;
            while i < b.len() && b[i] != b'\n' {
                i += 1;
            }
        } else if i + 1 < b.len() && b[i] == b'/' && b[i + 1] == b'*' {
            i += 2;
            while i + 1 < b.len() && !(b[i] == b'*' && b[i + 1] == b'/') {
                i += 1;
            }
            i = (i + 2).min(b.len());
        } else {
            return i;
        }
    }
}

/// Index just past a `"..."` string beginning at `i`.
fn scan_string_end(b: &[u8], i: usize) -> Option<usize> {
    let mut j = i + 1;
    while j < b.len() {
        match b[j] {
            b'\\' => j += 2,
            b'"' => return Some(j + 1),
            _ => j += 1,
        }
    }
    None
}

/// Index just past a `{...}` or `[...]` beginning at `i`.
fn scan_bracketed_end(b: &[u8], i: usize) -> Option<usize> {
    let open = b[i];
    let close = if open == b'{' { b'}' } else { b']' };
    let mut depth = 0i32;
    let mut j = i;
    while j < b.len() {
        match b[j] {
            b'"' => {
                j = scan_string_end(b, j)?;
            }
            b'/' if j + 1 < b.len() && (b[j + 1] == b'/' || b[j + 1] == b'*') => {
                j = skip_trivia(b, j);
            }
            c if c == open => {
                depth += 1;
                j += 1;
            }
            c if c == close => {
                depth -= 1;
                j += 1;
                if depth == 0 {
                    return Some(j);
                }
            }
            _ => j += 1,
        }
    }
    None
}

/// Index just past the JSON value starting at (or after trivia from) `i`.
fn scan_value_end(b: &[u8], i: usize) -> Option<usize> {
    let i = skip_trivia(b, i);
    if i >= b.len() {
        return None;
    }
    match b[i] {
        b'"' => scan_string_end(b, i),
        b'{' | b'[' => scan_bracketed_end(b, i),
        _ => {
            let mut j = i;
            while j < b.len()
                && !matches!(b[j], b',' | b'}' | b']')
                && !b[j].is_ascii_whitespace()
                && !(b[j] == b'/' && j + 1 < b.len() && (b[j + 1] == b'/' || b[j + 1] == b'*'))
            {
                j += 1;
            }
            (j > i).then_some(j)
        }
    }
}

/// A direct member of a JSON object.
struct Member {
    key: String,
    key_start: usize,
    value_end: usize,
}

/// Parse the direct members of the object whose opening `{` is at `open`.
/// Returns the closing `}` index and the members.
fn object_members(b: &[u8], open: usize) -> Option<(usize, Vec<Member>)> {
    let mut i = open + 1;
    let mut members = Vec::new();
    loop {
        i = skip_trivia(b, i);
        if i >= b.len() {
            return None;
        }
        if b[i] == b'}' {
            return Some((i, members));
        }
        if b[i] != b'"' {
            return None;
        }
        let key_start = i;
        let key_end = scan_string_end(b, i)?;
        let key = std::str::from_utf8(b.get(key_start + 1..key_end - 1)?)
            .ok()?
            .to_string();
        i = skip_trivia(b, key_end);
        if i >= b.len() || b[i] != b':' {
            return None;
        }
        let value_end = scan_value_end(b, i + 1)?;
        members.push(Member {
            key,
            key_start,
            value_end,
        });
        i = skip_trivia(b, value_end);
        if i < b.len() && b[i] == b',' {
            i += 1;
        }
    }
}

/// The opening `{` of the top-level object, if the document is one.
fn top_object_open(b: &[u8]) -> Option<usize> {
    let i = skip_trivia(b, 0);
    (i < b.len() && b[i] == b'{').then_some(i)
}

/// Detect the indent unit (first indentation run after a newline). Defaults to
/// two spaces.
fn detect_indent(text: &str) -> String {
    for line in text.lines() {
        let ws: String = line
            .chars()
            .take_while(|c| *c == ' ' || *c == '\t')
            .collect();
        if !ws.is_empty() && ws.len() < line.len() {
            return ws;
        }
    }
    "  ".to_string()
}

/// The indentation (leading whitespace) of the line containing byte `idx`.
fn line_indent(b: &[u8], idx: usize) -> String {
    let line_start = b[..idx]
        .iter()
        .rposition(|&c| c == b'\n')
        .map_or(0, |p| p + 1);
    let ws_end = b[line_start..idx]
        .iter()
        .position(|&c| c != b' ' && c != b'\t')
        .unwrap_or(idx - line_start);
    String::from_utf8_lossy(&b[line_start..line_start + ws_end]).into_owned()
}

/// Build a fresh document containing only the `murk` server under `root_key`.
fn fresh_document(root_key: &str, server: &str, spec: &ServerSpec, unit: &str) -> String {
    let member = render_member(server, spec, &unit.repeat(2), unit);
    format!(
        "{{\n{unit}{}: {{\n{member}\n{unit}}}\n}}\n",
        quote(root_key)
    )
}

/// Insert `server` as the first member of the object whose `{` is at `obj_open`.
/// `member_indent` is the indentation the new member should carry.
fn insert_first_member(
    text: &str,
    obj_open: usize,
    close: usize,
    empty: bool,
    server: &str,
    spec: &ServerSpec,
    member_indent: &str,
    unit: &str,
) -> String {
    let member = render_member(server, spec, member_indent, unit);
    let b = text.as_bytes();
    let after_open = obj_open + 1;
    let insertion = if empty {
        // Align the closing brace to its own line under the object's owner.
        let close_indent = line_indent(b, obj_open);
        format!("\n{member}\n{close_indent}")
    } else {
        format!("\n{member},")
    };
    let mut out = String::with_capacity(text.len() + insertion.len());
    out.push_str(&text[..after_open]);
    out.push_str(&insertion);
    if empty {
        // Skip the original whitespace between `{` and `}` — we rebuilt it.
        out.push_str(&text[close..]);
    } else {
        out.push_str(&text[after_open..]);
    }
    out
}

/// Upsert the `murk` server entry into `existing` (a client config) under
/// `root_key`, preserving all other content and comments. `None`/blank input
/// yields a fresh document.
pub(crate) fn upsert_json_server(
    existing: Option<&str>,
    root_key: &str,
    server: &str,
    spec: &ServerSpec,
) -> Result<String, MurkError> {
    let text = existing.unwrap_or("");
    if text.trim().is_empty() {
        return Ok(fresh_document(root_key, server, spec, "  "));
    }
    let unit = detect_indent(text);
    let b = text.as_bytes();
    let top = top_object_open(b)
        .ok_or_else(|| MurkError::Config("config is not a JSON object".into()))?;
    let (_top_close, top_members) = object_members(b, top)
        .ok_or_else(|| MurkError::Config("could not parse config JSON".into()))?;

    // Locate the root-key container (mcpServers / servers).
    let Some(root_member) = top_members.iter().find(|m| m.key == root_key) else {
        // No container yet: add one holding just murk, as the first top member.
        let member_indent = line_indent(b, top_members.first().map_or(top, |m| m.key_start));
        let inner = unit.repeat(2);
        let server_member = render_member(server, spec, &inner, &unit);
        let container = format!(
            "{}: {{\n{server_member}\n{member_indent}}}",
            quote(root_key)
        );
        let (top_close, _) = object_members(b, top).unwrap();
        return Ok(splice_top_member(
            text,
            top,
            top_close,
            top_members.is_empty(),
            &container,
            &member_indent,
        ));
    };

    // The container's value must be an object.
    // Re-find the container value's opening brace precisely.
    let colon = find_colon_after_key(b, root_member.key_start)
        .ok_or_else(|| MurkError::Config("malformed config member".into()))?;
    let cval_start = skip_trivia(b, colon + 1);
    if cval_start >= b.len() || b[cval_start] != b'{' {
        return Err(MurkError::Config(format!(
            "\"{root_key}\" is not an object in this config"
        )));
    }
    let (cclose, cmembers) = object_members(b, cval_start)
        .ok_or_else(|| MurkError::Config("could not parse server list".into()))?;

    if let Some(existing_server) = cmembers.iter().find(|m| m.key == server) {
        // Replace just murk's value span.
        let member_indent = line_indent(b, existing_server.key_start);
        let value = render_value(spec, &member_indent, &unit);
        let vstart = find_colon_after_key(b, existing_server.key_start)
            .map(|c| skip_trivia(b, c + 1))
            .ok_or_else(|| MurkError::Config("malformed murk entry".into()))?;
        let mut out = String::with_capacity(text.len());
        out.push_str(&text[..vstart]);
        out.push_str(&value);
        out.push_str(&text[existing_server.value_end..]);
        return Ok(out);
    }

    // Add murk as the first member of the existing container.
    let member_indent = if let Some(first) = cmembers.first() {
        line_indent(b, first.key_start)
    } else {
        format!("{}{}", line_indent(b, cval_start), unit)
    };
    Ok(insert_first_member(
        text,
        cval_start,
        cclose,
        cmembers.is_empty(),
        server,
        spec,
        &member_indent,
        &unit,
    ))
}

/// Splice a pre-rendered top-level member (`"key": {...}`) as the first member
/// of the top object.
fn splice_top_member(
    text: &str,
    top_open: usize,
    top_close: usize,
    empty: bool,
    member: &str,
    member_indent: &str,
) -> String {
    let after = top_open + 1;
    let insertion = if empty {
        let close_indent = line_indent(text.as_bytes(), top_open);
        format!("\n{member_indent}{member}\n{close_indent}")
    } else {
        format!("\n{member_indent}{member},")
    };
    let mut out = String::with_capacity(text.len() + insertion.len());
    out.push_str(&text[..after]);
    out.push_str(&insertion);
    if empty {
        out.push_str(&text[top_close..]);
    } else {
        out.push_str(&text[after..]);
    }
    out
}

/// Find the `:` after an object key that starts at `key_start`.
fn find_colon_after_key(b: &[u8], key_start: usize) -> Option<usize> {
    let key_end = scan_string_end(b, key_start)?;
    let i = skip_trivia(b, key_end);
    (i < b.len() && b[i] == b':').then_some(i)
}

/// Remove the `murk` server entry from `existing`. Returns `None` if there was
/// nothing to remove (no such entry), else the rewritten config.
// `Result` mirrors `upsert_json_server` and leaves room to reject malformed
// input later; today every failure path is a benign "nothing to remove".
#[allow(clippy::unnecessary_wraps)]
pub(crate) fn remove_json_server(
    existing: &str,
    root_key: &str,
    server: &str,
) -> Result<Option<String>, MurkError> {
    let b = existing.as_bytes();
    let Some(top) = top_object_open(b) else {
        return Ok(None);
    };
    let Some((_, top_members)) = object_members(b, top) else {
        return Ok(None);
    };
    let Some(root_member) = top_members.iter().find(|m| m.key == root_key) else {
        return Ok(None);
    };
    let Some(colon) = find_colon_after_key(b, root_member.key_start) else {
        return Ok(None);
    };
    let cval_start = skip_trivia(b, colon + 1);
    if cval_start >= b.len() || b[cval_start] != b'{' {
        return Ok(None);
    }
    let Some((_, cmembers)) = object_members(b, cval_start) else {
        return Ok(None);
    };
    let Some(idx) = cmembers.iter().position(|m| m.key == server) else {
        return Ok(None);
    };
    let target = &cmembers[idx];

    // Delete from the start of the member's line through its value, plus the
    // comma that binds it to a sibling (trailing if any, else the preceding one)
    // so the result stays valid JSON.
    let line_start = b[..target.key_start]
        .iter()
        .rposition(|&c| c == b'\n')
        .map_or(0, |p| p + 1);
    let mut del_start = line_start;
    let mut del_end = target.value_end;

    let after = skip_trivia(b, target.value_end);
    if after < b.len() && b[after] == b',' {
        // Has a following sibling: drop trailing comma and the blank line left.
        del_end = after + 1;
    } else {
        // Last member: drop the preceding comma instead.
        if let Some(prev_comma) = b[..line_start]
            .iter()
            .rposition(|&c| !c.is_ascii_whitespace())
            && b[prev_comma] == b','
        {
            del_start = prev_comma;
        }
    }
    // Trim a trailing newline so we don't leave a blank line behind.
    if del_end < b.len() && b[del_end] == b'\n' {
        del_end += 1;
    }

    let mut out = String::with_capacity(existing.len());
    out.push_str(&existing[..del_start]);
    out.push_str(&existing[del_end..]);
    Ok(Some(out))
}

// ---- Client adapters -------------------------------------------------------

/// The on-disk format of a client's MCP config.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum ConfigFormat {
    /// JSON/JSONC with a server-map object (Claude, Cursor, VS Code, Zed,
    /// Gemini, omp).
    Json,
    /// TOML with `[mcp_servers.<name>]` tables (Codex).
    Toml,
}

/// A supported MCP client: where its project-local config lives, the root key
/// its server map uses (or table namespace for TOML), whether an entry needs a
/// typed `"type": "stdio"`, the on-disk format, and a marker directory whose
/// presence signals the client is used in a project.
pub struct ClientAdapter {
    pub id: &'static str,
    pub display: &'static str,
    /// Project-local config path, relative to the repo root.
    pub rel_path: &'static str,
    /// Directory whose presence auto-detects the client (besides the config).
    pub marker_dir: &'static str,
    /// Root key holding the server map (`mcpServers`; `servers` for VS Code;
    /// `context_servers` for Zed) — or the table namespace (`mcp_servers`) for
    /// TOML clients.
    pub root_key: &'static str,
    /// VS Code requires an explicit `"type": "stdio"` on each server.
    pub typed_stdio: bool,
    /// On-disk config format.
    pub format: ConfigFormat,
}

/// Supported clients. Each writes a project-local config so a repo's grant
/// never leaks into a global, cross-repo config.
pub const ADAPTERS: &[ClientAdapter] = &[
    ClientAdapter {
        id: "claude",
        display: "Claude Code",
        rel_path: ".mcp.json",
        marker_dir: ".claude",
        root_key: "mcpServers",
        typed_stdio: false,
        format: ConfigFormat::Json,
    },
    ClientAdapter {
        id: "cursor",
        display: "Cursor",
        rel_path: ".cursor/mcp.json",
        marker_dir: ".cursor",
        root_key: "mcpServers",
        typed_stdio: false,
        format: ConfigFormat::Json,
    },
    ClientAdapter {
        id: "vscode",
        display: "VS Code",
        rel_path: ".vscode/mcp.json",
        marker_dir: ".vscode",
        root_key: "servers",
        typed_stdio: true,
        format: ConfigFormat::Json,
    },
    ClientAdapter {
        id: "zed",
        display: "Zed",
        rel_path: ".zed/settings.json",
        marker_dir: ".zed",
        root_key: "context_servers",
        typed_stdio: false,
        format: ConfigFormat::Json,
    },
    ClientAdapter {
        id: "gemini",
        display: "Gemini CLI",
        rel_path: ".gemini/settings.json",
        marker_dir: ".gemini",
        root_key: "mcpServers",
        typed_stdio: false,
        format: ConfigFormat::Json,
    },
    ClientAdapter {
        id: "omp",
        display: "omp",
        rel_path: ".omp/mcp.json",
        marker_dir: ".omp",
        root_key: "mcpServers",
        typed_stdio: false,
        format: ConfigFormat::Json,
    },
    ClientAdapter {
        id: "codex",
        display: "Codex",
        rel_path: ".codex/config.toml",
        marker_dir: ".codex",
        root_key: "mcp_servers",
        typed_stdio: false,
        format: ConfigFormat::Toml,
    },
];

/// Look up an adapter by id (case-insensitive).
pub fn adapter(id: &str) -> Option<&'static ClientAdapter> {
    ADAPTERS.iter().find(|a| a.id.eq_ignore_ascii_case(id))
}

/// Adapters whose config file or marker directory already exists under
/// `project_dir` — the clients this repo actually uses.
pub fn detect(project_dir: &Path) -> Vec<&'static ClientAdapter> {
    ADAPTERS
        .iter()
        .filter(|a| {
            project_dir.join(a.rel_path).exists() || project_dir.join(a.marker_dir).is_dir()
        })
        .collect()
}

impl ClientAdapter {
    /// The client's project-local config path under `project_dir`.
    pub(crate) fn config_path(&self, project_dir: &Path) -> PathBuf {
        project_dir.join(self.rel_path)
    }
}

/// Outcome of wiring one client.
pub struct ConnectOutcome {
    pub path: PathBuf,
    /// The config file was newly created (vs. an existing one updated).
    pub created: bool,
}

/// A config change rendered in memory but not yet written.
///
/// Planning every target first lets a caller fail on a malformed or unsafe
/// config *before* it takes an irreversible step (minting a grant), then write
/// all of them with [`ConfigEdit::apply`].
pub struct ConfigEdit {
    /// The config file this edit targets.
    pub path: PathBuf,
    /// The file does not exist yet — applying creates it.
    pub created: bool,
    project_dir: PathBuf,
    contents: String,
    /// The file as it was when planned (`None` if absent), for [`Self::undo`].
    original: Option<String>,
}

impl ConfigEdit {
    /// Write the rendered config atomically. The symlink guard runs again here:
    /// planning and writing can be separated by a vault write.
    pub fn apply(&self) -> Result<(), MurkError> {
        ensure_inside_project(&self.project_dir, &self.path)?;
        write_config(&self.path, &self.contents)
    }

    /// Put the file back as it was when planned: restore its old contents, or
    /// remove it if this edit created it. Used to roll back a partly applied
    /// connect. Refuses, touching nothing, if the file no longer holds what
    /// this edit wrote: someone changed it since, and that change wins.
    pub fn undo(&self) -> Result<(), MurkError> {
        ensure_inside_project(&self.project_dir, &self.path)?;
        match std::fs::read_to_string(&self.path) {
            Ok(now) if now == self.contents => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound && self.original.is_none() => {
                return Ok(());
            }
            _ => {
                return Err(MurkError::Config(format!(
                    "{} changed after murk wrote it — left as is; remove the murk entry by hand",
                    self.path.display()
                )));
            }
        }
        match &self.original {
            Some(original) => write_config(&self.path, original),
            None => std::fs::remove_file(&self.path).map_err(MurkError::Io),
        }
    }
}

/// Args `murk mcp` needs to open a non-default vault. The configured server
/// starts in the project directory — the one holding the config and the vault —
/// so the vault is named there by file name, exactly as the default `.murk` is
/// found. Empty for the default vault, which keeps its entry unchanged.
pub fn vault_args(vault_path: &str) -> Vec<String> {
    let name = Path::new(vault_path).file_name().map_or_else(
        || vault_path.to_string(),
        |n| n.to_string_lossy().into_owned(),
    );
    if name == crate::types::DEFAULT_VAULT_NAME {
        return Vec::new();
    }
    vec!["--vault".to_string(), name]
}

/// Render the `murk` server into `adapter`'s config under `project_dir`: only a
/// `MURK_KEY_FILE` path (`key_file`) + `MURK_AGENT=1` and any `extra_args` after
/// `mcp`. Preserves every other server and comment. Nothing is written until
/// [`ConfigEdit::apply`]; a malformed config or a symlinked path fails here.
pub fn plan_connect(
    adapter: &ClientAdapter,
    project_dir: &Path,
    key_file: &str,
    extra_args: &[String],
) -> Result<ConfigEdit, MurkError> {
    let path = adapter.config_path(project_dir);
    ensure_inside_project(project_dir, &path)?;
    let existing = match std::fs::read_to_string(&path) {
        Ok(s) => Some(s),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => return Err(MurkError::Io(e)),
    };
    let created = existing.is_none();
    let spec = ServerSpec {
        extra_args: extra_args.to_vec(),
        key_file: key_file.to_string(),
        typed_stdio: adapter.typed_stdio,
    };
    let contents = match adapter.format {
        ConfigFormat::Json => {
            upsert_json_server(existing.as_deref(), adapter.root_key, "murk", &spec)?
        }
        ConfigFormat::Toml => {
            upsert_toml_server(existing.as_deref(), adapter.root_key, "murk", &spec)?
        }
    };
    Ok(ConfigEdit {
        path,
        created,
        project_dir: project_dir.to_path_buf(),
        contents,
        original: existing,
    })
}

/// Upsert the `murk` server into `adapter`'s config under `project_dir` in one
/// step ([`plan_connect`] then [`ConfigEdit::apply`]). Atomic (temp+rename).
pub fn connect_client(
    adapter: &ClientAdapter,
    project_dir: &Path,
    key_file: &str,
    extra_args: &[String],
) -> Result<ConnectOutcome, MurkError> {
    let edit = plan_connect(adapter, project_dir, key_file, extra_args)?;
    edit.apply()?;
    Ok(ConnectOutcome {
        path: edit.path,
        created: edit.created,
    })
}

/// Render `adapter`'s config with the `murk` server removed. `None` when there
/// is no config or nothing to remove; nothing is written until
/// [`ConfigEdit::apply`].
pub fn plan_disconnect(
    adapter: &ClientAdapter,
    project_dir: &Path,
) -> Result<Option<ConfigEdit>, MurkError> {
    let path = adapter.config_path(project_dir);
    ensure_inside_project(project_dir, &path)?;
    let existing = match std::fs::read_to_string(&path) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(MurkError::Io(e)),
    };
    let removed = match adapter.format {
        ConfigFormat::Json => remove_json_server(&existing, adapter.root_key, "murk")?,
        ConfigFormat::Toml => remove_toml_server(&existing, adapter.root_key, "murk")?,
    };
    Ok(removed.map(|contents| ConfigEdit {
        path,
        created: false,
        project_dir: project_dir.to_path_buf(),
        contents,
        original: Some(existing),
    }))
}

/// Remove the `murk` server from `adapter`'s config. Returns the path when a
/// change was written, `None` when there was nothing to remove.
pub fn disconnect_client(
    adapter: &ClientAdapter,
    project_dir: &Path,
) -> Result<Option<PathBuf>, MurkError> {
    match plan_disconnect(adapter, project_dir)? {
        Some(edit) => {
            edit.apply()?;
            Ok(Some(edit.path))
        }
        None => Ok(None),
    }
}

/// Refuse a config path that is, or sits below, a symlink.
///
/// A repo can commit `.mcp.json` as a symlink to a file elsewhere on the
/// operator's machine (read it, merge into it, and the target's JSON lands in
/// the working tree), or `.cursor` as a link to a directory that makes murk
/// create config outside the project. So every component below `project_dir`
/// must be a real file or directory. `project_dir` itself is the operator's own
/// choice (the vault's directory) and may legitimately be reached via a link
/// (macOS `/tmp`).
fn ensure_inside_project(project_dir: &Path, path: &Path) -> Result<(), MurkError> {
    let rel = path.strip_prefix(project_dir).map_err(|_| {
        MurkError::Config(format!(
            "refusing {}: it is outside the project directory {}",
            path.display(),
            project_dir.display()
        ))
    })?;
    let parts: Vec<_> = rel.components().collect();
    let mut cur = project_dir.to_path_buf();
    // Deepest existing directory above the file: where a write would land.
    let mut parent = project_dir.to_path_buf();
    for (i, part) in parts.iter().enumerate() {
        cur.push(part);
        match std::fs::symlink_metadata(&cur) {
            Ok(meta) if meta.file_type().is_symlink() => {
                return Err(MurkError::Config(format!(
                    "refusing to touch {}: {} is a symlink — a client config must be a real file \
                     inside the project, not a link that redirects where murk reads and writes",
                    path.display(),
                    cur.display()
                )));
            }
            Ok(_) => {
                if i + 1 < parts.len() {
                    parent.clone_from(&cur);
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => break,
            Err(e) => return Err(MurkError::Io(e)),
        }
    }
    ensure_resolves_inside(project_dir, &parent)
}

/// Fail unless `dir` resolves (symlinks and all) to a place under `root`.
fn ensure_resolves_inside(root: &Path, dir: &Path) -> Result<(), MurkError> {
    let root = root.canonicalize().map_err(MurkError::Io)?;
    let dir_real = dir.canonicalize().map_err(MurkError::Io)?;
    if dir_real.starts_with(&root) {
        Ok(())
    } else {
        Err(MurkError::Config(format!(
            "refusing {}: it resolves to {}, outside the project directory {}",
            dir.display(),
            dir_real.display(),
            root.display()
        )))
    }
}

/// Atomic config write: create parent directories, then temp-file + rename so a
/// crash mid-write can never truncate an existing config.
fn write_config(path: &Path, contents: &str) -> Result<(), MurkError> {
    use std::io::Write;
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent).map_err(MurkError::Io)?;
    }
    let dir = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let mut tmp = tempfile::NamedTempFile::new_in(dir).map_err(MurkError::Io)?;
    tmp.write_all(contents.as_bytes()).map_err(MurkError::Io)?;
    tmp.as_file().sync_all().map_err(MurkError::Io)?;
    tmp.persist(path).map_err(|e| MurkError::Io(e.error))?;
    Ok(())
}

// ---- TOML writer (Codex config.toml) ---------------------------------------
//
// Codex stores MCP servers as `[mcp_servers.<name>]` tables (with a nested
// `[mcp_servers.<name>.env]` table). We edit surgically like the JSON writer:
// drop any existing murk tables, then append fresh ones, leaving every other
// table and comment untouched. `typed_stdio` doesn't apply (Codex has no typed
// server flag).

/// The dotted key path of a TOML table header line (`[a.b]` or `[[a.b]]`),
/// ignoring a trailing `# comment`. `None` for non-header lines.
fn toml_table_path(line: &str) -> Option<String> {
    let t = line.trim_start().strip_prefix('[')?;
    let t = t.strip_prefix('[').unwrap_or(t);
    let end = t.find(']')?;
    Some(t[..end].trim().to_string())
}

/// Line ranges `[start, end)` of every table under `<prefix>.<server>` (each
/// header plus its body, through the line before the next unrelated header).
fn murk_toml_sections(lines: &[&str], prefix: &str, server: &str) -> Vec<(usize, usize)> {
    let exact = format!("{prefix}.{server}");
    let nested = format!("{prefix}.{server}.");
    let owned = |p: &str| p == exact || p.starts_with(&nested);
    let mut ranges = Vec::new();
    let mut i = 0;
    while i < lines.len() {
        match toml_table_path(lines[i]) {
            Some(p) if owned(&p) => {
                let start = i;
                i += 1;
                while i < lines.len() {
                    match toml_table_path(lines[i]) {
                        Some(q) if !owned(&q) => break,
                        _ => i += 1,
                    }
                }
                ranges.push((start, i));
            }
            _ => i += 1,
        }
    }
    ranges
}

/// Render murk's `[prefix.server]` + `[prefix.server.env]` tables.
fn render_toml_member(prefix: &str, server: &str, spec: &ServerSpec) -> String {
    use std::fmt::Write as _;
    let mut args = vec![quote("mcp")];
    args.extend(spec.extra_args.iter().map(|a| quote(a)));
    let mut out = String::new();
    let _ = writeln!(out, "[{prefix}.{server}]");
    let _ = writeln!(out, "command = {}", quote("murk"));
    let _ = writeln!(out, "args = [{}]", args.join(", "));
    let _ = writeln!(out);
    let _ = writeln!(out, "[{prefix}.{server}.env]");
    let _ = writeln!(out, "MURK_KEY_FILE = {}", quote(&spec.key_file));
    let _ = writeln!(out, "MURK_KEY = {}", quote(""));
    let _ = writeln!(out, "MURK_AGENT = {}", quote("1"));
    out
}

/// Remove murk's tables from a TOML config. `None` when there was nothing to
/// remove; else the rewritten document.
#[allow(clippy::unnecessary_wraps)]
pub(crate) fn remove_toml_server(
    existing: &str,
    prefix: &str,
    server: &str,
) -> Result<Option<String>, MurkError> {
    let lines: Vec<&str> = existing.lines().collect();
    let sections = murk_toml_sections(&lines, prefix, server);
    if sections.is_empty() {
        return Ok(None);
    }
    let drop: std::collections::HashSet<usize> =
        sections.iter().flat_map(|(s, e)| *s..*e).collect();
    let mut kept: Vec<&str> = lines
        .iter()
        .enumerate()
        .filter(|(i, _)| !drop.contains(i))
        .map(|(_, l)| *l)
        .collect();
    while kept.last().is_some_and(|l| l.trim().is_empty()) {
        kept.pop();
    }
    let mut out = kept.join("\n");
    if !out.is_empty() {
        out.push('\n');
    }
    Ok(Some(out))
}

/// Upsert murk's tables into a TOML config, preserving all other tables and
/// comments. `None`/blank input yields a fresh document.
pub(crate) fn upsert_toml_server(
    existing: Option<&str>,
    prefix: &str,
    server: &str,
    spec: &ServerSpec,
) -> Result<String, MurkError> {
    let base = match existing {
        Some(s) if !s.trim().is_empty() => {
            if let Some(stripped) = remove_toml_server(s, prefix, server)? {
                stripped
            } else {
                let mut t = s.trim_end().to_string();
                t.push('\n');
                t
            }
        }
        _ => String::new(),
    };
    let block = render_toml_member(prefix, server, spec);
    if base.trim().is_empty() {
        return Ok(block);
    }
    Ok(format!("{base}\n{block}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec() -> ServerSpec {
        ServerSpec {
            extra_args: vec![],
            key_file: "/home/alice/.config/murk/agent-keys/abc-cursor".into(),
            typed_stdio: false,
        }
    }

    /// Strip `//` and `/* */` comments (string-aware) so a preserved-comment
    /// JSONC document can still be validated as JSON in tests.
    fn strip_comments(s: &str) -> String {
        let b = s.as_bytes();
        let mut out = Vec::with_capacity(b.len());
        let mut i = 0;
        while i < b.len() {
            if b[i] == b'"' {
                out.push(b[i]);
                i += 1;
                while i < b.len() {
                    out.push(b[i]);
                    if b[i] == b'\\' && i + 1 < b.len() {
                        out.push(b[i + 1]);
                        i += 2;
                        continue;
                    }
                    if b[i] == b'"' {
                        i += 1;
                        break;
                    }
                    i += 1;
                }
            } else if b[i] == b'/' && i + 1 < b.len() && b[i + 1] == b'/' {
                while i < b.len() && b[i] != b'\n' {
                    i += 1;
                }
            } else if b[i] == b'/' && i + 1 < b.len() && b[i + 1] == b'*' {
                i += 2;
                while i + 1 < b.len() && !(b[i] == b'*' && b[i + 1] == b'/') {
                    i += 1;
                }
                i += 2;
            } else {
                out.push(b[i]);
                i += 1;
            }
        }
        String::from_utf8(out).unwrap()
    }

    /// Parse writer output, tolerating preserved `//` and `/* */` comments.
    fn parse(s: &str) -> serde_json::Value {
        serde_json::from_str(&strip_comments(s)).expect("output must be valid JSON(C)")
    }

    #[test]
    fn fresh_creates_valid_document() {
        let out = upsert_json_server(None, "mcpServers", "murk", &spec()).unwrap();
        let v = parse(&out);
        assert_eq!(v["mcpServers"]["murk"]["command"], "murk");
        assert_eq!(v["mcpServers"]["murk"]["args"][0], "mcp");
        assert_eq!(v["mcpServers"]["murk"]["env"]["MURK_AGENT"], "1");
        assert_eq!(
            v["mcpServers"]["murk"]["env"]["MURK_KEY_FILE"],
            "/home/alice/.config/murk/agent-keys/abc-cursor"
        );
        // Masks a MURK_KEY the client passes down, which murk would otherwise
        // refuse alongside the grant's MURK_KEY_FILE.
        assert_eq!(v["mcpServers"]["murk"]["env"]["MURK_KEY"], "");
    }

    #[test]
    fn merge_preserves_other_servers_and_comments() {
        let existing = "{\n  // my servers\n  \"mcpServers\": {\n    \"other\": { \"command\": \"foo\" }\n  }\n}\n";
        let out = upsert_json_server(Some(existing), "mcpServers", "murk", &spec()).unwrap();
        assert!(out.contains("// my servers"), "comment must survive");
        let v = parse(&out);
        assert_eq!(v["mcpServers"]["other"]["command"], "foo");
        assert_eq!(v["mcpServers"]["murk"]["command"], "murk");
    }

    #[test]
    fn vscode_servers_root_and_typed_stdio() {
        let mut s = spec();
        s.typed_stdio = true;
        let out = upsert_json_server(None, "servers", "murk", &s).unwrap();
        let v = parse(&out);
        assert_eq!(v["servers"]["murk"]["type"], "stdio");
    }

    #[test]
    fn idempotent_update_replaces_value() {
        let out1 = upsert_json_server(None, "mcpServers", "murk", &spec()).unwrap();
        let mut s2 = spec();
        s2.extra_args = vec!["--allow-exec".into()];
        let out2 = upsert_json_server(Some(&out1), "mcpServers", "murk", &s2).unwrap();
        let v = parse(&out2);
        assert_eq!(v["mcpServers"]["murk"]["args"][1], "--allow-exec");
        // Exactly one murk *key* (the `command: "murk"` value also contains the word).
        assert_eq!(out2.matches("\"murk\":").count(), 1);
    }

    #[test]
    fn add_container_when_absent_preserves_siblings() {
        let existing = "{\n  \"other\": true\n}\n";
        let out = upsert_json_server(Some(existing), "mcpServers", "murk", &spec()).unwrap();
        let v = parse(&out);
        assert_eq!(v["other"], true);
        assert_eq!(v["mcpServers"]["murk"]["command"], "murk");
    }

    #[test]
    fn remove_leaves_other_servers_and_comments() {
        let existing = "{\n  // keep me\n  \"mcpServers\": {\n    \"murk\": { \"command\": \"murk\" },\n    \"other\": { \"command\": \"foo\" }\n  }\n}\n";
        let out = remove_json_server(existing, "mcpServers", "murk")
            .unwrap()
            .expect("should remove");
        assert!(out.contains("// keep me"));
        let v = parse(&out);
        assert!(v["mcpServers"]["murk"].is_null());
        assert_eq!(v["mcpServers"]["other"]["command"], "foo");
    }

    #[test]
    fn remove_last_member_yields_empty_container() {
        let existing = "{\n  \"mcpServers\": {\n    \"murk\": { \"command\": \"murk\" }\n  }\n}\n";
        let out = remove_json_server(existing, "mcpServers", "murk")
            .unwrap()
            .expect("should remove");
        let v = parse(&out);
        assert!(v["mcpServers"]["murk"].is_null());
        assert!(v["mcpServers"].is_object());
    }

    #[test]
    fn remove_absent_is_none() {
        let existing = "{\n  \"mcpServers\": {\n    \"other\": { \"command\": \"foo\" }\n  }\n}\n";
        assert!(
            remove_json_server(existing, "mcpServers", "murk")
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn detect_indent_reads_four_spaces() {
        assert_eq!(detect_indent("{\n    \"a\": 1\n}"), "    ");
        assert_eq!(detect_indent("{\n\t\"a\": 1\n}"), "\t");
    }

    #[test]
    fn detect_finds_marker_dirs() {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::create_dir_all(dir.path().join(".cursor")).unwrap();
        std::fs::create_dir_all(dir.path().join(".vscode")).unwrap();
        std::fs::create_dir_all(dir.path().join(".zed")).unwrap();
        std::fs::create_dir_all(dir.path().join(".codex")).unwrap();
        let ids: Vec<_> = detect(dir.path()).iter().map(|a| a.id).collect();
        assert!(ids.contains(&"cursor"));
        assert!(ids.contains(&"vscode"));
        assert!(ids.contains(&"zed"));
        assert!(ids.contains(&"codex"));
        assert!(
            !ids.contains(&"claude"),
            "no .claude dir or .mcp.json present"
        );
        assert!(!ids.contains(&"gemini"), "no .gemini marker present");
    }

    #[test]
    fn connect_then_disconnect_roundtrip() {
        let dir = tempfile::TempDir::new().unwrap();
        let a = adapter("cursor").unwrap();

        let outcome = connect_client(a, dir.path(), "/keys/abc-mcp", &[]).unwrap();
        assert!(outcome.created);
        let written = std::fs::read_to_string(&outcome.path).unwrap();
        let v: serde_json::Value = serde_json::from_str(&written).unwrap();
        assert_eq!(
            v["mcpServers"]["murk"]["env"]["MURK_KEY_FILE"],
            "/keys/abc-mcp"
        );
        assert_eq!(v["mcpServers"]["murk"]["env"]["MURK_AGENT"], "1");

        assert!(disconnect_client(a, dir.path()).unwrap().is_some());
        let after = std::fs::read_to_string(a.config_path(dir.path())).unwrap();
        let v2: serde_json::Value = serde_json::from_str(&after).unwrap();
        assert!(v2["mcpServers"]["murk"].is_null());

        // Disconnecting again is a no-op.
        assert!(disconnect_client(a, dir.path()).unwrap().is_none());
    }

    #[test]
    fn vscode_adapter_writes_typed_stdio_and_extra_args() {
        let dir = tempfile::TempDir::new().unwrap();
        let a = adapter("vscode").unwrap();
        connect_client(
            a,
            dir.path(),
            "/keys/abc-mcp",
            &["--allow-exec".to_string()],
        )
        .unwrap();
        let written = std::fs::read_to_string(a.config_path(dir.path())).unwrap();
        let v: serde_json::Value = serde_json::from_str(&written).unwrap();
        assert_eq!(v["servers"]["murk"]["type"], "stdio");
        assert_eq!(v["servers"]["murk"]["args"][0], "mcp");
        assert_eq!(v["servers"]["murk"]["args"][1], "--allow-exec");
    }

    #[test]
    fn zed_uses_context_servers_root_without_source() {
        let dir = tempfile::TempDir::new().unwrap();
        let a = adapter("zed").unwrap();
        connect_client(a, dir.path(), "/keys/abc-mcp", &[]).unwrap();
        let written = std::fs::read_to_string(a.config_path(dir.path())).unwrap();
        let v = parse(&written);
        assert_eq!(v["context_servers"]["murk"]["command"], "murk");
        assert_eq!(v["context_servers"]["murk"]["args"][0], "mcp");
        assert_eq!(
            v["context_servers"]["murk"]["env"]["MURK_KEY_FILE"],
            "/keys/abc-mcp"
        );
        // Current Zed (post m_2025_06_27 migration) takes a flat entry — no
        // `source` discriminator. Emitting one is not required and we don't.
        assert!(v["context_servers"]["murk"]["source"].is_null());
        assert!(!written.contains("\"source\""));
    }

    #[test]
    fn gemini_and_omp_use_mcpservers_root() {
        for id in ["gemini", "omp"] {
            let dir = tempfile::TempDir::new().unwrap();
            let a = adapter(id).unwrap();
            connect_client(a, dir.path(), "/keys/abc-mcp", &[]).unwrap();
            let v = parse(&std::fs::read_to_string(a.config_path(dir.path())).unwrap());
            assert_eq!(v["mcpServers"]["murk"]["command"], "murk", "adapter {id}");
            assert_eq!(v["mcpServers"]["murk"]["env"]["MURK_AGENT"], "1");
        }
    }

    // ---- TOML writer (Codex) ----

    fn toml_spec() -> ServerSpec {
        ServerSpec {
            extra_args: vec![],
            key_file: "/home/alice/.config/murk/agent-keys/abc-codex".into(),
            typed_stdio: false,
        }
    }

    #[test]
    fn toml_fresh_document_is_exact() {
        let out = upsert_toml_server(None, "mcp_servers", "murk", &toml_spec()).unwrap();
        assert_eq!(
            out,
            "[mcp_servers.murk]\n\
             command = \"murk\"\n\
             args = [\"mcp\"]\n\
             \n\
             [mcp_servers.murk.env]\n\
             MURK_KEY_FILE = \"/home/alice/.config/murk/agent-keys/abc-codex\"\n\
             MURK_KEY = \"\"\n\
             MURK_AGENT = \"1\"\n"
        );
    }

    #[test]
    fn toml_extra_args_land_after_mcp() {
        let mut s = toml_spec();
        s.extra_args = vec!["--allow-exec".into()];
        let out = upsert_toml_server(None, "mcp_servers", "murk", &s).unwrap();
        assert!(out.contains("args = [\"mcp\", \"--allow-exec\"]"));
    }

    #[test]
    fn toml_preserves_other_tables_and_comments() {
        let existing = "# my codex config\n\
                        model = \"o3\"\n\
                        \n\
                        [mcp_servers.other]\n\
                        command = \"foo\"\n\
                        args = [\"bar\"]\n";
        let out = upsert_toml_server(Some(existing), "mcp_servers", "murk", &toml_spec()).unwrap();
        assert!(out.contains("# my codex config"), "comment must survive");
        assert!(out.contains("model = \"o3\""), "top-level key must survive");
        assert!(
            out.contains("[mcp_servers.other]"),
            "sibling table must survive"
        );
        assert!(out.contains("command = \"foo\""));
        assert_eq!(out.matches("[mcp_servers.murk]").count(), 1);
        assert!(out.contains("[mcp_servers.murk.env]"));
    }

    #[test]
    fn toml_idempotent_upsert_keeps_one_section() {
        let out1 = upsert_toml_server(None, "mcp_servers", "murk", &toml_spec()).unwrap();
        let mut s2 = toml_spec();
        s2.extra_args = vec!["--allow-exec".into()];
        let out2 = upsert_toml_server(Some(&out1), "mcp_servers", "murk", &s2).unwrap();
        assert_eq!(out2.matches("[mcp_servers.murk]").count(), 1);
        assert_eq!(out2.matches("[mcp_servers.murk.env]").count(), 1);
        assert!(out2.contains("--allow-exec"), "update must apply new args");
    }

    #[test]
    fn toml_remove_leaves_siblings_and_comments() {
        let existing = "# keep me\n\
                        [mcp_servers.other]\n\
                        command = \"foo\"\n\
                        \n\
                        [mcp_servers.murk]\n\
                        command = \"murk\"\n\
                        args = [\"mcp\"]\n\
                        \n\
                        [mcp_servers.murk.env]\n\
                        MURK_AGENT = \"1\"\n";
        let out = remove_toml_server(existing, "mcp_servers", "murk")
            .unwrap()
            .expect("should remove");
        assert!(out.contains("# keep me"));
        assert!(out.contains("[mcp_servers.other]"));
        assert!(!out.contains("[mcp_servers.murk]"));
        assert!(!out.contains("[mcp_servers.murk.env]"));
    }

    #[test]
    fn toml_remove_absent_is_none() {
        let existing = "[mcp_servers.other]\ncommand = \"foo\"\n";
        assert!(
            remove_toml_server(existing, "mcp_servers", "murk")
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn codex_adapter_roundtrip() {
        let dir = tempfile::TempDir::new().unwrap();
        let a = adapter("codex").unwrap();
        assert_eq!(a.format, ConfigFormat::Toml);

        connect_client(a, dir.path(), "/keys/abc-codex", &[]).unwrap();
        let path = a.config_path(dir.path());
        assert!(path.ends_with(".codex/config.toml"));
        let written = std::fs::read_to_string(&path).unwrap();
        assert!(written.contains("[mcp_servers.murk]"));
        assert!(written.contains("MURK_KEY_FILE = \"/keys/abc-codex\""));
        assert!(!written.contains("AGE-SECRET-KEY"));

        assert!(disconnect_client(a, dir.path()).unwrap().is_some());
        let after = std::fs::read_to_string(&path).unwrap();
        assert!(!after.contains("[mcp_servers.murk]"));
        // Disconnecting again is a no-op.
        assert!(disconnect_client(a, dir.path()).unwrap().is_none());
    }

    #[test]
    fn disconnect_client_on_missing_config_is_none() {
        // No config file has ever been written: the read must fail with
        // `NotFound`, not any other error, so this is `Ok(None)`.
        let dir = tempfile::TempDir::new().unwrap();
        let a = adapter("cursor").unwrap();
        assert!(disconnect_client(a, dir.path()).unwrap().is_none());
    }

    // ---- Scanner unit tests (kill boundary/off-by-one mutants directly) ----

    #[test]
    fn skip_trivia_boundaries() {
        // Empty input: must not index past the end.
        assert_eq!(skip_trivia(b"", 0), 0);
        // Pure whitespace runs to end of input.
        assert_eq!(skip_trivia(b"   ", 0), 3);
        // Line comment with no trailing newline runs to EOF.
        assert_eq!(skip_trivia(b"//abc", 0), 5);
        // Line comment terminated by a newline, followed by content.
        assert_eq!(skip_trivia(b"// c\nx", 0), 5);
        // Unterminated block comment consumes to EOF (exercises the `.min`
        // clamp so it never runs past the buffer).
        assert_eq!(skip_trivia(b"/* unterminated", 0), 15);
        // Block comment containing a bare '/' that is not part of the closer:
        // distinguishes `&&` from `||` and `==` from `!=` in the closer check.
        assert_eq!(skip_trivia(b"/* a/b */x", 0), 9);
        // Whitespace, a line comment, and a block comment back to back.
        assert_eq!(skip_trivia(b"  // one\n/* two */  x", 0), 20);
        // A bare '/' that never forms a comment opener stops immediately.
        assert_eq!(skip_trivia(b"/x", 0), 0);
        // A single trailing '/' at the very end of the buffer: the length
        // check must be strict (`<`), not `<=`, or this indexes out of bounds.
        assert_eq!(skip_trivia(b"/", 0), 0);
        // A line comment whose body is empty (the newline immediately
        // follows `//`) followed by unrelated content with no further
        // newline: doubling the post-`//` index instead of adding 2 would
        // overshoot the newline entirely and swallow the trailing content.
        assert_eq!(skip_trivia(b"   //\nTAIL", 0), 6);
    }

    #[test]
    fn scan_string_end_boundaries() {
        assert_eq!(scan_string_end(b"\"\"", 0), Some(2));
        // Back-to-back escaped quotes: doubling `j` instead of adding 2 would
        // land on the wrong closing quote.
        assert_eq!(scan_string_end(b"\"\\\"\\\"x\"", 0), Some(7));
        // Unterminated string must not index past the end.
        assert_eq!(scan_string_end(b"\"ab", 0), None);
    }

    #[test]
    fn scan_bracketed_end_boundaries() {
        assert_eq!(scan_bracketed_end(b"{}", 0), Some(2));
        assert_eq!(scan_bracketed_end(b"{\"a\":{\"b\":1}}", 0), Some(13));
        // A brace inside a string must not be counted as real nesting.
        assert_eq!(scan_bracketed_end(b"{\"a\":\"}\"}", 0), Some(9));
        // A brace inside a `//` comment must not be counted either.
        assert_eq!(scan_bracketed_end(b"{ // }\n}", 0), Some(8));
        assert_eq!(scan_bracketed_end(b"[1,2,[3]]", 0), Some(9));
        // A `/` at the very end of the buffer (unterminated, no closer):
        // the length check guarding the comment-opener lookahead must be
        // strict, or this indexes out of bounds.
        assert_eq!(scan_bracketed_end(b"{/", 0), None);
        // A bare '/' that is not a comment opener is ordinary content.
        assert_eq!(scan_bracketed_end(b"{/x}", 0), Some(4));
        // A block comment with nothing in its body.
        assert_eq!(scan_bracketed_end(b"{/**/}", 0), Some(6));
        // A line comment with an empty body, terminated by the newline.
        assert_eq!(scan_bracketed_end(b"{//\n}", 0), Some(5));
        assert_eq!(scan_bracketed_end(b"{\"a\":1", 0), None);
    }

    #[test]
    fn scan_value_end_boundaries() {
        assert_eq!(scan_value_end(b"\"abc\",", 0), Some(5));
        assert_eq!(scan_value_end(b"123,", 0), Some(3));
        assert_eq!(scan_value_end(b"123", 0), Some(3));
        assert_eq!(scan_value_end(b"{\"a\":1},", 0), Some(7));
        assert_eq!(scan_value_end(b"[1,2],", 0), Some(5));
        // A bare-word value followed directly by a comment (no separating
        // whitespace) must stop at the comment, not swallow it.
        assert_eq!(scan_value_end(b"true// c", 0), Some(4));
        // Leading whitespace/newlines before the value are skipped first.
        assert_eq!(scan_value_end(b"  \n  42,", 0), Some(7));
        // A bare-word value directly followed by a block comment opener.
        assert_eq!(scan_value_end(b"x/y", 0), Some(3));
        // A value that is nothing but the delimiter itself has zero length
        // and must be rejected (`j > i`, not `j >= i`).
        assert_eq!(scan_value_end(b",", 0), None);
        // A string value containing a comma must not be truncated at it —
        // the `"` match arm must dispatch to the real string scanner.
        assert_eq!(scan_value_end(b"\"a,b\",", 0), Some(5));
    }

    #[test]
    fn object_members_boundaries() {
        // Exact key text and value-end offsets, including a nested object.
        let b = b"{\"ab\":1,\"c\":{\"d\":2}}";
        let (close, members) = object_members(b, 0).unwrap();
        assert_eq!(close, 19);
        assert_eq!(members.len(), 2);
        assert_eq!(members[0].key, "ab");
        assert_eq!(members[0].key_start, 1);
        assert_eq!(members[0].value_end, 7);
        assert_eq!(members[1].key, "c");
        assert_eq!(members[1].key_start, 8);
        assert_eq!(members[1].value_end, 19);

        // An empty object has no members and closes right after `{`.
        assert_eq!(object_members(b"{}", 0).unwrap().1.len(), 0);
        // Unterminated object body.
        assert!(object_members(b"{\"a\":1", 0).is_none());
        // A non-string key is malformed.
        assert!(object_members(b"{a:1}", 0).is_none());
        // A member missing its `:` is malformed.
        assert!(object_members(b"{\"a\" 1}", 0).is_none());
        // A key that runs to exactly the end of the buffer with no `:`
        // after it: the length check must short-circuit before indexing.
        assert!(object_members(b"{\"a\"", 0).is_none());
    }

    #[test]
    fn top_object_open_boundaries() {
        assert_eq!(top_object_open(b""), None);
        assert_eq!(top_object_open(b"   "), None);
        assert_eq!(top_object_open(b"[]"), None);
        assert_eq!(top_object_open(b"  {}"), Some(2));
    }

    #[test]
    fn detect_indent_skips_blank_lines() {
        // A whitespace-only line has no content, so its "indent" must not be
        // reported: `ws.len() < line.len()` must be strict.
        assert_eq!(detect_indent("   \n    x"), "    ");
    }

    #[test]
    fn line_indent_boundaries() {
        // No preceding newline: indent is measured from buffer start.
        assert_eq!(line_indent(b"abc", 0), "");
        // Indent stops at the first non-space/tab byte, even mid-line.
        assert_eq!(line_indent(b"  x   k", 6), "  ");
        // Tab indentation on a non-first line.
        assert_eq!(line_indent(b"\n\tkey", 2), "\t");
        // Whitespace-only line ending exactly at `idx == b.len()` exercises
        // the `unwrap_or(idx - line_start)` fallback with a non-zero
        // `line_start`.
        assert_eq!(line_indent(b"x\n   ", 5), "   ");
    }

    #[test]
    fn find_colon_after_key_boundaries() {
        assert_eq!(find_colon_after_key(b"\"k\":1", 0), Some(3));
        // Key with no colon at all, ending exactly at the buffer boundary.
        assert_eq!(find_colon_after_key(b"\"k\"", 0), None);
        // Key followed by trivia then a non-colon byte.
        assert_eq!(find_colon_after_key(b"\"k\" x", 0), None);
    }

    #[test]
    fn remove_json_server_exact_splice_with_trailing_sibling() {
        let existing = "{\n  // keep me\n  \"mcpServers\": {\n    \"murk\": { \"command\": \"murk\" },\n    \"other\": { \"command\": \"foo\" }\n  }\n}\n";
        let out = remove_json_server(existing, "mcpServers", "murk")
            .unwrap()
            .unwrap();
        assert_eq!(
            out,
            "{\n  // keep me\n  \"mcpServers\": {\n    \"other\": { \"command\": \"foo\" }\n  }\n}\n"
        );
    }

    #[test]
    fn remove_json_server_non_object_container_is_none() {
        let existing = "{\"mcpServers\": \"nope\"}";
        assert!(
            remove_json_server(existing, "mcpServers", "murk")
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn remove_json_server_exact_splice_with_leading_sibling() {
        // Removing the *last* member exercises the preceding-comma trim path
        // (as opposed to the trailing-comma path above).
        let existing = "{\n  \"mcpServers\": {\n    \"other\": { \"command\": \"foo\" },\n    \"murk\": { \"command\": \"murk\" }\n  }\n}\n";
        let out = remove_json_server(existing, "mcpServers", "murk")
            .unwrap()
            .unwrap();
        assert_eq!(
            out,
            "{\n  \"mcpServers\": {\n    \"other\": { \"command\": \"foo\" }  }\n}\n"
        );
    }

    #[test]
    fn upsert_json_server_rejects_non_object_container() {
        let existing = "{\"mcpServers\": \"nope\"}";
        let err = upsert_json_server(Some(existing), "mcpServers", "murk", &spec())
            .unwrap_err()
            .to_string();
        assert!(err.contains("is not an object"), "unexpected error: {err}");
    }

    #[test]
    fn murk_toml_sections_exact_range_stops_before_unrelated_table() {
        let lines = [
            "# c",
            "[mcp_servers.other]",
            "command = \"foo\"",
            "",
            "[mcp_servers.murk]",
            "command = \"murk\"",
            "args = [\"mcp\"]",
            "",
            "[mcp_servers.murk.env]",
            "MURK_AGENT = \"1\"",
            "[mcp_servers.zzz]",
            "command = \"zzz\"",
        ];
        assert_eq!(
            murk_toml_sections(&lines, "mcp_servers", "murk"),
            vec![(4, 10)]
        );
    }

    #[test]
    fn toml_remove_only_content_yields_empty_string() {
        let existing = "[mcp_servers.murk]\ncommand = \"murk\"\n\n[mcp_servers.murk.env]\nMURK_AGENT = \"1\"\n";
        let out = remove_toml_server(existing, "mcp_servers", "murk")
            .unwrap()
            .unwrap();
        assert_eq!(out, "");
    }

    #[test]
    fn connect_client_propagates_read_errors_other_than_not_found() {
        // `config_path` resolving to a directory instead of a file produces
        // an I/O error whose kind is not `NotFound`; that must still be
        // reported as an error, not silently treated as "no existing config".
        let dir = tempfile::TempDir::new().unwrap();
        let a = adapter("cursor").unwrap();
        std::fs::create_dir_all(a.config_path(dir.path())).unwrap();
        assert!(connect_client(a, dir.path(), "/keys/abc-mcp", &[]).is_err());
    }

    #[test]
    fn disconnect_client_propagates_read_errors_other_than_not_found() {
        let dir = tempfile::TempDir::new().unwrap();
        let a = adapter("cursor").unwrap();
        std::fs::create_dir_all(a.config_path(dir.path())).unwrap();
        assert!(disconnect_client(a, dir.path()).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn connect_client_not_found_guard_is_specific_to_not_found() {
        // An unreadable-but-writable existing file (mode 000) fails to read
        // with `PermissionDenied`, not `NotFound`. The guard must not treat
        // it as "no existing config" and silently overwrite it.
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::TempDir::new().unwrap();
        let a = adapter("cursor").unwrap();
        let path = a.config_path(dir.path());
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, "{}").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000)).unwrap();
        let result = connect_client(a, dir.path(), "/keys/abc-mcp", &[]);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(result.is_err(), "unreadable config must not be overwritten");
    }

    #[cfg(unix)]
    #[test]
    fn disconnect_client_not_found_guard_is_specific_to_not_found() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::TempDir::new().unwrap();
        let a = adapter("cursor").unwrap();
        let path = a.config_path(dir.path());
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, "{}").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000)).unwrap();
        let result = disconnect_client(a, dir.path());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(
            result.is_err(),
            "unreadable config must not be treated as absent"
        );
    }

    // ---- Planning, symlink guard, vault args ----

    #[test]
    fn undo_restores_what_was_there_before() {
        let dir = tempfile::TempDir::new().unwrap();
        let a = adapter("claude").unwrap();
        let path = a.config_path(dir.path());
        std::fs::write(&path, "{}\n").unwrap();
        let edit = plan_connect(a, dir.path(), "/keys/abc-mcp", &[]).unwrap();
        edit.apply().unwrap();
        edit.undo().unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "{}\n");
    }

    #[test]
    fn undo_leaves_a_file_changed_after_the_write_alone() {
        let dir = tempfile::TempDir::new().unwrap();
        let a = adapter("claude").unwrap();
        let path = a.config_path(dir.path());
        let edit = plan_connect(a, dir.path(), "/keys/abc-mcp", &[]).unwrap();
        edit.apply().unwrap();
        std::fs::write(&path, "{\"edited\":true}\n").unwrap();
        assert!(edit.undo().is_err());
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "{\"edited\":true}\n"
        );
    }

    #[test]
    fn plan_connect_renders_without_writing() {
        let dir = tempfile::TempDir::new().unwrap();
        let a = adapter("cursor").unwrap();
        let edit = plan_connect(a, dir.path(), "/keys/abc-mcp", &[]).unwrap();
        assert!(edit.created);
        assert!(
            !dir.path().join(".cursor").exists(),
            "planning must not touch the filesystem"
        );
        edit.apply().unwrap();
        let v = parse(&std::fs::read_to_string(&edit.path).unwrap());
        assert_eq!(
            v["mcpServers"]["murk"]["env"]["MURK_KEY_FILE"],
            "/keys/abc-mcp"
        );
    }

    #[test]
    fn plan_connect_rejects_malformed_config_without_writing() {
        let dir = tempfile::TempDir::new().unwrap();
        let a = adapter("claude").unwrap();
        let path = a.config_path(dir.path());
        std::fs::write(&path, "{not json").unwrap();
        assert!(plan_connect(a, dir.path(), "/keys/abc-mcp", &[]).is_err());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "{not json");
    }

    #[test]
    fn plan_disconnect_renders_without_writing() {
        let dir = tempfile::TempDir::new().unwrap();
        let a = adapter("claude").unwrap();
        connect_client(a, dir.path(), "/keys/abc-mcp", &[]).unwrap();
        let path = a.config_path(dir.path());
        let before = std::fs::read_to_string(&path).unwrap();
        let edit = plan_disconnect(a, dir.path()).unwrap().unwrap();
        assert!(!edit.created);
        assert_eq!(std::fs::read_to_string(&path).unwrap(), before);
        edit.apply().unwrap();
        assert!(!std::fs::read_to_string(&path).unwrap().contains("murk"));
    }

    #[test]
    fn vault_args_default_vault_adds_nothing() {
        let none = Vec::<String>::new();
        assert_eq!(vault_args(".murk"), none);
        // The config lives next to the vault, so a default vault in another
        // directory is still found as `.murk` from there.
        assert_eq!(vault_args("sub/.murk"), none);
        assert_eq!(vault_args("/abs/proj/.murk"), none);
    }

    #[test]
    fn vault_args_names_a_custom_vault_by_file_name() {
        assert_eq!(vault_args("prod.murk"), ["--vault", "prod.murk"]);
        assert_eq!(vault_args("./prod.murk"), ["--vault", "prod.murk"]);
        assert_eq!(vault_args("sub/prod.murk"), ["--vault", "prod.murk"]);
        assert_eq!(vault_args("/abs/proj/prod.murk"), ["--vault", "prod.murk"]);
    }

    #[test]
    fn vault_args_land_after_mcp_in_the_entry() {
        let dir = tempfile::TempDir::new().unwrap();
        let a = adapter("claude").unwrap();
        let mut args = vault_args("prod.murk");
        args.push("--allow-exec".into());
        let edit = plan_connect(a, dir.path(), "/keys/abc-mcp", &args).unwrap();
        let v = parse(&edit.contents);
        assert_eq!(
            v["mcpServers"]["murk"]["args"],
            serde_json::json!(["mcp", "--vault", "prod.murk", "--allow-exec"])
        );
    }

    #[test]
    fn ensure_resolves_inside_rejects_a_dir_outside_the_root() {
        let root = tempfile::TempDir::new().unwrap();
        let elsewhere = tempfile::TempDir::new().unwrap();
        std::fs::create_dir(root.path().join("in")).unwrap();
        assert!(ensure_resolves_inside(root.path(), root.path()).is_ok());
        assert!(ensure_resolves_inside(root.path(), &root.path().join("in")).is_ok());
        let err = ensure_resolves_inside(root.path(), elsewhere.path()).unwrap_err();
        assert!(err.to_string().contains("outside the project directory"));
    }

    #[test]
    fn ensure_inside_project_rejects_a_path_outside_the_project() {
        let dir = tempfile::TempDir::new().unwrap();
        let other = tempfile::TempDir::new().unwrap();
        let err = ensure_inside_project(dir.path(), &other.path().join(".mcp.json")).unwrap_err();
        assert!(err.to_string().contains("outside the project directory"));
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_config_file_is_refused_and_left_alone() {
        let dir = tempfile::TempDir::new().unwrap();
        let outside = tempfile::TempDir::new().unwrap();
        let target = outside.path().join("config.json");
        let secret = "{\"auths\": {\"registry\": \"TOP-SECRET\"}}\n";
        std::fs::write(&target, secret).unwrap();
        let a = adapter("claude").unwrap();
        let link = a.config_path(dir.path());
        std::os::unix::fs::symlink(&target, &link).unwrap();

        let err = match plan_connect(a, dir.path(), "/keys/abc-mcp", &[]) {
            Err(e) => e.to_string(),
            Ok(_) => panic!("a symlinked config must be refused"),
        };
        assert!(err.contains("symlink"), "{err}");
        assert!(err.contains(".mcp.json"), "error must name the path: {err}");
        assert!(connect_client(a, dir.path(), "/keys/abc-mcp", &[]).is_err());
        assert!(disconnect_client(a, dir.path()).is_err());
        assert!(plan_disconnect(a, dir.path()).is_err());

        assert!(
            std::fs::symlink_metadata(&link)
                .unwrap()
                .file_type()
                .is_symlink(),
            "the link must still be a link"
        );
        assert_eq!(std::fs::read_to_string(&target).unwrap(), secret);
    }

    #[cfg(unix)]
    #[test]
    fn dangling_symlinked_config_file_is_refused() {
        let dir = tempfile::TempDir::new().unwrap();
        let outside = tempfile::TempDir::new().unwrap();
        let target = outside.path().join("not-yet");
        let a = adapter("claude").unwrap();
        std::os::unix::fs::symlink(&target, a.config_path(dir.path())).unwrap();
        assert!(plan_connect(a, dir.path(), "/keys/abc-mcp", &[]).is_err());
        assert!(!target.exists(), "must not create the link's target");
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_client_dir_is_refused_and_nothing_is_created_outside() {
        let dir = tempfile::TempDir::new().unwrap();
        let outside = tempfile::TempDir::new().unwrap();
        let a = adapter("cursor").unwrap();
        std::os::unix::fs::symlink(outside.path(), dir.path().join(".cursor")).unwrap();

        let err = match plan_connect(a, dir.path(), "/keys/abc-mcp", &[]) {
            Err(e) => e.to_string(),
            Ok(_) => panic!("a symlinked client dir must be refused"),
        };
        assert!(err.contains("symlink"), "{err}");
        assert!(err.contains(".cursor"), "error must name the link: {err}");
        assert!(connect_client(a, dir.path(), "/keys/abc-mcp", &[]).is_err());
        assert!(
            std::fs::read_dir(outside.path()).unwrap().next().is_none(),
            "nothing may be written through the link"
        );
    }

    #[cfg(unix)]
    #[test]
    fn apply_rechecks_for_a_symlink_swapped_in_after_planning() {
        let dir = tempfile::TempDir::new().unwrap();
        let outside = tempfile::TempDir::new().unwrap();
        let a = adapter("cursor").unwrap();
        let edit = plan_connect(a, dir.path(), "/keys/abc-mcp", &[]).unwrap();
        std::os::unix::fs::symlink(outside.path(), dir.path().join(".cursor")).unwrap();
        assert!(edit.apply().is_err());
        assert!(std::fs::read_dir(outside.path()).unwrap().next().is_none());
    }

    #[cfg(unix)]
    #[test]
    fn project_dir_reached_through_a_symlink_is_allowed() {
        // The project directory is the operator's own choice (macOS `/tmp`
        // is a link); only components below it are guarded.
        let real = tempfile::TempDir::new().unwrap();
        let holder = tempfile::TempDir::new().unwrap();
        let via = holder.path().join("proj");
        std::os::unix::fs::symlink(real.path(), &via).unwrap();
        let a = adapter("cursor").unwrap();
        connect_client(a, &via, "/keys/abc-mcp", &[]).unwrap();
        assert!(real.path().join(".cursor/mcp.json").is_file());
        assert!(disconnect_client(a, &via).unwrap().is_some());
    }
}
