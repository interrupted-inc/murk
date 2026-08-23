//! Wiring `murk mcp` into AI-editor MCP client configs — the engine behind
//! `murk agent connect` / `murk agent disconnect`.
//!
//! Every client stores MCP servers in its own file with its own root key
//! (`mcpServers`, or `servers` for VS Code) and its own formatting, and those
//! files are frequently hand-edited and full of `//` comments. So we never
//! reserialize the whole document: we surgically upsert (or remove) only the
//! `murk` entry, leaving every other server, key, and comment byte-for-byte
//! intact. The only thing written into a config is a `MURK_KEY_FILE` *path* plus
//! `MURK_AGENT=1` — never inline key material — so even a committed config leaks
//! nothing but a machine-local path.

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
        .ok_or_else(|| MurkError::Io(std::io::Error::other("config is not a JSON object")))?;
    let (_top_close, top_members) = object_members(b, top)
        .ok_or_else(|| MurkError::Io(std::io::Error::other("could not parse config JSON")))?;

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
        .ok_or_else(|| MurkError::Io(std::io::Error::other("malformed config member")))?;
    let cval_start = skip_trivia(b, colon + 1);
    if cval_start >= b.len() || b[cval_start] != b'{' {
        return Err(MurkError::Io(std::io::Error::other(format!(
            "\"{root_key}\" is not an object in this config"
        ))));
    }
    let (cclose, cmembers) = object_members(b, cval_start)
        .ok_or_else(|| MurkError::Io(std::io::Error::other("could not parse server list")))?;

    if let Some(existing_server) = cmembers.iter().find(|m| m.key == server) {
        // Replace just murk's value span.
        let member_indent = line_indent(b, existing_server.key_start);
        let value = render_value(spec, &member_indent, &unit);
        let vstart = find_colon_after_key(b, existing_server.key_start)
            .map(|c| skip_trivia(b, c + 1))
            .ok_or_else(|| MurkError::Io(std::io::Error::other("malformed murk entry")))?;
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

/// Upsert the `murk` server into `adapter`'s config under `project_dir`, writing
/// only a `MURK_KEY_FILE` path (`key_file`) + `MURK_AGENT=1` and any `extra_args`
/// after `mcp`. Preserves every other server and comment; atomic (temp+rename).
pub fn connect_client(
    adapter: &ClientAdapter,
    project_dir: &Path,
    key_file: &str,
    extra_args: &[String],
) -> Result<ConnectOutcome, MurkError> {
    let path = adapter.config_path(project_dir);
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
    let updated = match adapter.format {
        ConfigFormat::Json => {
            upsert_json_server(existing.as_deref(), adapter.root_key, "murk", &spec)?
        }
        ConfigFormat::Toml => {
            upsert_toml_server(existing.as_deref(), adapter.root_key, "murk", &spec)?
        }
    };
    write_config(&path, &updated)?;
    Ok(ConnectOutcome { path, created })
}

/// Remove the `murk` server from `adapter`'s config. Returns the path when a
/// change was written, `None` when there was nothing to remove.
pub fn disconnect_client(
    adapter: &ClientAdapter,
    project_dir: &Path,
) -> Result<Option<PathBuf>, MurkError> {
    let path = adapter.config_path(project_dir);
    let existing = match std::fs::read_to_string(&path) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(MurkError::Io(e)),
    };
    let removed = match adapter.format {
        ConfigFormat::Json => remove_json_server(&existing, adapter.root_key, "murk")?,
        ConfigFormat::Toml => remove_toml_server(&existing, adapter.root_key, "murk")?,
    };
    match removed {
        Some(updated) => {
            write_config(&path, &updated)?;
            Ok(Some(path))
        }
        None => Ok(None),
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
}
