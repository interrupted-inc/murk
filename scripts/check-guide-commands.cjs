#!/usr/bin/env node
"use strict";

// Anti-drift for the docs guides: every murk command shown in a guide example
// must (a) be a real command in the CLI surface and (b) be exercised by a
// tested flow — a VHS demo tape, a Makefile demo target, or the shared demo
// setup helpers. A command that fails (a) is a rename/removal the prose missed;
// one that fails (b) is an example we claim works but never run.
//
// This is a command-level presence check, deliberately not a flag- or
// argument-level one: it catches removed/renamed subcommands (the failure mode
// that silently rots prose) without breaking on copy edits or placeholder args.
//
// Sources of truth:
//   - Valid command paths: docs/cli-reference.md, generated from the clap model
//     by gen-docs and already CI-checked for currency (ci.yaml lint job).
//   - Executed corpus: demo/*.tape, demo/setup.sh, and the Makefile demo
//     targets that `make test-demos` runs in CI (not the whole Makefile — a
//     manual-only recipe must not create false coverage).
//   - Documented examples: fenced code blocks in the guide pages below.
//
// A guide command that is valid but intentionally not demo-covered belongs in
// ALLOWLIST with a reason, so the exemption is a conscious, reviewed decision.

const fs = require("node:fs");
const path = require("node:path");

const root = path.resolve(__dirname, "..");
const read = (f) => fs.readFileSync(path.join(root, f), "utf8");

// Guide/example pages whose fenced commands must map to a tested flow.
const GUIDE_GLOB_DIR = "docs-site/src/content/docs/guides";
const EXTRA_GUIDE_PAGES = ["docs-site/src/content/docs/quick-start.mdx"];
// Files whose murk invocations constitute the "tested flow" corpus. The
// Makefile is scanned selectively (see makefileCorpus); setup.sh is sourced by
// every demo target, and the tapes are recorded by the CI vhs matrix.
const CORPUS_STATIC_FILES = ["demo/setup.sh"];
const CORPUS_TAPE_DIR = "demo";

// Valid commands that guides document but no demo exercises, by design.
// Each entry MUST carry a reason; unused entries are reported as stale.
// These are covered by the Rust integration tests (tests/cli.rs et al.) but not
// by a visual VHS demo, so they don't appear in the executed-demo corpus. Each
// stays honest: it's tested, just not scripted as a tape.
const ALLOWLIST = {
  exec: "run-a-command wrapper; tests/cli.rs (agent-exec tape covers the scoped variant)",
  "agent init": "agent grant onboarding; tests/cli.rs (multi-identity flow doesn't render as one tape)",
  "agent connect": "MCP editor wiring; tests/cli.rs",
  "agent ls": "grant listing; tests/cli.rs",
  "agent revoke": "grant revocation; tests/cli.rs",
  "policy set": "agent policy write; tests/cli.rs",
  mcp: "long-running stdio server; tests/mcp_interop.rs (no finite tape)",
  diff: "git-ref secret diff; tests/cli.rs",
  "setup-merge-driver": "one-time git config; tests/cli.rs",
  import: "reverse of export; tests/cli.rs + tests/adversarial.rs",
};

// --- Command tree from the generated CLI reference ---------------------------

// Parse the "Command Overview" bullet list: * [`murk circle authorize`↴](...).
function loadValidPaths() {
  const ref = read("docs/cli-reference.md");
  const paths = new Set();
  const re = /\* \[`murk([^`↴]*)`/g;
  let m;
  while ((m = re.exec(ref)) !== null) {
    const rest = m[1].trim(); // "" for bare murk, "circle authorize", etc.
    paths.add(rest);
  }
  if (paths.size <= 1) {
    console.error("::error::could not parse commands from docs/cli-reference.md");
    process.exit(1);
  }
  return paths;
}

// Resolve a token list (everything after `murk`) to its canonical command path
// — the longest leading run of tokens that names a real command. Returns null
// when the first token names no command (an unknown/renamed command), and ""
// for a bare `murk` / global-flag invocation (no subcommand — skipped).
function resolvePath(tokens, validPaths) {
  const words = tokens.filter((t) => /^[a-z][a-z-]*$/.test(t)); // subcommand-shaped only
  if (words.length === 0) return ""; // bare murk or `murk --flag`
  for (let depth = Math.min(2, words.length); depth >= 1; depth--) {
    const candidate = words.slice(0, depth).join(" ");
    if (validPaths.has(candidate)) return candidate;
  }
  return null; // no valid command prefix -> unknown command
}

// Find every murk invocation in a blob of shell-ish text and yield its tail
function* murkInvocations(text) {
  // Drop shell comments first: a `# ... murk ...` line is prose, not a command
  // (and the guides are full of explanatory `#` comments inside bash blocks).
  const normalized = text
    .split("\n")
    .map((line) => line.replace(/(^|\s)#.*$/, "$1"))
    .join("\n")
    .replace(/\$\(MURK\)/g, "murk");
  // `murk` must be a command word: reject `.murk`/`path/murk` (a filename, not
  // the binary) via the lookbehind, and keep the gap between the command and
  // its args on one line so a bare `murk` can't glom onto the next line.
  const re = /(?<![\w./-])murk[ \t]+([^\n|&;`"'()<>]*)/g;
  let m;
  while ((m = re.exec(normalized)) !== null) {
    yield m[1].trim().split(/\s+/).filter(Boolean);
  }
}

// Fenced code blocks only — inline `code` in prose is a reference, not a
// runnable example, and often uses alternation like `create|ls|add|rm`.
function* fencedBlocks(md) {
  const re = /```[^\n]*\n([\s\S]*?)```/g;
  let m;
  while ((m = re.exec(md)) !== null) yield m[1];
}

function guidePages() {
  const dir = path.join(root, GUIDE_GLOB_DIR);
  const pages = fs
    .readdirSync(dir)
    .filter((f) => f.endsWith(".md") || f.endsWith(".mdx"))
    .map((f) => path.join(GUIDE_GLOB_DIR, f));
  return [...pages, ...EXTRA_GUIDE_PAGES];
}

function tapeFiles() {
  const dir = path.join(root, CORPUS_TAPE_DIR);
  return fs
    .readdirSync(dir)
    .filter((f) => f.endsWith(".tape"))
    .map((f) => path.join(CORPUS_TAPE_DIR, f));
}

// Recipe bodies of exactly the Makefile targets that `make test-demos` runs, so
// a manual-only recipe can never create false "covered" entries. Reads the
// test-demos prerequisite line for the target names, then extracts each
// target's indented recipe body.
function makefileCorpus() {
  const mk = read("Makefile");
  const demoLine = mk.match(/^test-demos:[^\n]*/m);
  if (!demoLine) {
    console.error("::error::could not find the test-demos target in the Makefile");
    process.exit(1);
  }
  const targets = (demoLine[0].match(/test-[a-z-]+/g) || []).filter(
    (t) => t !== "test-demos",
  );
  const bodies = [];
  for (const t of targets) {
    const re = new RegExp(`^${t}:[^\\n]*\\n((?:\\t[^\\n]*\\n?)+)`, "m");
    const m = mk.match(re);
    if (m) bodies.push(m[1]);
  }
  return bodies.join("\n");
}

// --- Build sets --------------------------------------------------------------

const validPaths = loadValidPaths();

// Corpus: commands proven to run — static demo files, all recorded tapes, and
// the CI-run Makefile demo recipes (as an in-memory blob).
const covered = new Set();
const corpusTexts = [
  ...[...CORPUS_STATIC_FILES, ...tapeFiles()].map(read),
  makefileCorpus(),
];
for (const text of corpusTexts) {
  for (const tokens of murkInvocations(text)) {
    const p = resolvePath(tokens, validPaths);
    if (p) covered.add(p);
  }
}

// Guides: commands we must justify.
const unknown = []; // documented command that is not a real murk command
const uncovered = []; // valid command with no tested flow and no allowlist entry
const documented = new Set();

for (const page of guidePages()) {
  const md = read(page);
  for (const block of fencedBlocks(md)) {
    for (const tokens of murkInvocations(block)) {
      const p = resolvePath(tokens, validPaths);
      if (p === "") continue; // bare murk / global flag
      if (p === null) {
        unknown.push({ page, cmd: `murk ${tokens.join(" ")}` });
        continue;
      }
      documented.add(p);
      if (!covered.has(p) && !(p in ALLOWLIST)) uncovered.push({ page, cmd: p });
    }
  }
}

// Stale allowlist entries: exempted but no longer documented (or now covered).
const staleAllow = Object.keys(ALLOWLIST).filter(
  (p) => !documented.has(p) || covered.has(p),
);

// --- Report ------------------------------------------------------------------

let failed = false;

if (unknown.length) {
  failed = true;
  console.error("::error::guide examples reference commands that do not exist in the murk CLI:");
  for (const u of unknown) console.error(`  ${u.cmd}  (${u.page})`);
}

if (uncovered.length) {
  failed = true;
  const seen = new Set();
  console.error(
    "::error::guide examples use commands not exercised by any demo/test flow (add a demo, or add to ALLOWLIST with a reason):",
  );
  for (const u of uncovered) {
    if (seen.has(u.cmd)) continue;
    seen.add(u.cmd);
    console.error(`  murk ${u.cmd}`);
  }
}

if (staleAllow.length) {
  failed = true;
  console.error("::error::stale ALLOWLIST entries — no longer documented or now demo-covered, remove them:");
  for (const p of staleAllow) console.error(`  murk ${p}`);
}

if (failed) process.exit(1);

console.log(
  `OK: ${documented.size} guide command(s) all resolve to real CLI commands and map to a tested flow` +
    (Object.keys(ALLOWLIST).length ? ` (${Object.keys(ALLOWLIST).length} allowlisted)` : ""),
);
