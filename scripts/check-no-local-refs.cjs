#!/usr/bin/env node
// SPDX-FileCopyrightText: murk contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

"use strict";

// Fail the build if a local-only reference ID leaks into a committed file.
//
// Short `murk-<slug>` tokens (e.g. murk-x1y, murk-x1y.2) are local-only
// reference IDs: they are meaningful only on the machine that generated them,
// so in a shared file they are pure noise or confusion to every other reader.
// This turns a rule that was enforced by memory into an enforced invariant,
// alongside the repo's other check-*.cjs guards.
//
// Shape: `murk-` + a 3-character base-36 slug, optionally with `.N` suffixes.
// That 3-char slug is the whole signal — it cleanly separates these IDs from
// the many legitimate `murk-` tokens (murk-cli, murk-docs, murk-accent-glow,
// murk-secrets-linux-x64, the CLI command anchors, …) which are either a
// different length or multi-segment. If the ID length ever changes, widen the
// pattern below. The few legitimate 3-char tokens (murk-cli/-key and 3-letter
// command anchors like murk-add/-get/-env/-mcp) are allowlisted; the command
// anchors are derived from the generated docs/cli-reference.md, so new commands
// never trip the guard.

const { execFileSync } = require("node:child_process");
const fs = require("node:fs");
const path = require("node:path");

const root = path.resolve(__dirname, "..");
const read = (f) => fs.readFileSync(path.join(root, f), "utf8");
const SELF = "scripts/check-no-local-refs.cjs";

// 3-char-slug tokens that are legitimately in the tree.
function buildAllowlist() {
  const allow = new Set(["murk-cli", "murk-key"]);
  // 3-letter CLI command anchors from the generated reference (`murk add` ->
  // murk-add). Longer anchors never match the ID pattern, so they're harmless.
  try {
    const ref = read("docs/cli-reference.md");
    const re = /\[`(murk[a-z0-9 -]*)`/g;
    let m;
    while ((m = re.exec(ref)) !== null) {
      allow.add(m[1].trim().replace(/\s+/g, "-"));
    }
  } catch {
    // No generated reference; static allowlist still applies.
  }
  return allow;
}

// `murk-` + exactly a 3-char alphanumeric slug, not part of a longer hyphenated
// token, plus optional `.N` suffixes.
const TOKEN = /(?<![a-z0-9-])murk-[a-z0-9]{3}(?![a-z0-9-])(?:\.[0-9]+)*/g;

const baseOf = (token) => token.replace(/(?:\.[0-9]+)+$/, "");
const isAllowed = (allow, token) => allow.has(token) || allow.has(baseOf(token));

const flaggedInLine = (allow, line) =>
  (line.match(TOKEN) || []).filter((tok) => !isAllowed(allow, tok));

const isBinaryPath = (p) =>
  /\.(gif|png|jpe?g|webp|ico|svg|woff2?|ttf|otf|eot|pdf|zip|gz|wasm)$/i.test(p);

// Prove the whole pipeline (pattern + allowlist) before trusting it in CI.
// Flag cases use synthetic placeholder slugs, never real IDs.
function selfTest(allow) {
  const flag = [
    "see murk-x1y.2 for context",
    "(murk-q9q.5)",
    "murk-z0z",
    "regression for murk-a7b",
    "murk-q9q.1",
    "(murk-x1y.3)",
  ];
  const pass = [
    "murk-cli",
    "the murk-key: prefix",
    "@interrupted/murk-secrets",
    "murk-napi crate",
    "#murk-agent-plan",
    "murk-init",
    "murk-mcp anchor",
    "the murk-docs package",
    "murk-linux artifact",
    "--murk-accent-glow",
    "murk-secrets-linux-x64-gnu",
    "murk-cli-fuzz",
    "murk-v0.8.0",
  ];
  let ok = true;
  for (const line of flag) {
    if (flaggedInLine(allow, line).length === 0) {
      console.error(`self-test FAIL: expected a hit in: ${line}`);
      ok = false;
    }
  }
  for (const line of pass) {
    const hits = flaggedInLine(allow, line);
    if (hits.length) {
      console.error(`self-test FAIL: false positive ${hits.join(",")} in: ${line}`);
      ok = false;
    }
  }
  if (!ok) process.exit(1);
  console.log(`self-test OK (${flag.length} hits caught, ${pass.length} legit tokens passed)`);
}

function main() {
  const allow = buildAllowlist();

  if (process.argv.includes("--self-test")) {
    selfTest(allow);
    return;
  }

  const files = execFileSync("git", ["ls-files"], {
    cwd: root,
    encoding: "utf8",
    maxBuffer: 1 << 26,
  })
    .split("\n")
    .filter(Boolean)
    .filter((f) => f !== SELF)
    .filter((f) => !isBinaryPath(f));

  const violations = [];
  for (const f of files) {
    let text;
    try {
      text = read(f);
    } catch {
      continue;
    }
    if (text.includes("\u0000")) continue; // binary
    text.split("\n").forEach((line, i) => {
      for (const tok of flaggedInLine(allow, line)) {
        violations.push({ file: f, line: i + 1, tok });
      }
    });
  }

  if (violations.length) {
    console.error(
      `::error::local-only reference IDs must not appear in committed files (${violations.length} found):`,
    );
    for (const v of violations) {
      console.error(`  ${v.file}:${v.line}  ${v.tok}`);
    }
    process.exit(1);
  }
  console.log(`OK: no stray local reference IDs in ${files.length} tracked files`);
}

main();
