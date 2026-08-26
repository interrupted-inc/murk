#!/usr/bin/env node
"use strict";

// Fail the build if a demo VHS tape types something that breaks on camera.
//
// Two hazards, both learned the hard way:
//
//  1. Non-ASCII dashes inside `Type`. An em dash (or its en-dash / horizontal-bar
//     cousins) typed via VHS `Type` scrambles the line — and worse, corrupts the
//     input stream — on some local ttyd builds (reproduced on homebrew ttyd
//     1.7.7). A Hide-block `printf ... > run-tests.sh` once silently never ran
//     because of this, so the demo it set up would have failed on camera. The
//     pinned CI image renders the same tapes correctly, which is exactly why it
//     survives review unnoticed. So the check runs everywhere, Hide or Show.
//
//  2. Over-wide narration. The shared theme (demo/theme.tape) is a narrow window;
//     a `Type "# ..."` narration line longer than the on-camera budget wraps
//     mid-word, the same papercut that made the MURK_KEY error a four-line wall.
//
// Only the *typed* string is inspected. Em dashes in tape `#` comments are fine —
// they are never sent to the terminal — so this deliberately does not touch them.

const fs = require("node:fs");
const path = require("node:path");

const root = path.resolve(__dirname, "..");
const demoDir = path.join(root, "demo");
const SELF = "scripts/check-tape-typing.cjs";

// On-camera width budget for narration, in columns. The shared theme renders a
// narrow terminal (demo/theme.tape: Width 900, FontSize 18, Padding 20), so
// narration past this wraps on screen. Existing narration sits well under it;
// widen only if the theme's window grows.
const MAX_NARRATION_COLS = 75;

// A `Type` command with an optional `@speed` modifier and a single quoted
// argument (double, single, or backtick). Group 2 is the typed text.
const TYPE_RE = /^\s*Type(?:@\S+)?\s+(["'`])([\s\S]*)\1\s*$/;

// U+2013 en dash, U+2014 em dash, U+2015 horizontal bar — the "smart dash" glyphs
// an editor autocorrects a hyphen into, and the ones that corrupt ttyd input.
const DASH_RE = /[\u2013\u2014\u2015]/;

// Return the rule violations for a single tape line (empty if it is not a
// `Type`, or types nothing hazardous).
function checkLine(line) {
  const m = line.match(TYPE_RE);
  if (!m) return [];
  const text = m[2];
  const out = [];
  if (DASH_RE.test(text)) {
    out.push({ kind: "dash", detail: "non-ASCII dash in Type corrupts input on some ttyd builds; use ASCII '-'" });
  }
  if (text.trimStart().startsWith("#")) {
    const cols = [...text].length;
    if (cols > MAX_NARRATION_COLS) {
      out.push({ kind: "width", detail: `narration is ${cols} columns; keep it <= ${MAX_NARRATION_COLS} so it does not wrap on camera` });
    }
  }
  return out;
}

// Prove the parser and both rules before trusting them in CI. Cases are
// synthetic, not read from the tree.
function selfTest() {
  const flag = [
    'Type "foo \u2014 bar"', // em dash in Type
    "Type `x\u2013y`", // en dash in backtick Type
    'Type@50ms "a \u2015 b"', // horizontal bar with a speed modifier
    `Type "# ${"x".repeat(MAX_NARRATION_COLS + 1)}"`, // over-wide narration
  ];
  const pass = [
    "# Agent exec demo \u2014 run the tests with a secret", // em dash in a tape comment, not Type
    'Type "murk agent exec --only DATABASE_URL -- ./run-tests.sh"', // ASCII hyphens/double-dash
    'Type "# Give it that one value in the subprocess only"', // narration under budget
    "Sleep 1500ms",
    "Type@30ms `source .env`",
    `Type "murk get ${"K".repeat(MAX_NARRATION_COLS + 5)}"`, // long, but a command, not narration
  ];
  let ok = true;
  for (const line of flag) {
    if (checkLine(line).length === 0) {
      console.error(`self-test FAIL: expected a hit in: ${line}`);
      ok = false;
    }
  }
  for (const line of pass) {
    const hits = checkLine(line);
    if (hits.length) {
      console.error(`self-test FAIL: false positive ${hits.map((h) => h.kind).join(",")} in: ${line}`);
      ok = false;
    }
  }
  if (!ok) process.exit(1);
  console.log(`self-test OK (${flag.length} hits caught, ${pass.length} legit lines passed)`);
}

function main() {
  if (process.argv.includes("--self-test")) {
    selfTest();
    return;
  }

  let tapes;
  try {
    tapes = fs.readdirSync(demoDir).filter((f) => f.endsWith(".tape")).sort();
  } catch (e) {
    console.error(`::error::cannot read ${demoDir}: ${e.message}`);
    process.exit(1);
  }

  const violations = [];
  for (const tape of tapes) {
    const rel = `demo/${tape}`;
    const text = fs.readFileSync(path.join(demoDir, tape), "utf8");
    text.split("\n").forEach((line, i) => {
      for (const v of checkLine(line)) {
        violations.push({ file: rel, line: i + 1, ...v });
      }
    });
  }

  if (violations.length) {
    console.error(`::error::demo tapes have on-camera hazards (${violations.length} found):`);
    for (const v of violations) {
      console.error(`  ${v.file}:${v.line}  [${v.kind}] ${v.detail}`);
    }
    process.exit(1);
  }
  console.log(`OK: ${tapes.length} demo tapes type only safe, on-budget text`);
}

main();
