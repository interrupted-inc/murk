#!/usr/bin/env node
// SPDX-FileCopyrightText: murk contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

"use strict";

// Decide whether a bot's dependency update may merge without a human reading
// it. Both workflows that auto-merge use it, each from the base branch:
//
//   .github/workflows/dependabot-automerge.yaml (Dependabot PRs)
//     node scripts/automerge-policy.cjs
//     Reads UPDATE_TYPE and DEPENDENCY_NAMES (from dependabot/fetch-metadata)
//     and appends automerge=true|false to $GITHUB_OUTPUT. Only semver-patch
//     updates qualify.
//
//   .github/workflows/advisories.yaml (lockfile-only RustSec fixes)
//     node scripts/automerge-policy.cjs --lockfiles OLD NEW [OLD NEW]...
//     Compares each pair of Cargo.lock files. Exits 0 if the update may merge,
//     10 if it must wait for review, anything else on error.
//
// Either way, an update that touches a dependency murk's security rests on
// waits for review: encryption, signing, hashing, randomness, key encoding,
// secret handling in memory, TLS for key fetches, the parsers that read the
// untrusted vault file, and the MCP server agents talk to. A compromised
// release of one of those would otherwise reach main, and the next release,
// unread. CI only blocks known advisories.

const fs = require("node:fs");

const HOLD = 10;

const NEEDS_REVIEW = [
  /^age(-|$)/, // age, age-core, age-plugin
  /^ssh-/, // ssh-key, ssh-encoding, ssh-cipher
  /^(ed|x|curve)25519/, // ed25519, ed25519-dalek, x25519-dalek, curve25519-dalek
  /^(ml-kem|kem|hpke|hybrid-array|generic-array|cpufeatures)$/,
  /^(chacha20(poly1305)?|poly1305|salsa20|aead|cipher|aes(-gcm)?|ctr|cbc|blowfish|block-padding|inout)$/,
  /^(ghash|polyval|universal-hash|opaque-debug)$/,
  /^(blake3|sha1|sha2|sha3|keccak|digest|block-buffer|hmac|hkdf|scrypt|pbkdf2|bcrypt-pbkdf|signature)$/,
  /^(rsa|p256|elliptic-curve|crypto-bigint|crypto-common|der|spki|pkcs1|pkcs8|pem-rfc7468|base16ct|base64ct|const-oid)$/,
  /^(fiat-crypto|ff|group|sec1|primeorder|num-bigint-dig)$/,
  /^(rand|rand_core|rand_chacha|ppv-lite86|getrandom)$/,
  /^(subtle|zeroize|zeroize_derive|secrecy|constant_time_eq|bip39|bitcoin_hashes|bech32)$/,
  /^(ring|untrusted|rustls|rustls-pki-types|rustls-webpki|webpki-roots|ureq|ureq-proto)$/,
  /^(rpassword|pinentry)$/, // read secrets and passphrases
  /^serde(_core|_derive|_json)?$/,
  /^rmcp(-|$)/, // rmcp, rmcp-macros
];

function needsReview(name) {
  return NEEDS_REVIEW.some((re) => re.test(name));
}

// held(names) -> the names that need a human review.
const held = (names) => names.filter(needsReview);

// decide(updateType, dependencyNames) -> { automerge, reason } for Dependabot.
function decide(updateType, dependencyNames) {
  if (updateType !== "version-update:semver-patch") {
    return { automerge: false, reason: `${updateType || "unknown update type"} needs review` };
  }
  const names = dependencyNames
    .split(",")
    .map((n) => n.trim())
    .filter(Boolean);
  if (names.length === 0) {
    return { automerge: false, reason: "no dependency names reported; needs review" };
  }
  const h = held(names);
  if (h.length) {
    return { automerge: false, reason: `security-relevant dependency needs review: ${h.join(", ")}` };
  }
  return { automerge: true, reason: `patch update of ${names.join(", ")}` };
}

// lockPackages(text) -> Map of package name to its sorted "version source" list.
function lockPackages(text) {
  const pkgs = new Map();
  for (const block of text.split(/^\[\[package\]\]$/m).slice(1)) {
    const field = (key) => (block.match(new RegExp(`^${key} = "([^"]*)"$`, "m")) || [])[1] || "";
    const name = field("name");
    if (!name) throw new Error("Cargo.lock package without a name");
    const entry = `${field("version")} ${field("source")} ${field("checksum")}`;
    pkgs.set(name, [...(pkgs.get(name) || []), entry].sort());
  }
  return pkgs;
}

// changedCrates(oldText, newText) -> names added, removed or changed.
function changedCrates(oldText, newText) {
  const before = lockPackages(oldText);
  const after = lockPackages(newText);
  const names = new Set([...before.keys(), ...after.keys()]);
  return [...names]
    .filter((n) => JSON.stringify(before.get(n)) !== JSON.stringify(after.get(n)))
    .sort();
}

function selfTest() {
  let ok = true;
  const check = (label, got, want) => {
    if (got !== want) {
      console.error(`self-test FAIL: ${label} -> ${got}, want ${want}`);
      ok = false;
    }
  };

  const patch = "version-update:semver-patch";
  const dependabot = [
    // [updateType, names, expected automerge]
    [patch, "clap", true],
    [patch, "clap, colored", true],
    [patch, "actions/checkout", true],
    [patch, "tempfile,walkdir", true],
    [patch, "sharded-slab", true],
    [patch, "age", false],
    [patch, "age-core", false],
    [patch, "blake3", false],
    [patch, "ed25519-dalek", false],
    [patch, "x25519-dalek", false],
    [patch, "curve25519-dalek", false],
    [patch, "ml-kem", false],
    [patch, "kem", false],
    [patch, "ghash", false],
    [patch, "polyval", false],
    [patch, "keccak", false],
    [patch, "hpke", false],
    [patch, "fiat-crypto", false],
    [patch, "rpassword", false],
    [patch, "ssh-key", false],
    [patch, "chacha20poly1305", false],
    [patch, "sha2", false],
    [patch, "rand_core", false],
    [patch, "zeroize", false],
    [patch, "serde_json", false],
    [patch, "rmcp", false],
    [patch, "rustls-webpki", false],
    [patch, "clap, age", false],
    [patch, "", false],
    ["version-update:semver-minor", "clap", false],
    ["version-update:semver-major", "clap", false],
    ["", "clap", false],
  ];
  for (const [type, names, want] of dependabot) {
    check(`${type} [${names}]`, decide(type, names).automerge, want);
  }

  const lock = (...pkgs) =>
    "version = 4\n\n" +
    pkgs
      .map(([name, version]) => `[[package]]\nname = "${name}"\nversion = "${version}"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\n`)
      .join("\n");
  const base = lock(["clap", "4.6.1"], ["keccak", "0.1.5"], ["tempfile", "3.27.0"]);
  const lockfiles = [
    // [label, new lockfile, expected changed crates, expected held]
    ["clap bump", lock(["clap", "4.6.2"], ["keccak", "0.1.5"], ["tempfile", "3.27.0"]), "clap", ""],
    ["keccak bump", lock(["clap", "4.6.1"], ["keccak", "0.1.6"], ["tempfile", "3.27.0"]), "keccak", "keccak"],
    ["ghash added", lock(["clap", "4.6.1"], ["ghash", "0.5.1"], ["keccak", "0.1.5"], ["tempfile", "3.27.0"]), "ghash", "ghash"],
    ["second ml-kem copy", lock(["clap", "4.6.1"], ["keccak", "0.1.5"], ["ml-kem", "0.2.1"], ["ml-kem", "0.3.0"], ["tempfile", "3.27.0"]), "ml-kem", "ml-kem"],
    ["tempfile removed", lock(["clap", "4.6.1"], ["keccak", "0.1.5"]), "tempfile", ""],
    ["unchanged", base, "", ""],
  ];
  for (const [label, next, wantChanged, wantHeld] of lockfiles) {
    const changed = changedCrates(base, next);
    check(`lockfile ${label}: changed`, changed.join(","), wantChanged);
    check(`lockfile ${label}: held`, held(changed).join(","), wantHeld);
  }

  if (!ok) process.exit(1);
  console.log(`self-test OK (${dependabot.length} Dependabot cases, ${lockfiles.length} lockfile cases)`);
}

function lockfileMode(paths) {
  if (paths.length === 0 || paths.length % 2 !== 0) {
    console.error("usage: automerge-policy.cjs --lockfiles OLD NEW [OLD NEW]...");
    process.exit(2);
  }
  const changed = new Set();
  for (let i = 0; i < paths.length; i += 2) {
    const [oldPath, newPath] = [paths[i], paths[i + 1]];
    for (const n of changedCrates(fs.readFileSync(oldPath, "utf8"), fs.readFileSync(newPath, "utf8"))) {
      changed.add(n);
    }
  }
  const h = held([...changed]);
  if (h.length) {
    console.log(`no auto-merge: security-relevant dependency needs review: ${h.join(", ")}`);
    process.exit(HOLD);
  }
  console.log(`auto-merge: lockfile update of ${[...changed].join(", ") || "nothing"}`);
}

function main() {
  const args = process.argv.slice(2);
  if (args.includes("--self-test")) {
    selfTest();
    return;
  }
  if (args[0] === "--lockfiles") {
    lockfileMode(args.slice(1));
    return;
  }
  const { automerge, reason } = decide(process.env.UPDATE_TYPE || "", process.env.DEPENDENCY_NAMES || "");
  console.log(`${automerge ? "auto-merge" : "no auto-merge"}: ${reason}`);
  if (process.env.GITHUB_OUTPUT) {
    fs.appendFileSync(process.env.GITHUB_OUTPUT, `automerge=${automerge}\n`);
  }
}

main();
