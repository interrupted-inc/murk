// Mirror the repo's generated documentation into the Starlight content
// collection.
//
// docs/cli-reference.md and docs/env-reference.md are produced by
// `cargo run --features doc-gen --bin gen-docs` and CI-checked. This script is
// the docs site's only bridge to them: for each, it strips the generated-file
// banner and the leading H1, prepends Starlight frontmatter, and writes the
// result into the content collection. The outputs are git-ignored and never
// hand-edited, so the generator stays the single source of truth — regenerating
// and rebuilding the site is enough to update these pages.

import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));

/** @type {{source:string,target:string,title:string,description:string,order:number,h1:RegExp}[]} */
const artifacts = [
  {
    source: "../../docs/cli-reference.md",
    target: "../src/content/docs/reference/cli.md",
    title: "CLI reference",
    description:
      "Complete command reference for the murk command-line program, generated from its argument model.",
    order: 1,
    h1: /^#\s+murk command reference\s*\n+/,
  },
  {
    source: "../../docs/env-reference.md",
    target: "../src/content/docs/reference/env.md",
    title: "Environment variables (reference)",
    description:
      "Terse reference of the environment variables murk reads, generated from the doc registry.",
    order: 2,
    h1: /^#\s+murk environment variable reference\s*\n+/,
  },
];

for (const { source, target, title, description, order, h1 } of artifacts) {
  const src = resolve(here, source);
  const dst = resolve(here, target);
  const raw = readFileSync(src, "utf8");

  // Drop the leading "<!-- Generated ... -->" banner (frontmatter carries the
  // provenance instead), then the duplicate H1 (Starlight renders the
  // frontmatter title as the page H1).
  const body = raw.replace(/^<!--[\s\S]*?-->\s*/, "").replace(h1, "");

  const frontmatter = `---
title: ${title}
description: ${description}
sidebar:
  order: ${order}
# Generated file — do not edit.
# Source: ${source.replace("../../", "")} (produced by \`cargo run --features doc-gen --bin gen-docs\`).
# Regenerate the source, then rebuild the docs site. This file is produced by scripts/sync-generated-docs.mjs.
editUrl: false
---

`;

  mkdirSync(dirname(dst), { recursive: true });
  writeFileSync(dst, frontmatter + body);
  console.log(`synced ${title} -> ${dst}`);
}
