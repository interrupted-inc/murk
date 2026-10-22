// SPDX-FileCopyrightText: murk contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The role × command authorization matrix: for every vault command and every
//! role, whether murk allows it.
//!
//! This module is plain data. `tests/auth_matrix.rs` runs every cell against
//! the real binary, and `src/bin/gen-docs.rs` renders the same rows into
//! `docs/permissions.md`, so the documented policy and the enforced one can't
//! drift apart.
//!
//! The fixture vault the test builds (and the docs describe):
//!
//! - `SHARED` — shared with everyone. The override owner also has a personal
//!   (`--group me`) value for it.
//! - `OPS` — held by the group `ops` (owner, group member, and the spare
//!   recipient).
//! - `PRIV` — only the override owner's personal value.
//! - `AGENT_OK` — shared with everyone; the scope of both agent grants.
//! - Every key is tagged `agents` and the policy allows that tag, so the policy
//!   never hides a key from a grant here.
//! - `spare` is a recipient in `ops` that commands target (revoke, group rm).
//! - `idle` is a group with no secrets, whose members are the owner and the
//!   group member.
//! - `x` is a key that is not on the vault yet; `circle authorize` adds it.

// Each consumer (the test and gen-docs) uses a different part of this module.
#![allow(dead_code)]

/// Who runs the command.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    /// Created the vault with `murk init`; also in group `ops`.
    Owner,
    /// An ordinary recipient, in no group.
    Member,
    /// A recipient in group `ops`, not the owner.
    GroupMember,
    /// A recipient outside group `ops`.
    NonMember,
    /// A recipient with personal (`--group me`) values: an override of
    /// `SHARED` and the only value of `PRIV`.
    OverrideOwner,
    /// An agent grant key scoped to `AGENT_OK`, without `MURK_AGENT`.
    Grant,
    /// The same grant key with `MURK_AGENT=1`.
    GrantAgent,
    /// A grant key for `AGENT_OK` whose TTL has passed.
    GrantExpired,
    /// A recipient that was revoked (without rotation).
    Revoked,
    /// A key that was never on the vault.
    Outsider,
}

impl Role {
    /// Column order of every row's `cells`.
    pub const ALL: [Role; 10] = [
        Role::Owner,
        Role::Member,
        Role::GroupMember,
        Role::NonMember,
        Role::OverrideOwner,
        Role::Grant,
        Role::GrantAgent,
        Role::GrantExpired,
        Role::Revoked,
        Role::Outsider,
    ];

    /// Short column heading.
    pub fn heading(self) -> &'static str {
        match self {
            Role::Owner => "owner",
            Role::Member => "member",
            Role::GroupMember => "group member",
            Role::NonMember => "group non-member",
            Role::OverrideOwner => "override owner",
            Role::Grant => "grant",
            Role::GrantAgent => "grant + MURK_AGENT",
            Role::GrantExpired => "expired grant",
            Role::Revoked => "revoked",
            Role::Outsider => "outsider",
        }
    }

    /// One-line description for the docs legend.
    pub fn describe(self) -> &'static str {
        match self {
            Role::Owner => "created the vault with `murk init`; a member of group `ops`",
            Role::Member => "an ordinary recipient in no group",
            Role::GroupMember => "a recipient in group `ops`",
            Role::NonMember => "a recipient outside group `ops`",
            Role::OverrideOwner => {
                "a recipient with personal (`--group me`) values: an override of `SHARED` and all of `PRIV`"
            }
            Role::Grant => "an agent grant key scoped to `AGENT_OK`, with `MURK_AGENT` unset",
            Role::GrantAgent => "the same grant key with `MURK_AGENT=1`",
            Role::GrantExpired => "a grant key for `AGENT_OK` past its TTL",
            Role::Revoked => "a recipient removed with `circle revoke` (no rotation)",
            Role::Outsider => "a key that was never on the vault",
        }
    }

    pub fn index(self) -> usize {
        Role::ALL.iter().position(|r| *r == self).unwrap()
    }
}

/// What murk does with the command for a role.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    Allow,
    Refuse,
    /// Only for `merge-driver`: it exits non-zero and reports a conflict, so
    /// git records the merge as conflicted instead of committing it. Git keeps
    /// what the driver wrote to its scratch copy as the conflicted result, so
    /// that copy may change; the merge is never reported clean.
    Conflict,
}

/// Why a cell holds its verdict.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Basis {
    /// Settled by the stated policy, SPEC.md, or the docs.
    Policy,
    /// The policy left it open; decided here for the reason given, picking
    /// the rule that never widens who can read a value.
    Decided(&'static str),
    /// What murk does today, recorded so the test notices any change. Whether
    /// it is the intended rule is an open product question (see
    /// [`UNDER_REVIEW`]); a decision changes these cells.
    UnderReview,
}

/// One cell: the verdict and why it holds.
#[derive(Clone, Copy, Debug)]
pub struct Cell {
    pub verdict: Verdict,
    pub basis: Basis,
}

const A: Cell = Cell {
    verdict: Verdict::Allow,
    basis: Basis::Policy,
};
const R: Cell = Cell {
    verdict: Verdict::Refuse,
    basis: Basis::Policy,
};
const fn da(reason: &'static str) -> Cell {
    Cell {
        verdict: Verdict::Allow,
        basis: Basis::Decided(reason),
    }
}
const fn dr(reason: &'static str) -> Cell {
    Cell {
        verdict: Verdict::Refuse,
        basis: Basis::Decided(reason),
    }
}
const fn dc(reason: &'static str) -> Cell {
    Cell {
        verdict: Verdict::Conflict,
        basis: Basis::Decided(reason),
    }
}
/// Allowed today, under review.
const CUR: Cell = Cell {
    verdict: Verdict::Allow,
    basis: Basis::UnderReview,
};

/// The open question behind every [`Basis::UnderReview`] cell, as the docs
/// state it.
pub const UNDER_REVIEW: &str = "murk has no admin role. Every recipient except agent grants can add and remove recipients, manage groups, set the policy and mint grants. Group-only and personal values stay protected from recipients outside the group. Changes are attributable through vault signatures (keys that cannot sign, such as hardware keys, rely on signed git commits).";

/// Who a newly created key's value must be encrypted to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Audience {
    /// The shared value only, readable by every recipient (no grant).
    Everyone,
    /// One named group's value only, readable by exactly its members.
    Group(&'static str),
    /// The caller's personal value only.
    Me,
}

/// How the test judges an allowed cell beyond its exit status. Every cell
/// also checks that no output holds a value the role may not read, and every
/// refused cell that the guarded vault file is byte-for-byte unchanged.
///
/// Write checks work per value (each key's shared value, each group value,
/// each personal value), found by decrypting every ciphertext with every
/// fixture key straight through age.
#[derive(Clone, Copy, Debug)]
pub enum Check {
    /// Reads only: the vault must not change. With `reveals`, the output must
    /// carry the value of that key this role sees.
    Read { reveals: Option<&'static str> },
    /// Changes the vault. An allowed run must change the guarded file, and:
    ///
    /// - nobody may gain read access to a value unless listed in `gains`
    ///   (`(key, reader)`, `*` for any);
    /// - a personal value may only appear for the caller;
    /// - every value keeps its readers and its plaintext, unless its key is in
    ///   `touches` (personal values of other recipients are kept even then) or
    ///   the reader is listed in `losses`; an expired grant may lose access on
    ///   any write, since that only closes access;
    /// - every new key is listed in `creates`, with exactly the audience given.
    Write {
        touches: &'static [&'static str],
        gains: &'static [(&'static str, &'static str)],
        losses: &'static [(&'static str, &'static str)],
        creates: &'static [(&'static str, Audience)],
    },
}

/// Why the editor rows run on Unix only: they drive `murk edit` with a POSIX
/// `sh` editor script, and murk runs `$EDITOR` through `sh` only on Unix.
/// The rest of the suite tests `edit` on Unix only for the same reason.
pub const EDITOR_UNIX_ONLY: &str =
    "the test drives `$EDITOR` with an `sh` script, which murk runs through `sh` only on Unix";

/// One command: how to run it and the expected verdict per role.
#[derive(Clone, Copy, Debug)]
pub struct Row {
    /// Shown in the docs. Close to `args`, without `--vault`.
    pub command: &'static str,
    /// argv after `murk`. `{X}` is replaced with the new recipient's pubkey,
    /// and `{PRINTENV}` with a command that prints the environment (`env`, or
    /// `cmd /C set` on Windows).
    pub args: &'static [&'static str],
    /// Piped to stdin.
    pub stdin: &'static str,
    /// Files written into the repo before the run: `(path, contents)`.
    pub files: &'static [(&'static str, &'static str)],
    /// Run with `EDITOR` set to a script that writes `val-edited` (Unix only,
    /// see [`EDITOR_UNIX_ONLY`]).
    pub editor: bool,
    /// The vault file the command works on: unchanged on refusal, changed by
    /// an allowed write (default `test.murk`).
    pub guard: &'static str,
    pub check: Check,
    /// One per [`Role::ALL`], in order.
    pub cells: [Cell; 10],
}

const READ: Check = Check::Read { reveals: None };
const fn reveals(key: &'static str) -> Check {
    Check::Read { reveals: Some(key) }
}
const fn write(touches: &'static [&'static str]) -> Check {
    Check::Write {
        touches,
        gains: &[],
        losses: &[],
        creates: &[],
    }
}
const fn create(creates: &'static [(&'static str, Audience)]) -> Check {
    Check::Write {
        touches: &[],
        gains: &[],
        losses: &[],
        creates,
    }
}

const fn row(
    command: &'static str,
    args: &'static [&'static str],
    check: Check,
    cells: [Cell; 10],
) -> Row {
    Row {
        command,
        args,
        stdin: "",
        files: &[],
        editor: false,
        guard: "test.murk",
        check,
        cells,
    }
}

impl Row {
    const fn stdin(mut self, stdin: &'static str) -> Self {
        self.stdin = stdin;
        self
    }
    const fn files(mut self, files: &'static [(&'static str, &'static str)]) -> Self {
        self.files = files;
        self
    }
    const fn editor(mut self) -> Self {
        self.editor = true;
        self
    }
    const fn guard(mut self, guard: &'static str) -> Self {
        self.guard = guard;
        self
    }
}

// Reasons for cells the stated policy leaves open. Each picks the rule that
// never widens who can read a value.
const PUBLIC: &str = "reads only the plaintext header and schema, which are public by design (SPEC: header is public, values are private)";
const GRANT_META: &str = "a grant is not a meta recipient, so these commands run but reveal no recipient names, groups or other grants, and no value outside its scope (THREAT_MODEL: agent grants)";
const GRANT_READ: &str = "a read bounded to the grant's scope, the same as `export`";
const MCP_ONLY_AGENT: &str = "`murk mcp` serves only a grant key in agent context (docs/ai-agents.md: serving secrets over MCP)";
const NO_SHIFT: &str = "piped values are matched by position, so a batch that would skip a value the caller can't rotate (another group's value, or another recipient's override) refuses before writing";
const NONMEMBER_RM: &str =
    "deleting a group value is the most destructive overwrite, so a non-member can't do it";
const NONMEMBER_DESCRIBE: &str =
    "only a group member can change a group key, its schema included, as with `rm`";
const OPERATOR_KEY: &str = "`agent exec` is for agent grant keys; a recipient's own key needs `--allow-operator-key`, an explicit operator decision (docs/ai-agents.md: rules)";
const LOADS: &str = "`rotate --list` loads and verifies the vault before trusting its rotation schedule, so it needs a key that can load the vault (SPEC: header reads)";
const GRANT_DIFF: &str = "a grant can't read the meta, so it can't verify the git revision `diff` compares against, and nothing unverified is shown";
const OTHERS_ONLY: &str = "the key holds only another recipient's personal value: there is no tier the caller could keep, and murk never picks a wider one";
const SELF_REVOKE: &str = "revoking your own key would lock the writer out mid-command, so murk asks another recipient to do it";
const MERGE_KEYLESS: &str = "a key that can't read both sides' meta can't rebuild the integrity metadata, so the driver reports a conflict and git keeps the merge out of history";

/// Readers of everything current: recipients only.
const RECIPIENTS: [Cell; 10] = [A, A, A, A, A, R, R, R, R, R];
/// Writers: every recipient; no grant, revoked key or outsider.
const WRITERS: [Cell; 10] = RECIPIENTS;
/// Group `ops` only.
const OPS: [Cell; 10] = [A, R, A, R, R, R, R, R, R, R];
/// Recipients plus a live grant, reading within its scope.
const WITH_GRANT: [Cell; 10] = [A, A, A, A, A, A, A, R, R, R];
/// Every recipient, as murk behaves today; under review (see [`UNDER_REVIEW`]).
const ANY: [Cell; 10] = [CUR, CUR, CUR, CUR, CUR, R, R, R, R, R];
/// Header-only reads: everyone, including keys that can't decrypt.
const PUBLIC_ALL: [Cell; 10] = [
    A,
    A,
    A,
    A,
    A,
    da(PUBLIC),
    da(PUBLIC),
    da(PUBLIC),
    da(PUBLIC),
    da(PUBLIC),
];
/// Meta reads: recipients and live grants.
const META: [Cell; 10] = [A, A, A, A, A, da(GRANT_META), da(GRANT_META), R, R, R];
/// `agent exec`: grant keys only; recipients need `--allow-operator-key`.
const OP_KEY: Cell = dr(OPERATOR_KEY);

/// `KEY=value` file naming the two shared keys.
const SHARED_VALUES: &[(&str, &str)] = &[("vals.env", "SHARED=val-rot-s\nAGENT_OK=val-rot-a\n")];

/// Every row of the matrix, in display order.
pub const ROWS: &[Row] = &[
    // ── Reads ──────────────────────────────────────────────────────────
    row("get SHARED", &["get", "SHARED"], reveals("SHARED"), RECIPIENTS),
    row("get OPS", &["get", "OPS"], reveals("OPS"), OPS),
    row(
        "get PRIV",
        &["get", "PRIV"],
        reveals("PRIV"),
        [R, R, R, R, A, R, R, R, R, R],
    ),
    row("get AGENT_OK", &["get", "AGENT_OK"], reveals("AGENT_OK"), WITH_GRANT),
    row(
        "export",
        &["export"],
        READ,
        [A, A, A, A, A, da(GRANT_READ), da(GRANT_READ), R, R, R],
    ),
    row(
        "exec -- env",
        &["exec", "--", "{PRINTENV}"],
        READ,
        [A, A, A, A, A, da(GRANT_READ), da(GRANT_READ), R, R, R],
    ),
    row(
        "agent exec --only AGENT_OK -- env",
        &["agent", "exec", "--only", "AGENT_OK", "--", "{PRINTENV}"],
        READ,
        [OP_KEY, OP_KEY, OP_KEY, OP_KEY, OP_KEY, A, A, R, R, R],
    ),
    row(
        "agent exec --only SHARED -- env",
        &["agent", "exec", "--only", "SHARED", "--", "{PRINTENV}"],
        READ,
        [OP_KEY, OP_KEY, OP_KEY, OP_KEY, OP_KEY, R, R, R, R, R],
    ),
    row(
        "agent exec --allow-operator-key --only SHARED -- env",
        &["agent", "exec", "--allow-operator-key", "--only", "SHARED", "--", "{PRINTENV}"],
        READ,
        RECIPIENTS,
    ),
    row(
        "mcp (murk_get AGENT_OK)",
        &["mcp"],
        reveals("AGENT_OK"),
        [
            dr(MCP_ONLY_AGENT),
            dr(MCP_ONLY_AGENT),
            dr(MCP_ONLY_AGENT),
            dr(MCP_ONLY_AGENT),
            dr(MCP_ONLY_AGENT),
            dr(MCP_ONLY_AGENT),
            A,
            R,
            R,
            R,
        ],
    )
    .stdin(concat!(
        r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"matrix","version":"0"}}}"#,
        "\n",
        r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
        "\n",
        r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"murk_get","arguments":{"key":"AGENT_OK"}}}"#,
        "\n",
        r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"murk_get","arguments":{"key":"SHARED"}}}"#,
        "\n",
    )),
    row(
        "diff --show-values",
        &["diff", "--show-values"],
        READ,
        [A, A, A, A, A, dr(GRANT_DIFF), dr(GRANT_DIFF), R, R, R],
    ),
    // On a copy git has no commit for: `verify` also fails on an unsigned
    // last commit, for every role alike, which says nothing about access.
    row("verify", &["verify", "--vault", ".merge/ours.murk"], READ, META).guard(".merge/ours.murk"),
    row(
        "scan",
        &["scan"],
        READ,
        [A, A, A, A, A, da(GRANT_READ), da(GRANT_READ), R, R, R],
    ),
    row("ls", &["ls"], READ, PUBLIC_ALL),
    row("info", &["info"], READ, PUBLIC_ALL),
    row("circle", &["circle"], READ, PUBLIC_ALL),
    row("policy show", &["policy", "show"], READ, PUBLIC_ALL),
    row(
        "rotate --list --json",
        &["rotate", "--list", "--json"],
        READ,
        [
            A,
            A,
            A,
            A,
            A,
            da(LOADS),
            da(LOADS),
            dr(LOADS),
            dr(LOADS),
            dr(LOADS),
        ],
    ),
    row("skeleton -o FILE", &["skeleton", "-o", "skeleton.murk"], READ, PUBLIC_ALL),
    row("agent plan -o FILE", &["agent", "plan", "-o", "plan.txt"], READ, PUBLIC_ALL),
    row("group ls", &["group", "ls"], READ, META),
    row("agent ls", &["agent", "ls"], READ, META),
    // ── Secret writes ──────────────────────────────────────────────────
    row("add NEW", &["add", "NEW"], create(&[("NEW", Audience::Everyone)]), WRITERS)
        .stdin("val-new\n"),
    row(
        "add NEW --group everyone",
        &["add", "NEW", "--group", "everyone"],
        create(&[("NEW", Audience::Everyone)]),
        WRITERS,
    )
    .stdin("val-new\n"),
    row(
        "add NEW --group ops",
        &["add", "NEW", "--group", "ops"],
        create(&[("NEW", Audience::Group("ops"))]),
        OPS,
    )
    .stdin("val-new\n"),
    row(
        "add NEW --group me",
        &["add", "NEW", "--group", "me"],
        create(&[("NEW", Audience::Me)]),
        WRITERS,
    )
    .stdin("val-new\n"),
    row("add SHARED", &["add", "SHARED"], write(&["SHARED"]), WRITERS).stdin("val-upd\n"),
    row("add OPS", &["add", "OPS"], write(&["OPS"]), OPS).stdin("val-upd\n"),
    row(
        "add OPS --group me",
        &["add", "OPS", "--group", "me"],
        write(&["OPS"]),
        WRITERS,
    )
    .stdin("val-upd\n"),
    row(
        "add PRIV",
        &["add", "PRIV"],
        write(&["PRIV"]),
        [
            dr(OTHERS_ONLY),
            dr(OTHERS_ONLY),
            dr(OTHERS_ONLY),
            dr(OTHERS_ONLY),
            A,
            R,
            R,
            R,
            R,
            R,
        ],
    )
    .stdin("val-upd\n"),
    row(
        "add OPS --group everyone",
        &["add", "OPS", "--group", "everyone"],
        Check::Write {
            touches: &["OPS"],
            gains: &[("OPS", "*")],
            losses: &[],
            creates: &[],
        },
        OPS,
    )
    .stdin("val-upd\n"),
    row(
        "generate NEW",
        &["generate", "NEW"],
        create(&[("NEW", Audience::Everyone)]),
        WRITERS,
    ),
    row("generate OPS", &["generate", "OPS"], write(&["OPS"]), OPS),
    // `rm` removes every value of the key, other recipients' overrides too.
    row(
        "rm SHARED",
        &["rm", "SHARED"],
        Check::Write {
            touches: &["SHARED"],
            gains: &[],
            losses: &[("SHARED", "*")],
            creates: &[],
        },
        WRITERS,
    ),
    row(
        "rm OPS",
        &["rm", "OPS"],
        write(&["OPS"]),
        [
            A,
            dr(NONMEMBER_RM),
            A,
            dr(NONMEMBER_RM),
            dr(NONMEMBER_RM),
            R,
            R,
            R,
            R,
            R,
        ],
    ),
    row(
        "describe SHARED",
        &["describe", "SHARED", "described", "--tag", "agents"],
        write(&[]),
        WRITERS,
    ),
    row(
        "describe OPS",
        &["describe", "OPS", "described", "--tag", "agents"],
        write(&[]),
        [
            A,
            dr(NONMEMBER_DESCRIBE),
            A,
            dr(NONMEMBER_DESCRIBE),
            dr(NONMEMBER_DESCRIBE),
            R,
            R,
            R,
            R,
            R,
        ],
    ),
    row(
        "import FILE (new keys)",
        &["import", "new.env"],
        create(&[("NEW", Audience::Everyone)]),
        WRITERS,
    )
        .files(&[("new.env", "NEW=val-new\n")]),
    row(
        "import --force FILE (OPS)",
        &["import", "--force", "ops.env"],
        write(&["OPS"]),
        OPS,
    )
    .files(&[("ops.env", "OPS=val-upd\n")]),
    row("edit SHARED", &["edit", "SHARED"], write(&["SHARED"]), WRITERS).editor(),
    row(
        "edit AGENT_OK (in the grant's scope)",
        &["edit", "AGENT_OK"],
        write(&["AGENT_OK"]),
        WRITERS,
    )
    .editor(),
    row(
        "edit OPS --group ops",
        &["edit", "OPS", "--group", "ops"],
        write(&["OPS"]),
        OPS,
    )
    .editor(),
    // ── Rotation ───────────────────────────────────────────────────────
    row(
        "rotate SHARED --generate",
        &["rotate", "SHARED", "--generate"],
        write(&["SHARED"]),
        WRITERS,
    ),
    row(
        "rotate AGENT_OK --generate (in the grant's scope)",
        &["rotate", "AGENT_OK", "--generate"],
        write(&["AGENT_OK"]),
        WRITERS,
    ),
    row(
        "rotate PRIV --generate",
        &["rotate", "PRIV", "--generate"],
        write(&["PRIV"]),
        [
            dr(OTHERS_ONLY),
            dr(OTHERS_ONLY),
            dr(OTHERS_ONLY),
            dr(OTHERS_ONLY),
            A,
            R,
            R,
            R,
            R,
            R,
        ],
    ),
    row(
        "rotate OPS --generate",
        &["rotate", "OPS", "--generate"],
        write(&["OPS"]),
        OPS,
    ),
    row(
        "rotate --all (piped values)",
        &["rotate", "--all"],
        write(&["SHARED", "OPS", "AGENT_OK", "PRIV"]),
        [
            dr(NO_SHIFT),
            dr(NO_SHIFT),
            dr(NO_SHIFT),
            dr(NO_SHIFT),
            dr(NO_SHIFT),
            R,
            R,
            R,
            R,
            R,
        ],
    )
    .stdin("val-rot-1\nval-rot-2\nval-rot-3\nval-rot-4\n"),
    row(
        "rotate --all --values-from FILE (shared keys)",
        &["rotate", "--all", "--values-from", "vals.env"],
        write(&["SHARED", "AGENT_OK"]),
        WRITERS,
    )
    .files(SHARED_VALUES),
    row(
        "rotate OPS --values-from FILE",
        &["rotate", "OPS", "--values-from", "ops.env"],
        write(&["OPS"]),
        OPS,
    )
    .files(&[("ops.env", "OPS=val-rot-o\n")]),
    // ── Recipients and groups ──────────────────────────────────────────
    row(
        "circle authorize X",
        &["circle", "authorize", "{X}", "--name", "x"],
        Check::Write {
            touches: &[],
            gains: &[("*", "x")],
            losses: &[],
            creates: &[],
        },
        ANY,
    ),
    row(
        "circle authorize X --group ops",
        &["circle", "authorize", "{X}", "--name", "x", "--group", "ops"],
        Check::Write {
            touches: &[],
            gains: &[("*", "x")],
            losses: &[],
            creates: &[],
        },
        OPS,
    ),
    row(
        "circle revoke owner (the creator)",
        &["circle", "revoke", "testuser"],
        Check::Write {
            touches: &[],
            gains: &[],
            // The owner minted the grant, so its key file trusts the owner as
            // a signer: revoking the owner revokes the grant too.
            losses: &[("*", "owner"), ("*", "grant")],
            creates: &[],
        },
        [dr(SELF_REVOKE), CUR, CUR, CUR, CUR, R, R, R, R, R],
    ),
    row(
        "circle revoke spare",
        &["circle", "revoke", "spare"],
        Check::Write {
            touches: &[],
            gains: &[],
            losses: &[("*", "spare")],
            creates: &[],
        },
        ANY,
    ),
    row(
        "circle revoke spare --rotate (piped values)",
        &["circle", "revoke", "spare", "--rotate"],
        Check::Write {
            touches: &["SHARED", "OPS", "AGENT_OK"],
            gains: &[],
            losses: &[("*", "spare")],
            creates: &[],
        },
        [
            CUR,
            dr(NO_SHIFT),
            CUR,
            dr(NO_SHIFT),
            dr(NO_SHIFT),
            R,
            R,
            R,
            R,
            R,
        ],
    )
    .stdin("val-rot-1\nval-rot-2\nval-rot-3\n"),
    row(
        "circle revoke spare --rotate --values-from FILE",
        &["circle", "revoke", "spare", "--rotate", "--values-from", "vals.env"],
        Check::Write {
            touches: &["SHARED", "AGENT_OK"],
            gains: &[],
            losses: &[("*", "spare")],
            creates: &[],
        },
        ANY,
    )
    .files(SHARED_VALUES),
    row("group create NEWG", &["group", "create", "newg"], write(&[]), ANY),
    row(
        "group add ops --member member",
        &["group", "add", "ops", "--member", "member"],
        Check::Write {
            touches: &[],
            gains: &[("OPS", "member")],
            losses: &[],
            creates: &[],
        },
        OPS,
    ),
    row(
        "group rm ops --member spare",
        &["group", "rm", "ops", "--member", "spare"],
        Check::Write {
            touches: &[],
            gains: &[],
            losses: &[("OPS", "spare")],
            creates: &[],
        },
        OPS,
    ),
    row("group rm idle (delete)", &["group", "rm", "idle"], write(&[]), OPS),
    // ── Policy and agents ──────────────────────────────────────────────
    row(
        "policy set --allow-tag other",
        &["policy", "set", "--allow-tag", "other"],
        write(&[]),
        ANY,
    ),
    row("policy clear", &["policy", "clear"], write(&[]), ANY),
    row(
        "agent grant --only SHARED",
        &["agent", "grant", "--name", "newgrant", "--only", "SHARED", "--out", "newgrant.key"],
        Check::Write {
            touches: &[],
            gains: &[("SHARED", "newgrant")],
            losses: &[],
            creates: &[],
        },
        ANY,
    ),
    row(
        "agent init --only AGENT_OK",
        &["agent", "init", "--name", "newgrant", "--only", "AGENT_OK", "--out", "newgrant.key"],
        Check::Write {
            touches: &[],
            gains: &[("AGENT_OK", "newgrant")],
            losses: &[],
            creates: &[],
        },
        ANY,
    ),
    row(
        "agent revoke bot",
        &["agent", "revoke", "bot"],
        Check::Write {
            touches: &[],
            gains: &[],
            losses: &[("*", "grant")],
            creates: &[],
        },
        ANY,
    ),
    row(
        "agent revoke bot --rotate (piped value)",
        &["agent", "revoke", "bot", "--rotate"],
        Check::Write {
            touches: &["AGENT_OK"],
            gains: &[],
            losses: &[("*", "grant")],
            creates: &[],
        },
        ANY,
    )
    .stdin("val-rot-a\n"),
    row(
        "agent connect claude --only AGENT_OK",
        &["agent", "connect", "claude", "--only", "AGENT_OK", "--name", "newgrant"],
        Check::Write {
            touches: &[],
            gains: &[("AGENT_OK", "newgrant")],
            losses: &[],
            creates: &[],
        },
        ANY,
    ),
    row(
        "agent disconnect claude --rotate --name bot",
        &["agent", "disconnect", "claude", "--rotate", "--name", "bot"],
        Check::Write {
            touches: &["AGENT_OK"],
            gains: &[],
            losses: &[("*", "grant")],
            creates: &[],
        },
        ANY,
    )
    .stdin("val-rot-a\n")
    .files(&[(
        ".mcp.json",
        "{\"mcpServers\":{\"murk\":{\"command\":\"murk\",\"args\":[\"mcp\"]}}}\n",
    )]),
    // ── Git ────────────────────────────────────────────────────────────
    row(
        "merge-driver BASE OURS THEIRS",
        &["merge-driver", ".merge/base.murk", ".merge/ours.murk", ".merge/theirs.murk"],
        Check::Write {
            touches: &[],
            gains: &[],
            losses: &[],
            creates: &[("THEIRS", Audience::Everyone)],
        },
        [
            A,
            A,
            A,
            A,
            A,
            R,
            R,
            R,
            dc(MERGE_KEYLESS),
            dc(MERGE_KEYLESS),
        ],
    )
    // Git hands the driver a scratch copy (%A) to write, never the vault.
    .guard(".merge/ours.murk"),
];

/// Surfaces the matrix leaves out, with the reason: they touch no vault,
/// repeat a row above, or can't run under `cargo test`. Rendered under the
/// table.
pub const NOT_IN_MATRIX: &[(&str, &str)] = &[
    (
        "init",
        "creates a vault and key; on an existing vault it only reports whether your key is a recipient and never rewrites the vault, whoever runs it",
    ),
    ("env", "writes `.envrc`, not the vault"),
    (
        "doctor",
        "reads repo files and the public schema with no key",
    ),
    ("recover / restore", "work on the key, not the vault"),
    (
        "setup-merge-driver / completion",
        "configure git and the shell",
    ),
    (
        "authorize / revoke",
        "hidden aliases of `circle authorize` / `circle revoke`, which share their code",
    ),
    (
        "Node and Python bindings",
        "need a native build and run under Node or Python, outside `cargo test`, so this matrix can't drive them; their own suites cover grant and policy checks",
    ),
];
