#!/usr/bin/env bash
# SPDX-FileCopyrightText: murk contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

# Shared setup functions for murk VHS demos and Makefile tests.
# Source this file — do not execute it directly.

# Remove ANSI color codes from stdin.
strip_ansi() {
    local esc=$'\x1b'
    sed "s/${esc}\[[0-9;]*m//g"
}

# Resolve the secret key from MURK_KEY or MURK_KEY_FILE.
resolve_murk_key() {
    if [ -n "$MURK_KEY" ]; then
        echo "$MURK_KEY"
    elif [ -n "$MURK_KEY_FILE" ]; then
        cat "$MURK_KEY_FILE"
    fi
}

# Switch this shell to an inline MURK_KEY. `source .env` exports MURK_KEY_FILE,
# personas later switch with `export MURK_KEY=...`, and murk refuses both set.
use_murk_key() {
    unset MURK_KEY_FILE
    export MURK_KEY="$1"
}

# Print the public key from `murk init` output (strips ANSI codes).
murk_pubkey() {
    murk init 2>&1 | strip_ansi | grep -o "age1[a-z0-9]*"
}

# Create temp dirs for a multi-persona demo.
# Starts a local git daemon so push/pull output shows clean URLs.
# Usage: demo_init_dirs alice bob [carol ...]
# Sets: DEMO_BASE, REMOTE_URL, ALICE_DIR, BOB_DIR, etc.
demo_init_dirs() {
    export DEMO_BASE="$(mktemp -d)"
    local bare="$DEMO_BASE/app.git"

    git init --bare "$bare" >/dev/null 2>&1
    git -C "$bare" symbolic-ref HEAD refs/heads/main

    # Start git daemon for clean push/pull URLs.
    local port=$((10000 + RANDOM % 50000))
    git daemon --reuseaddr --base-path="$DEMO_BASE" \
        --export-all --enable=receive-pack \
        --port="$port" &
    export DAEMON_PID=$!
    export REMOTE_URL="git://localhost:$port/app.git"

    # Wait for daemon to be ready (up to 5s).
    local attempts=0
    while ! git ls-remote "$REMOTE_URL" >/dev/null 2>&1; do
        attempts=$((attempts + 1))
        if [ $attempts -ge 50 ]; then
            echo "error: git daemon failed to start" >&2
            return 1
        fi
        sleep 0.1
    done

    export GIT_AUTHOR_NAME="demo"
    export GIT_AUTHOR_EMAIL="demo@murk"
    export GIT_COMMITTER_NAME="demo"
    export GIT_COMMITTER_EMAIL="demo@murk"

    # Redirect HOME so key files land in the temp dir, not ~/.config/murk/keys.
    export HOME="$DEMO_BASE"

    for name in "$@"; do
        local upper
        upper=$(echo "$name" | tr '[:lower:]' '[:upper:]')
        local dir="$DEMO_BASE/$name"
        mkdir -p "$dir"
        export "${upper}_DIR=$dir"
    done
}

# Initialize Alice's vault with 3 secrets and push to remote.
# Sets: ALICE_KEY
demo_alice_vault() {
    cd "$ALICE_DIR" || return 1
    echo "alice" | murk init >/dev/null 2>&1
    source .env
    export ALICE_KEY="$(resolve_murk_key)"
    use_murk_key "$ALICE_KEY"

    echo "postgres://prod:secret@db.example.com/app" | murk add DATABASE_URL --desc "Production database" >/dev/null 2>&1
    echo "sk-proj-abc123def456" | murk add API_KEY --desc "OpenAI API key" >/dev/null 2>&1
    echo "sk_live_xyz789" | murk add STRIPE_SECRET --desc "Stripe secret key" >/dev/null 2>&1

    git init -b main >/dev/null 2>&1
    git add .murk
    git commit -m "init vault" >/dev/null 2>&1
    git remote add origin "$REMOTE_URL"
    git push -u origin main >/dev/null 2>&1
}

# Clone repo, run murk init, capture key and pubkey.
# Usage: demo_onboard <name>
# Sets: <NAME>_KEY, <NAME>_PUBKEY
demo_onboard() {
    local name="$1"
    local upper
    upper=$(echo "$name" | tr '[:lower:]' '[:upper:]')
    local dir_var="${upper}_DIR"

    cd "${!dir_var}" || return 1
    unset MURK_KEY MURK_KEY_FILE
    git clone "$REMOTE_URL" . >/dev/null 2>&1
    murk init >/dev/null 2>&1
    source .env
    export "${upper}_KEY=$(resolve_murk_key)"
    local key_var="${upper}_KEY"
    use_murk_key "${!key_var}"
    export "${upper}_PUBKEY=$(murk_pubkey)"
}

# Capture key and pubkey from an existing .env (after visible murk init).
# Usage: demo_capture_key <name>
# Sets: <NAME>_KEY, <NAME>_PUBKEY
demo_capture_key() {
    local name="$1"
    local upper
    upper=$(echo "$name" | tr '[:lower:]' '[:upper:]')
    local dir_var="${upper}_DIR"

    cd "${!dir_var}" || return 1
    unset MURK_KEY MURK_KEY_FILE
    source .env
    export "${upper}_KEY=$(resolve_murk_key)"
    local key_var="${upper}_KEY"
    use_murk_key "${!key_var}"
    export "${upper}_PUBKEY=$(murk_pubkey)"
}

# Authorize a persona as Alice.
# Usage: demo_alice_authorize <name>
demo_alice_authorize() {
    local name="$1"
    local upper
    upper=$(echo "$name" | tr '[:lower:]' '[:upper:]')
    local pubkey_var="${upper}_PUBKEY"

    cd "$ALICE_DIR" || return 1
    export MURK_KEY="$ALICE_KEY"
    murk circle authorize "${!pubkey_var}" --name "$name" >/dev/null 2>&1
}

# Git add .murk, commit, and push as Alice.
# Usage: demo_alice_push [commit message]
demo_alice_push() {
    local msg="${1:-update vault}"
    cd "$ALICE_DIR" || return 1
    export MURK_KEY="$ALICE_KEY"
    git add .murk
    git commit -m "$msg" >/dev/null 2>&1
    git push >/dev/null 2>&1
}

# Pull latest as a persona.
# Usage: demo_pull <name>
demo_pull() {
    local name="$1"
    local upper
    upper=$(echo "$name" | tr '[:lower:]' '[:upper:]')
    local dir_var="${upper}_DIR"
    local key_var="${upper}_KEY"

    cd "${!dir_var}" || return 1
    export MURK_KEY="${!key_var}"
    git pull >/dev/null 2>&1
}

# Stop daemon and remove all temp dirs.
demo_cleanup() {
    if [ -n "$DAEMON_PID" ]; then
        kill "$DAEMON_PID" 2>/dev/null
        wait "$DAEMON_PID" 2>/dev/null || true
    fi
    [ -n "$DEMO_BASE" ] && rm -rf "$DEMO_BASE"
}
