# SPDX-FileCopyrightText: murk contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Shared fixtures for murk Python SDK tests."""

import os
import subprocess
import tempfile
from pathlib import Path

import pytest


@pytest.fixture()
def vault_dir():
    """Create a temp directory with an initialized murk vault and secrets."""
    murk_bin = Path(__file__).resolve().parents[2] / "target" / "release" / "murk"
    if not murk_bin.exists():
        pytest.skip("murk binary not found — run cargo build --release first")

    with tempfile.TemporaryDirectory() as tmpdir:
        env = {**os.environ, "PATH": f"{murk_bin.parent}:{os.environ['PATH']}"}

        # Remove any existing MURK_KEY/MURK_KEY_FILE to avoid interference.
        env.pop("MURK_KEY", None)
        env.pop("MURK_KEY_FILE", None)

        # Init vault.
        subprocess.run(
            [str(murk_bin), "init", "--vault", ".murk"],
            input="testuser\n",
            capture_output=True,
            text=True,
            cwd=tmpdir,
            env=env,
            check=True,
        )

        # Read the key from .env.
        dot_env = Path(tmpdir) / ".env"
        for line in dot_env.read_text().splitlines():
            if line.startswith("export MURK_KEY_FILE="):
                key_file = line.split("=", 1)[1].strip().strip("'\"")
                murk_key = Path(key_file).read_text().strip()
                break
            elif line.startswith("export MURK_KEY="):
                murk_key = line.split("=", 1)[1].strip().strip("'\"")
                break
        else:
            pytest.fail("Could not find MURK_KEY in .env")

        env["MURK_KEY"] = murk_key

        # Add secrets.
        for key, value in [
            ("DATABASE_URL", "postgres://localhost/mydb"),
            ("API_KEY", "sk-test-123"),
            ("STRIPE_SECRET", "sk_live_abc"),
        ]:
            subprocess.run(
                [str(murk_bin), "add", key, "--vault", ".murk"],
                input=f"{value}\n",
                capture_output=True,
                text=True,
                cwd=tmpdir,
                env=env,
                check=True,
            )

        yield {"path": tmpdir, "key": murk_key}


@pytest.fixture()
def agent_vault_dir():
    """A vault with an agent policy and a granted agent identity.

    Lets tests prove the bindings enforce the same policy the CLI applies at
    `agent exec`. Yields the agent's key, the vault path, and a ``tighten``
    callable that drops the agent's tag from the policy (the agent's scoped
    ciphertext lingers, so the crypto still works but policy should now refuse).
    """
    murk_bin = Path(__file__).resolve().parents[2] / "target" / "release" / "murk"
    if not murk_bin.exists():
        pytest.skip("murk binary not found — run cargo build --release first")

    with tempfile.TemporaryDirectory() as tmpdir:
        env = {**os.environ, "PATH": f"{murk_bin.parent}:{os.environ['PATH']}"}
        env.pop("MURK_KEY", None)
        env.pop("MURK_KEY_FILE", None)

        def run(args, stdin=""):
            subprocess.run(
                [str(murk_bin), *args, "--vault", ".murk"],
                input=stdin,
                capture_output=True,
                text=True,
                cwd=tmpdir,
                env=env,
                check=True,
            )

        run(["init"], "agentowner\n")

        dot_env = Path(tmpdir) / ".env"
        for line in dot_env.read_text().splitlines():
            if line.startswith("export MURK_KEY_FILE="):
                key_file = line.split("=", 1)[1].strip().strip("'\"")
                op_key = Path(key_file).read_text().strip()
                break
            elif line.startswith("export MURK_KEY="):
                op_key = line.split("=", 1)[1].strip().strip("'\"")
                break
        else:
            pytest.fail("Could not find MURK_KEY in .env")

        env["MURK_KEY"] = op_key
        run(["add", "AGENT_DB"], "postgres://agent\n")
        run(["add", "PROD_DB"], "postgres://prod\n")
        run(["describe", "AGENT_DB", "agent db", "--tag", "agents"])
        run(["describe", "PROD_DB", "prod db", "--tag", "prod"])
        run(["policy", "set", "--allow-tag", "agents"])
        run(["agent", "grant", "--name", "codex", "--only", "AGENT_DB", "--out", "agent.key"])
        agent_key = (Path(tmpdir) / "agent.key").read_text().strip()

        def tighten():
            run(["policy", "set", "--allow-tag", "prod"])

        yield {
            "vault": str(Path(tmpdir) / ".murk"),
            "agent_key": agent_key,
            "tighten": tighten,
        }
