# SPDX-FileCopyrightText: murk contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

"""The binding applies the same trust rules as the CLI.

Each scenario builds vaults with the murk binary, one HOME per person (the
trust pin lives under HOME), and checks that ``murk.load`` accepts or refuses
exactly as ``murk get`` does, with the same message.
"""

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

import murk

MURK_BIN = Path(__file__).resolve().parents[2] / "target" / "release" / "murk"
CONTEXT_VARS = (
    "MURK_KEY",
    "MURK_KEY_FILE",
    "MURK_VAULT",
    "MURK_AGENT",
    "MURK_STRICT",
    "MURK_NO_SIGNER_PIN",
    "MURK_TRUSTED_SIGNERS",
    "CI",
)


@pytest.fixture(autouse=True)
def _binary():
    if not MURK_BIN.exists():
        pytest.skip("murk binary not found — run cargo build --release first")


@pytest.fixture()
def clean_env(monkeypatch):
    """The binding reads these from the process environment: start without any."""
    for var in CONTEXT_VARS:
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("NO_COLOR", "1")
    return monkeypatch


class Person:
    """One person's machine: their own HOME, so their own trust pin."""

    def __init__(self, base: Path, name: str):
        self.home = base / f"{name}-home"
        self.home.mkdir()

    def env(self, **extra):
        env = {k: v for k, v in os.environ.items() if k not in CONTEXT_VARS}
        env.update(HOME=str(self.home), NO_COLOR="1", **extra)
        return env

    def murk(self, cwd: Path, *args, stdin="", check=True, **extra):
        return subprocess.run(
            [str(MURK_BIN), *args],
            input=stdin,
            capture_output=True,
            text=True,
            cwd=cwd,
            env=self.env(**extra),
            check=check,
        )

    def key_file(self) -> Path:
        return next((self.home / ".config" / "murk" / "keys").iterdir())

    def signer_entry(self, cwd: Path) -> str:
        """This person's trusted-signer entry (`age1…:<verifying key>`)."""
        out = self.murk(cwd, "trust", "--print-key", MURK_KEY_FILE=str(self.key_file()))
        return out.stdout.strip()

    def pubkey(self, cwd: Path) -> str:
        return self.signer_entry(cwd).split(":", 1)[0]

    def use(self, mp, repo: Path, **extra):
        """Run the binding as this person in `repo`: their HOME, plus `extra`."""
        mp.chdir(repo)
        mp.setenv("HOME", str(self.home))
        for k, v in extra.items():
            mp.setenv(k, v)


def alice_repo(base: Path):
    """Alice's repo, a signed vault holding DB_URL=prod-db, pinned on her machine."""
    alice = Person(base, "alice")
    repo = base / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-q", "-b", "main"], cwd=repo, check=True)
    alice.murk(repo, "init", stdin="alice\n")
    alice.murk(repo, "add", "DB_URL", stdin="prod-db\n")
    return alice, repo


def mallory_vault(base: Path, alice_pk: str) -> Path:
    """Mallory's own vault, listing Alice as a recipient, signed by Mallory."""
    mallory = Person(base, "mallory")
    forge = base / "forge"
    forge.mkdir()
    mallory.murk(forge, "init", stdin="mallory\n")
    mallory.murk(forge, "circle", "authorize", alice_pk, "--name", "alice")
    mallory.murk(forge, "add", "DB_URL", stdin="postgres://attacker\n")
    return forge / ".murk"


def strip_signature(vault: Path):
    data = json.loads(vault.read_text())
    data.pop("sig", None)
    vault.write_text(json.dumps(data, indent=2))


def refusal() -> str:
    with pytest.raises(murk.TrustError) as exc:
        murk.load()
    return str(exc.value)


def assert_same_as_cli(message: str, cli: subprocess.CompletedProcess):
    """The CLI refused with this exact message: its first line, then hints."""
    first, *rest = message.splitlines()
    assert cli.returncode != 0
    assert cli.stdout == ""
    assert cli.stderr == f"✕ {first}\n" + "".join(f"  hint {h}\n" for h in rest)


def test_trust_error_is_a_runtime_error():
    assert issubclass(murk.TrustError, RuntimeError)


def test_forged_unsigned_vault_is_refused(tmp_path, clean_env):
    alice, repo = alice_repo(tmp_path)
    forged = mallory_vault(tmp_path, alice.pubkey(repo))
    strip_signature(forged)
    shutil.copy(forged, repo / ".murk")
    laptop = Person(tmp_path, "alice-laptop")
    laptop.use(clean_env, repo, MURK_KEY_FILE=str(alice.key_file()))

    message = refusal()

    assert "is unsigned" in message
    for one_liner in (lambda: murk.get("DB_URL", ".murk"), lambda: murk.export_all(".murk")):
        with pytest.raises(murk.TrustError):
            one_liner()
    cli = laptop.murk(repo, "get", "DB_URL", check=False, MURK_KEY_FILE=str(alice.key_file()))
    assert_same_as_cli(message, cli)


def test_self_enrolled_signer_is_refused_on_a_pinned_machine(tmp_path, clean_env):
    alice, repo = alice_repo(tmp_path)
    forged = mallory_vault(tmp_path, alice.pubkey(repo))
    shutil.copy(forged, repo / ".murk")
    pins = alice.home / ".config" / "murk" / "signer-pins"
    before = {p.name: p.read_bytes() for p in pins.glob("*.json")}
    alice.use(clean_env, repo, MURK_KEY_FILE=str(alice.key_file()))

    message = refusal()

    assert "not a trusted signer" in message
    assert {p.name: p.read_bytes() for p in pins.glob("*.json")} == before
    cli = alice.murk(repo, "get", "DB_URL", check=False)
    assert_same_as_cli(message, cli)


def test_vault_is_accepted_after_the_trust_step(tmp_path, clean_env):
    alice, repo = alice_repo(tmp_path)
    laptop = Person(tmp_path, "alice-laptop")
    laptop.use(clean_env, repo, MURK_KEY_FILE=str(alice.key_file()))

    message = refusal()
    assert "not trusted on this machine yet" in message

    laptop.murk(repo, "trust", "--yes", MURK_KEY_FILE=str(alice.key_file()))
    vault = murk.load(".murk")
    assert vault.get("DB_URL") == "prod-db"
    assert vault.warnings == []


def grant_key(alice: Person, repo: Path) -> str:
    alice.murk(repo, "agent", "grant", "--name", "ci", "--only", "DB_URL", "--out", "agent.key")
    return (repo / "agent.key").read_text()


def test_grant_reads_through_its_key_file_anchor(tmp_path, clean_env):
    alice, repo = alice_repo(tmp_path)
    key = grant_key(alice, repo)
    assert key.startswith("# murk-trusted-signer: ")
    runner = Person(tmp_path, "runner")
    runner.use(clean_env, repo, MURK_KEY=key)

    assert murk.get("DB_URL", ".murk") == "prod-db"
    # A grant never touches the pin.
    assert not (runner.home / ".config" / "murk" / "signer-pins").exists()


def test_grant_without_its_anchor_is_refused_with_the_re_mint_message(tmp_path, clean_env):
    alice, repo = alice_repo(tmp_path)
    bare = "\n".join(
        line for line in grant_key(alice, repo).splitlines() if not line.startswith("#")
    )
    runner = Person(tmp_path, "runner")
    runner.use(clean_env, repo, MURK_KEY=bare)

    message = refusal()

    assert "re-mint the grant" in message
    cli = runner.murk(repo, "get", "DB_URL", check=False, MURK_KEY=bare)
    assert_same_as_cli(message, cli)
    # MURK_TRUSTED_SIGNERS is the other anchor a grant can use.
    clean_env.setenv("MURK_TRUSTED_SIGNERS", alice.signer_entry(repo))
    assert murk.get("DB_URL", ".murk") == "prod-db"


@pytest.mark.skipif(shutil.which("ssh-keygen") is None, reason="needs ssh-keygen")
def test_unsigned_vault_loaded_by_a_key_that_cannot_sign_carries_the_cli_warning(
    tmp_path, clean_env
):
    alice, repo = alice_repo(tmp_path)
    rsa = tmp_path / "rsa"
    subprocess.run(
        ["ssh-keygen", "-q", "-t", "rsa", "-b", "2048", "-N", "", "-f", str(rsa)],
        check=True,
    )
    rsa_pub = " ".join(Path(f"{rsa}.pub").read_text().split()[:2])
    alice.murk(repo, "circle", "authorize", rsa_pub, "--name", "rsa-dev", "--allow-ssh-rsa")
    dev = Person(tmp_path, "rsa-dev")
    dev.murk(repo, "trust", "--yes", MURK_KEY_FILE=str(rsa))
    dev.murk(repo, "add", "DB_URL", stdin="from-rsa\n", MURK_KEY_FILE=str(rsa))
    dev.use(clean_env, repo, MURK_KEY_FILE=str(rsa))

    vault = murk.load(".murk")

    assert vault.get("DB_URL") == "from-rsa"
    assert len(vault.warnings) == 1
    assert "vault is unsigned and your key cannot sign" in vault.warnings[0]
    cli = dev.murk(repo, "get", "DB_URL", MURK_KEY_FILE=str(rsa))
    assert vault.warnings[0] in cli.stderr
    # On Alice's machine the same vault is a stripped signature: refused.
    alice.use(clean_env, repo, MURK_KEY_FILE=str(alice.key_file()))
    assert "is now unsigned" in refusal()
