# SPDX-FileCopyrightText: murk contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Tests for the murk Python SDK."""

import os

import pytest

import murk


class TestLoad:
    def test_load_vault(self, vault_dir):
        os.chdir(vault_dir["path"])
        os.environ["MURK_KEY"] = vault_dir["key"]

        vault = murk.load()
        assert vault is not None

    def test_load_with_explicit_path(self, vault_dir):
        os.environ["MURK_KEY"] = vault_dir["key"]
        vault_path = os.path.join(vault_dir["path"], ".murk")

        vault = murk.load(vault_path)
        assert vault is not None

    def test_load_missing_vault_raises(self, vault_dir):
        os.environ["MURK_KEY"] = vault_dir["key"]

        try:
            murk.load("/nonexistent/.murk")
            assert False, "Expected RuntimeError"
        except RuntimeError:
            pass

    def test_load_missing_key_raises(self, tmp_path):
        # Use a clean dir with no .murk or .env to avoid key auto-discovery.
        os.chdir(tmp_path)
        os.environ.pop("MURK_KEY", None)
        os.environ.pop("MURK_KEY_FILE", None)

        try:
            murk.load()
            assert False, "Expected RuntimeError"
        except RuntimeError:
            pass


class TestGet:
    def test_get_existing_key(self, vault_dir):
        os.chdir(vault_dir["path"])
        os.environ["MURK_KEY"] = vault_dir["key"]

        vault = murk.load()
        assert vault.get("DATABASE_URL") == "postgres://localhost/mydb"
        assert vault.get("API_KEY") == "sk-test-123"

    def test_get_missing_key_returns_none(self, vault_dir):
        os.chdir(vault_dir["path"])
        os.environ["MURK_KEY"] = vault_dir["key"]

        vault = murk.load()
        assert vault.get("NONEXISTENT") is None

    def test_get_oneliner(self, vault_dir):
        os.chdir(vault_dir["path"])
        os.environ["MURK_KEY"] = vault_dir["key"]

        assert murk.get("DATABASE_URL") == "postgres://localhost/mydb"

    def test_get_oneliner_missing_returns_none(self, vault_dir):
        os.chdir(vault_dir["path"])
        os.environ["MURK_KEY"] = vault_dir["key"]

        assert murk.get("NONEXISTENT") is None


class TestExport:
    def test_export_returns_all_secrets(self, vault_dir):
        os.chdir(vault_dir["path"])
        os.environ["MURK_KEY"] = vault_dir["key"]

        vault = murk.load()
        secrets = vault.export()

        assert isinstance(secrets, dict)
        assert secrets["DATABASE_URL"] == "postgres://localhost/mydb"
        assert secrets["API_KEY"] == "sk-test-123"
        assert secrets["STRIPE_SECRET"] == "sk_live_abc"
        assert len(secrets) == 3

    def test_export_all_oneliner(self, vault_dir):
        os.chdir(vault_dir["path"])
        os.environ["MURK_KEY"] = vault_dir["key"]

        secrets = murk.export_all()
        assert len(secrets) == 3
        assert secrets["API_KEY"] == "sk-test-123"


class TestVaultMethods:
    def test_keys(self, vault_dir):
        os.chdir(vault_dir["path"])
        os.environ["MURK_KEY"] = vault_dir["key"]

        vault = murk.load()
        keys = vault.keys()
        assert sorted(keys) == ["API_KEY", "DATABASE_URL", "STRIPE_SECRET"]

    def test_len(self, vault_dir):
        os.chdir(vault_dir["path"])
        os.environ["MURK_KEY"] = vault_dir["key"]

        vault = murk.load()
        assert len(vault) == 3

    def test_contains(self, vault_dir):
        os.chdir(vault_dir["path"])
        os.environ["MURK_KEY"] = vault_dir["key"]

        vault = murk.load()
        assert "DATABASE_URL" in vault
        assert "NONEXISTENT" not in vault

    def test_getitem(self, vault_dir):
        os.chdir(vault_dir["path"])
        os.environ["MURK_KEY"] = vault_dir["key"]

        vault = murk.load()
        assert vault["API_KEY"] == "sk-test-123"

    def test_getitem_missing_raises(self, vault_dir):
        os.chdir(vault_dir["path"])
        os.environ["MURK_KEY"] = vault_dir["key"]

        vault = murk.load()
        try:
            _ = vault["NONEXISTENT"]
            assert False, "Expected RuntimeError"
        except RuntimeError:
            pass

    def test_repr(self, vault_dir):
        os.chdir(vault_dir["path"])
        os.environ["MURK_KEY"] = vault_dir["key"]

        vault = murk.load()
        r = repr(vault)
        assert "3 secrets" in r
        assert "1 recipients" in r


class TestAgentPolicy:
    def test_agent_reads_allowed_key(self, agent_vault_dir):
        os.environ["MURK_KEY"] = agent_vault_dir["agent_key"]
        vault = murk.load(agent_vault_dir["vault"])
        assert vault.get("AGENT_DB") == "postgres://agent"

    def test_agent_cannot_read_out_of_scope_key(self, agent_vault_dir):
        # Not a recipient of PROD_DB — the crypto boundary returns None.
        os.environ["MURK_KEY"] = agent_vault_dir["agent_key"]
        vault = murk.load(agent_vault_dir["vault"])
        assert vault.get("PROD_DB") is None

    def test_agent_export_only_scoped_allowed_keys(self, agent_vault_dir):
        os.environ["MURK_KEY"] = agent_vault_dir["agent_key"]
        vault = murk.load(agent_vault_dir["vault"])
        assert vault.export() == {"AGENT_DB": "postgres://agent"}

    def test_tightened_policy_blocks_get(self, agent_vault_dir):
        agent_vault_dir["tighten"]()
        os.environ["MURK_KEY"] = agent_vault_dir["agent_key"]
        vault = murk.load(agent_vault_dir["vault"])
        with pytest.raises(RuntimeError, match="policy forbids"):
            vault.get("AGENT_DB")

    def test_tightened_policy_blocks_export(self, agent_vault_dir):
        agent_vault_dir["tighten"]()
        os.environ["MURK_KEY"] = agent_vault_dir["agent_key"]
        vault = murk.load(agent_vault_dir["vault"])
        with pytest.raises(RuntimeError, match="policy forbids"):
            vault.export()


class TestHasIdentity:
    def test_has_identity_true(self, vault_dir):
        os.environ["MURK_KEY"] = vault_dir["key"]
        assert murk.has_identity() is True

    def test_has_identity_false(self, tmp_path):
        os.environ.pop("MURK_KEY", None)
        os.environ.pop("MURK_KEY_FILE", None)
        # Use a clean dir with no .murk or .env to avoid auto-discovery.
        os.chdir(tmp_path)
        assert murk.has_identity() is False
