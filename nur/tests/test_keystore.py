"""Tests for nur.keystore — org-local key management and HMAC-based IOC hashing."""
from __future__ import annotations

import re
from unittest.mock import patch

import pytest

import nur.keystore as ks


@pytest.fixture(autouse=True)
def _isolate_keystore(tmp_path, monkeypatch):
    """Redirect all keystore paths to a temp directory so tests never touch ~/.nur/."""
    monkeypatch.setattr(ks, "_NUR_DIR", tmp_path)
    monkeypatch.setattr(ks, "_KEY_PATH", tmp_path / "key")
    monkeypatch.setattr(ks, "_BUDGET_PATH", tmp_path / "budget.json")
    monkeypatch.setattr(ks, "_PUBKEY_PATH", tmp_path / "id_nur.pub")
    monkeypatch.setattr(ks, "_PRIVKEY_PATH", tmp_path / "id_nur")


# ── get_or_create_key ─────────────────────────────────────────────────


class TestGetOrCreateKey:
    def test_creates_file_and_returns_32_bytes(self, tmp_path):
        key = ks.get_or_create_key()
        assert isinstance(key, bytes)
        assert len(key) == 32
        assert (tmp_path / "key").exists()

    def test_idempotent(self):
        first = ks.get_or_create_key()
        second = ks.get_or_create_key()
        assert first == second


# ── hmac_ioc ──────────────────────────────────────────────────────────


class TestHmacIoc:
    def test_returns_64_char_hex(self):
        result = ks.hmac_ioc("test", secret=b"x" * 32)
        assert len(result) == 64
        assert all(c in "0123456789abcdef" for c in result)

    def test_deterministic_for_same_input(self):
        secret = b"s" * 32
        a = ks.hmac_ioc("8.8.8.8", secret=secret)
        b = ks.hmac_ioc("8.8.8.8", secret=secret)
        assert a == b

    def test_different_secrets_produce_different_hashes(self):
        a = ks.hmac_ioc("8.8.8.8", secret=b"a" * 32)
        b = ks.hmac_ioc("8.8.8.8", secret=b"b" * 32)
        assert a != b

    def test_normalizes_input(self):
        secret = b"k" * 32
        assert ks.hmac_ioc("  Test  ", secret=secret) == ks.hmac_ioc("test", secret=secret)

    def test_with_session_id_differs_from_without(self):
        secret = b"k" * 32
        without = ks.hmac_ioc("evil.com", secret=secret)
        with_session = ks.hmac_ioc("evil.com", secret=secret, session_id="sess-1")
        assert without != with_session


# ── derive_session_key ────────────────────────────────────────────────


class TestDeriveSessionKey:
    def test_different_sessions_produce_different_keys(self):
        base = b"base" * 8  # 32 bytes
        k1 = ks.derive_session_key(base, "session-alpha")
        k2 = ks.derive_session_key(base, "session-beta")
        assert k1 != k2
        assert len(k1) == 32
        assert len(k2) == 32

    def test_deterministic(self):
        base = b"x" * 32
        assert ks.derive_session_key(base, "s1") == ks.derive_session_key(base, "s1")


# ── get_or_create_keypair ─────────────────────────────────────────────


class TestGetOrCreateKeypair:
    def test_creates_files_and_returns_bytes_tuple(self, tmp_path):
        pub, priv = ks.get_or_create_keypair()
        assert isinstance(pub, bytes)
        assert isinstance(priv, bytes)
        assert len(priv) == 32
        assert len(pub) == 32
        assert (tmp_path / "id_nur.pub").exists()
        assert (tmp_path / "id_nur").exists()

    def test_idempotent(self):
        first = ks.get_or_create_keypair()
        second = ks.get_or_create_keypair()
        assert first == second


# ── sign_request ──────────────────────────────────────────────────────


class TestSignRequest:
    def test_returns_timestamp_dot_signature_format(self):
        result = ks.sign_request(b"hello", b"k" * 32)
        assert re.match(r"^\d+\.[0-9a-f]{64}$", result), f"unexpected format: {result}"

    def test_consistent_within_same_second(self):
        key = b"k" * 32
        body = b"same body"
        # time is imported locally inside sign_request, so patch the stdlib module
        import time as time_mod
        original = time_mod.time
        try:
            time_mod.time = lambda: 1700000000.0
            a = ks.sign_request(body, key)
            b = ks.sign_request(body, key)
        finally:
            time_mod.time = original
        assert a == b


# ── get_public_key_hex ────────────────────────────────────────────────


class TestGetPublicKeyHex:
    def test_returns_64_char_hex(self):
        hexstr = ks.get_public_key_hex()
        assert len(hexstr) == 64
        assert all(c in "0123456789abcdef" for c in hexstr)
