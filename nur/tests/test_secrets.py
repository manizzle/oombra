"""Tests for nur.secrets — AWS Secrets Manager integration."""
from __future__ import annotations

import json
import os
from unittest.mock import MagicMock, patch

import pytest

from nur.secrets import load_secrets


class TestLoadSecrets:
    def test_returns_empty_dict_when_arn_not_set(self, monkeypatch):
        monkeypatch.delenv("NUR_SECRETS_ARN", raising=False)
        result = load_secrets()
        assert result == {}

    def test_returns_empty_dict_when_arn_is_empty(self, monkeypatch):
        monkeypatch.setenv("NUR_SECRETS_ARN", "")
        result = load_secrets()
        assert result == {}

    def test_returns_empty_dict_when_boto3_not_installed(self, monkeypatch):
        monkeypatch.setenv("NUR_SECRETS_ARN", "arn:aws:secretsmanager:us-west-2:123:secret:test")
        with patch.dict("sys.modules", {"boto3": None}):
            # Force ImportError on import boto3
            import importlib
            import builtins
            original_import = builtins.__import__

            def mock_import(name, *args, **kwargs):
                if name == "boto3":
                    raise ImportError("mocked: no boto3")
                return original_import(name, *args, **kwargs)

            monkeypatch.setattr(builtins, "__import__", mock_import)
            result = load_secrets()
        assert result == {}

    def test_sets_env_vars_when_secrets_loaded(self, monkeypatch):
        monkeypatch.setenv("NUR_SECRETS_ARN", "arn:aws:secretsmanager:us-west-2:123:secret:test")
        # Clean up any leftover env vars from a previous run
        monkeypatch.delenv("TEST_SECRET_KEY", raising=False)
        monkeypatch.delenv("TEST_SECRET_TWO", raising=False)

        secret_payload = {"TEST_SECRET_KEY": "value1", "TEST_SECRET_TWO": "value2"}
        mock_client = MagicMock()
        mock_client.get_secret_value.return_value = {
            "SecretString": json.dumps(secret_payload)
        }
        mock_boto3 = MagicMock()
        mock_boto3.client.return_value = mock_client

        with patch.dict("sys.modules", {"boto3": mock_boto3}):
            result = load_secrets()

        assert len(result) == 2
        assert os.environ.get("TEST_SECRET_KEY") == "value1"
        assert os.environ.get("TEST_SECRET_TWO") == "value2"

        # Values in result dict are masked
        assert result["TEST_SECRET_KEY"] == "***"
        assert result["TEST_SECRET_TWO"] == "***"

        # Cleanup
        monkeypatch.delenv("TEST_SECRET_KEY", raising=False)
        monkeypatch.delenv("TEST_SECRET_TWO", raising=False)

    def test_skips_non_string_values(self, monkeypatch):
        monkeypatch.setenv("NUR_SECRETS_ARN", "arn:aws:secretsmanager:us-west-2:123:secret:test")
        monkeypatch.delenv("ONLY_STR", raising=False)

        secret_payload = {"ONLY_STR": "ok", "NULL_VAL": None, "INT_VAL": 42}
        mock_client = MagicMock()
        mock_client.get_secret_value.return_value = {
            "SecretString": json.dumps(secret_payload)
        }
        mock_boto3 = MagicMock()
        mock_boto3.client.return_value = mock_client

        with patch.dict("sys.modules", {"boto3": mock_boto3}):
            result = load_secrets()

        # Only the string value should be loaded
        assert len(result) == 1
        assert "ONLY_STR" in result
        monkeypatch.delenv("ONLY_STR", raising=False)
