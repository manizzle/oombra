"""Tests for nur.server.email — SMTP verification email sending."""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from nur.server.email import send_verification_email


class TestSendVerificationEmail:
    def test_returns_false_when_smtp_not_configured(self, monkeypatch):
        monkeypatch.delenv("SMTP_HOST", raising=False)
        monkeypatch.delenv("SMTP_USER", raising=False)
        monkeypatch.delenv("SMTP_PASS", raising=False)
        assert send_verification_email("user@example.com", "https://nur.test/verify?t=abc") is False

    def test_returns_false_when_smtp_pass_missing(self, monkeypatch):
        monkeypatch.setenv("SMTP_HOST", "smtp.example.com")
        monkeypatch.setenv("SMTP_USER", "noreply@example.com")
        monkeypatch.delenv("SMTP_PASS", raising=False)
        assert send_verification_email("user@example.com", "https://nur.test/verify?t=abc") is False

    def test_returns_false_when_smtp_host_missing(self, monkeypatch):
        monkeypatch.delenv("SMTP_HOST", raising=False)
        monkeypatch.setenv("SMTP_USER", "noreply@example.com")
        monkeypatch.setenv("SMTP_PASS", "secret")
        assert send_verification_email("user@example.com", "https://nur.test/verify?t=abc") is False

    def test_constructs_correct_email_with_verify_url(self, monkeypatch):
        monkeypatch.setenv("SMTP_HOST", "smtp.example.com")
        monkeypatch.setenv("SMTP_PORT", "587")
        monkeypatch.setenv("SMTP_USER", "noreply@example.com")
        monkeypatch.setenv("SMTP_PASS", "secret")

        verify_url = "https://nur.saramena.us/verify?token=abc123"
        sent_messages = []

        mock_smtp_instance = MagicMock()
        mock_smtp_instance.__enter__ = MagicMock(return_value=mock_smtp_instance)
        mock_smtp_instance.__exit__ = MagicMock(return_value=False)
        mock_smtp_instance.sendmail = MagicMock(
            side_effect=lambda from_, to_, msg: sent_messages.append((from_, to_, msg))
        )

        with patch("nur.server.email.smtplib.SMTP", return_value=mock_smtp_instance):
            result = send_verification_email("user@test.com", verify_url)

        assert result is True

        # Verify sendmail was called
        assert len(sent_messages) == 1
        from_addr, to_addr, raw_msg = sent_messages[0]
        assert from_addr == "noreply@example.com"
        assert to_addr == "user@test.com"
        # The body is base64-encoded by MIMEText, so decode the full message
        # to check for the verify URL
        import base64
        # Find base64 chunks and decode them to verify URL is present
        decoded_parts = []
        for line in raw_msg.split("\n"):
            line = line.strip()
            try:
                decoded_parts.append(base64.b64decode(line).decode("utf-8", errors="ignore"))
            except Exception:
                decoded_parts.append(line)
        full_decoded = "\n".join(decoded_parts)
        assert verify_url in full_decoded
        # Verify From header (appears in raw headers, not base64)
        assert "nur <noreply@example.com>" in raw_msg

    def test_happy_path_calls_starttls_and_login(self, monkeypatch):
        monkeypatch.setenv("SMTP_HOST", "smtp.example.com")
        monkeypatch.setenv("SMTP_PORT", "587")
        monkeypatch.setenv("SMTP_USER", "noreply@example.com")
        monkeypatch.setenv("SMTP_PASS", "secret")

        mock_smtp_instance = MagicMock()
        mock_smtp_instance.__enter__ = MagicMock(return_value=mock_smtp_instance)
        mock_smtp_instance.__exit__ = MagicMock(return_value=False)

        with patch("nur.server.email.smtplib.SMTP", return_value=mock_smtp_instance) as mock_cls:
            result = send_verification_email("user@test.com", "https://verify.test/t=1")

        assert result is True
        mock_cls.assert_called_once_with("smtp.example.com", 587, timeout=10)
        mock_smtp_instance.ehlo.assert_called_once()
        mock_smtp_instance.starttls.assert_called_once()
        mock_smtp_instance.login.assert_called_once_with("noreply@example.com", "secret")
        mock_smtp_instance.sendmail.assert_called_once()

    def test_returns_false_on_smtp_exception(self, monkeypatch):
        monkeypatch.setenv("SMTP_HOST", "smtp.example.com")
        monkeypatch.setenv("SMTP_USER", "noreply@example.com")
        monkeypatch.setenv("SMTP_PASS", "secret")

        mock_smtp_instance = MagicMock()
        mock_smtp_instance.__enter__ = MagicMock(return_value=mock_smtp_instance)
        mock_smtp_instance.__exit__ = MagicMock(return_value=False)
        mock_smtp_instance.ehlo.side_effect = ConnectionError("connection refused")

        with patch("nur.server.email.smtplib.SMTP", return_value=mock_smtp_instance):
            result = send_verification_email("user@test.com", "https://verify.test/t=1")

        assert result is False
