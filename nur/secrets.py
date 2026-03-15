"""
Secrets management — load secrets from AWS Secrets Manager or environment variables.

Usage:
    from nur.secrets import load_secrets
    load_secrets()  # call once at startup — populates os.environ from AWS SM

Priority:
    1. AWS Secrets Manager (if NUR_SECRETS_ARN is set)
    2. Environment variables / .env file

The secret in AWS SM should be a JSON object:
    {
        "NUR_API_KEY": "...",
        "POSTGRES_PASSWORD": "...",
        "SMTP_PASS": "...",
        "ABUSEIPDB_API_KEY": "...",
        "PULSEDIVE_API_KEY": "...",
        ...
    }
"""
from __future__ import annotations

import json
import os


def load_secrets() -> dict[str, str]:
    """Load secrets from AWS Secrets Manager if configured, else return empty dict.

    Sets os.environ for each secret key so the rest of the app just reads env vars.
    """
    arn = os.environ.get("NUR_SECRETS_ARN", "")
    if not arn:
        return {}

    try:
        import boto3
        region = os.environ.get("AWS_DEFAULT_REGION", "us-west-2")
        client = boto3.client("secretsmanager", region_name=region)
        response = client.get_secret_value(SecretId=arn)
        secrets = json.loads(response["SecretString"])

        loaded = {}
        for key, value in secrets.items():
            if value and isinstance(value, str):
                os.environ[key] = value
                loaded[key] = "***"  # don't log actual values

        print(f"[nur] Loaded {len(loaded)} secrets from AWS Secrets Manager")
        return loaded

    except ImportError:
        print("[nur] boto3 not installed — skipping AWS Secrets Manager")
        return {}
    except Exception as e:
        print(f"[nur] Failed to load secrets from AWS SM: {e}")
        return {}
