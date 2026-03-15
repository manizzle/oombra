"""
Shared LLM extraction utility for scrapers.

Priority order (same as bakeoff's base.py):
  1. Azure OpenAI  (AZURE_OPENAI_KEY + AZURE_OPENAI_ENDPOINT)
  2. AWS Bedrock   (AWS_DEFAULT_REGION + AWS profile)
  3. Anthropic     (ANTHROPIC_API_KEY)

Returns parsed JSON or None. Fails gracefully if no LLM is configured.
"""
from __future__ import annotations

import json
import os
import re


def llm_extract(page_text: str, prompt: str) -> dict | list | None:
    """
    Extract structured data from page text using an available LLM.
    Returns parsed JSON (dict or list) or None on failure.
    """
    full_prompt = f"{prompt}\n\nPage content:\n{page_text[:10000]}"
    raw = None

    # -- 1. Azure OpenAI --
    azure_key = os.getenv("AZURE_OPENAI_KEY") or os.getenv("AZURE_API_KEY")
    azure_endpoint = os.getenv("AZURE_OPENAI_ENDPOINT") or os.getenv("AZURE_ENDPOINT")
    azure_deploy = os.getenv("AZURE_OPENAI_DEPLOYMENT", "gpt-4o")
    azure_version = os.getenv("AZURE_OPENAI_API_VERSION", "2024-12-01-preview")

    if azure_key and azure_endpoint:
        try:
            from openai import AzureOpenAI
            client = AzureOpenAI(
                api_key=azure_key,
                azure_endpoint=azure_endpoint,
                api_version=azure_version,
            )
            resp = client.chat.completions.create(
                model=azure_deploy,
                max_completion_tokens=2048,
                messages=[
                    {
                        "role": "system",
                        "content": (
                            "You are a data analyst for a cybersecurity market research platform. "
                            "Extract structured evaluation data from publicly available community "
                            "discussions and product reviews. Output valid JSON only."
                        ),
                    },
                    {"role": "user", "content": full_prompt},
                ],
            )
            raw = resp.choices[0].message.content.strip()
        except Exception:
            pass

    # -- 2. AWS Bedrock (Claude Haiku) --
    if raw is None and os.getenv("AWS_DEFAULT_REGION"):
        try:
            import boto3
            bedrock = boto3.client(
                "bedrock-runtime",
                region_name=os.getenv("AWS_DEFAULT_REGION", "us-east-1"),
            )
            body = json.dumps({
                "anthropic_version": "bedrock-2023-05-31",
                "max_tokens": 2048,
                "messages": [{"role": "user", "content": full_prompt}],
            })
            resp = bedrock.invoke_model(
                modelId=os.getenv("BEDROCK_MODEL_ID", "anthropic.claude-haiku-20240307-v1:0"),
                body=body,
            )
            raw = json.loads(resp["body"].read())["content"][0]["text"].strip()
        except Exception:
            pass

    # -- 3. Anthropic direct --
    if raw is None:
        api_key = os.getenv("ANTHROPIC_API_KEY")
        if not api_key:
            return None
        try:
            import anthropic
            client = anthropic.Anthropic(api_key=api_key)
            msg = client.messages.create(
                model="claude-haiku-4-5-20251001",
                max_tokens=2048,
                messages=[{"role": "user", "content": full_prompt}],
            )
            raw = msg.content[0].text.strip()
        except Exception:
            return None

    if raw is None:
        return None

    # Parse JSON (strip markdown fences if present)
    try:
        raw = re.sub(r"^```json\s*", "", raw)
        raw = re.sub(r"```\s*$", "", raw).strip()
        return json.loads(raw)
    except Exception:
        return None
