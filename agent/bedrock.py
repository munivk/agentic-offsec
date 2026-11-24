"""
Thin wrapper around AWS Bedrock's Converse API.

This is the agent's "brain" connection. We keep it tiny and in one place so the
rest of the code never has to think about AWS details. The Converse API is used
(not raw InvokeModel) because it gives us a clean, model-agnostic shape for
messages and tool use, and lets us swap models later without touching the agent.
"""
import os
import time
import boto3
from botocore.exceptions import ClientError

# Bedrock occasionally returns transient errors (throttling, or an inference
# profile momentarily reporting a model as unavailable). Retry those with backoff
# so a single flaky call does not crash an entire engagement.
_RETRYABLE = {"ThrottlingException", "ResourceNotFoundException",
              "ModelNotReadyException", "ServiceUnavailableException",
              "InternalServerException"}

# Configurable via environment, with working defaults. The model is a Bedrock
# inference-profile id; the design is model-agnostic, so a different (including an
# internal) model can be swapped in by setting BEDROCK_MODEL_ID.
REGION = os.environ.get("AWS_REGION", "us-east-1")
PROFILE = os.environ.get("AWS_PROFILE")  # None = standard AWS credential chain; use a least-privilege profile
MODEL_ID = os.environ.get("BEDROCK_MODEL_ID", "us.anthropic.claude-sonnet-4-6")


def make_client():
    """One Bedrock runtime client, authenticated via the configured AWS profile."""
    return boto3.Session(profile_name=PROFILE).client(
        "bedrock-runtime", region_name=REGION
    )


def converse(client, messages, system, tools=None, max_tokens=2000, temperature=0.2):
    """
    One turn of conversation with the model.

    messages : the running conversation (list of {role, content})
    system   : the system prompt (list of {"text": ...})
    tools    : optional tool specs; when present the model may ask to call a tool
    Returns the raw Bedrock response (caller inspects stopReason + content).
    """
    kwargs = {
        "modelId": MODEL_ID,
        "messages": messages,
        "system": system,
        "inferenceConfig": {"maxTokens": max_tokens, "temperature": temperature},
    }
    if tools:
        kwargs["toolConfig"] = {"tools": tools}

    last = None
    for attempt in range(5):
        try:
            return client.converse(**kwargs)
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code", "")
            if code not in _RETRYABLE:
                raise
            last = e
            time.sleep(2 ** attempt)  # 1, 2, 4, 8, 16 s
    raise last
