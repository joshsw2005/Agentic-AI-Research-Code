import json
import os
import re
from typing import Any, Dict, List

import requests


def _extract_json(content: str) -> Any:
    """Parse JSON from model output, tolerating extra text around it."""
    try:
        return json.loads(content)
    except json.JSONDecodeError:
        pass

    fenced = re.search(r"```(?:json)?\s*(.*?)\s*```", content, re.DOTALL)
    if fenced:
        try:
            return json.loads(fenced.group(1))
        except json.JSONDecodeError:
            pass

    bracket_match = re.search(r"[\{\[].*[\}\]]", content, re.DOTALL)
    if bracket_match:
        try:
            return json.loads(bracket_match.group(0))
        except json.JSONDecodeError:
            pass

    raise json.JSONDecodeError("Could not extract valid JSON from content", content, 0)


def call_llm(messages: List[Dict[str, str]], expect_json: bool = True) -> Any:
    api_key = os.environ.get("LLM_API_KEY")
    api_url = os.environ.get("LLM_API_URL")
    model = os.environ.get("LLM_MODEL")
    if not model:
        raise RuntimeError("Missing LLM_MODEL environment variable")
    timeout = int(os.environ.get("LLM_TIMEOUT_SECONDS", "90"))
    response_format_mode = os.environ.get("LLM_RESPONSE_FORMAT_MODE", "json_object")
    num_ctx = int(os.environ.get("LLM_NUM_CTX", "8192"))
    max_tokens = int(os.environ.get("LLM_MAX_TOKENS", "4096"))

    if not api_key:
        raise RuntimeError("Missing LLM_API_KEY environment variable")
    if not api_url:
        raise RuntimeError("Missing LLM_API_URL environment variable")

    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }

    payload = {
        "model": model,
        "messages": messages,
        "temperature": 0.1,
        "stream": False,
        "max_tokens": max_tokens,
        "options": {"num_ctx": num_ctx},
    }

    if expect_json and response_format_mode != "none":
        payload["format"] = "json"

    response = requests.post(api_url, headers=headers, json=payload, timeout=timeout)
    response.raise_for_status()
    
    # Parse last JSON object from streaming response
    lines = response.text.strip().split('\n')
    data = json.loads(lines[-1])

    try:
        content = data["message"]["content"]
    except (KeyError, IndexError) as exc:
        raise RuntimeError(f"Unexpected LLM response format: {data}") from exc

    if not expect_json:
        return content

    try:
        return _extract_json(content)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"LLM did not return valid JSON: {content}") from exc


def chat_completion(prompt: str) -> Dict[str, Any]:
    return call_llm(
        [
            {"role": "system", "content": "You are a precise application security assistant."},
            {"role": "user", "content": prompt},
        ],
        expect_json=True,
    )
