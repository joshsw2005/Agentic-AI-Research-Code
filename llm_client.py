import json
import os
from typing import Any, Dict, List

import requests


def call_llm(messages: List[Dict[str, str]], expect_json: bool = True) -> Any:
    api_key = os.environ.get("LLM_API_KEY")
    api_url = os.environ.get("LLM_API_URL")
    model = os.environ.get("LLM_MODEL", "Qwen3-Code-Next")
    timeout = int(os.environ.get("LLM_TIMEOUT_SECONDS", "90"))

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
    }

    if expect_json:
        payload["response_format"] = {"type": "json_object"}

    response = requests.post(api_url, headers=headers, json=payload, timeout=timeout)
    response.raise_for_status()
    data = response.json()

    try:
        content = data["choices"][0]["message"]["content"]
    except (KeyError, IndexError) as exc:
        raise RuntimeError(f"Unexpected LLM response format: {data}") from exc

    if not expect_json:
        return content

    try:
        return json.loads(content)
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
