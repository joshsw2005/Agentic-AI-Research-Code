import json
import subprocess
from pathlib import Path
from typing import Any, Dict, List


def _find_rule_dirs(rule_root: str) -> List[str]:
    """
    Return all top-level rule directories that contain at least one
    valid Semgrep rule. Skip metadata directories like .github, stats,
    and scripts automatically.
    """
    root = Path(rule_root)
    configs = []

    for d in root.iterdir():
        if not d.is_dir():
            continue

        # Skip known non-rule directories
        if d.name in {"stats", "scripts", ".github"}:
            continue

        # Check whether this directory contains at least one rule file
        valid = False
        for ext in ("*.yml", "*.yaml"):
            for rule in d.rglob(ext):
                try:
                    text = rule.read_text(encoding="utf-8", errors="ignore")
                    if text.lstrip().startswith("rules:"):
                        valid = True
                        break
                except Exception:
                    pass

            if valid:
                break

        if valid:
            configs.append(str(d))

    return configs


def run_semgrep(
    repo_path: str,
    config: str = "/opt/agentic-vuln-ai/semgrep-rules-develop",
) -> Dict[str, Any]:

    rule_dirs = _find_rule_dirs(config)

    if not rule_dirs:
        raise RuntimeError(f"No valid Semgrep rule directories found in {config}")

    cmd = ["semgrep", "scan"]

    for cfg in rule_dirs:
        cmd.extend(["--config", cfg])

    cmd.extend(["--json", repo_path])

    result = subprocess.run(cmd, capture_output=True, text=True, check=False)

    if result.returncode not in (0, 1):
        raise RuntimeError(
            "Semgrep failed.\n"
            f"STDOUT:\n{result.stdout}\n\nSTDERR:\n{result.stderr}"
        )

    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"Failed to parse Semgrep JSON output: {result.stdout[:1000]}") from exc


def run_semgrep_multi(
    file_paths: List[str],
    config: str = "/opt/agentic-vuln-ai/semgrep-rules-develop",
) -> Dict[str, Any]:
    """
    Same as run_semgrep(), but scans multiple files in a single Semgrep
    invocation. Rule loading/startup only happens once instead of once
    per file — this is the dominant cost when verifying many patched
    files individually, since each subprocess call re-parses the full
    ruleset from scratch before scanning even a single small file.
    """
    rule_dirs = _find_rule_dirs(config)

    if not rule_dirs:
        raise RuntimeError(f"No valid Semgrep rule directories found in {config}")

    if not file_paths:
        return {"results": []}

    cmd = ["semgrep", "scan"]

    for cfg in rule_dirs:
        cmd.extend(["--config", cfg])

    cmd.extend(["--json", *file_paths])

    result = subprocess.run(cmd, capture_output=True, text=True, check=False)

    if result.returncode not in (0, 1):
        raise RuntimeError(
            "Semgrep failed.\n"
            f"STDOUT:\n{result.stdout}\n\nSTDERR:\n{result.stderr}"
        )

    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"Failed to parse Semgrep JSON output: {result.stdout[:1000]}") from exc


def _read_code_window(path: Path, start_line: int, end_line: int, padding: int = 4) -> str:
    if not path.exists():
        return ""

    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    start = max(1, start_line - padding)
    end = min(len(lines), end_line + padding)

    snippet = []
    for idx in range(start, end + 1):
        snippet.append(f"{idx}: {lines[idx - 1]}")
    return "\n".join(snippet)


def _resolve_result_path(scan_target: Path, result_path: str) -> Path:
    raw_path = Path(result_path)
    if raw_path.is_absolute():
        return raw_path.resolve()

    candidates = [raw_path]

    if scan_target.is_dir():
        candidates.append(scan_target / raw_path)
        candidates.append(scan_target.parent / raw_path)
    else:
        candidates.append(scan_target.parent / raw_path)

    seen = set()
    for candidate in candidates:
        candidate_key = str(candidate)
        if candidate_key in seen:
            continue
        seen.add(candidate_key)
        if candidate.exists():
            return candidate.resolve()

    return candidates[0].resolve()


def simplify_findings(semgrep_json: Dict[str, Any], repo_path: str) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    scan_target = Path(repo_path).resolve()

    for result in semgrep_json.get("results", []):
        path = result.get("path", "")
        start_line = result.get("start", {}).get("line", 0)
        end_line = result.get("end", {}).get("line", start_line)
        absolute_path = _resolve_result_path(scan_target, path)

        finding = {
            "rule_id": result.get("check_id", ""),
            "message": result.get("extra", {}).get("message", ""),
            "severity": result.get("extra", {}).get("severity", "Unknown"),
            "path": str(absolute_path),
            "start_line": start_line,
            "end_line": end_line,
            "code": _read_code_window(absolute_path, start_line, end_line),
        }
        findings.append(finding)

    return findings
