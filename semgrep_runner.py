import json
import subprocess
from pathlib import Path
from typing import Any, Dict, List


def run_semgrep(repo_path: str, config: str = "auto") -> Dict[str, Any]:
    cmd = [
        "semgrep",
        "scan",
        "--config",
        config,
        "--json",
        repo_path,
    ]
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
