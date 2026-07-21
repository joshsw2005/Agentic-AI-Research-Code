"""Independent LLM-based vulnerability detector.

Runs alongside Semgrep (not on its output) to catch issues that rule-based
static analysis is structurally unable to find: business-logic flaws,
missing authorization checks, insecure design choices, etc.

Output findings are shaped to match semgrep_runner.simplify_findings() output
so both sources can be merged by combine_findings.py without special-casing.
"""

import os
from pathlib import Path
from typing import Any, Dict, List

from llm_client import call_llm
from prompts import build_detection_prompt, build_verify_prompt

# Source file extensions worth sending to the LLM detector.
SCANNABLE_EXTENSIONS = {
    # Python
    ".py",
    # JavaScript / TypeScript
    ".js", ".jsx", ".ts", ".tsx",
    # Java
    ".java",
    # C / C++
    ".c", ".h", ".cpp", ".cc", ".cxx", ".hpp",
    # Other
    ".php", ".rb", ".go", ".cs",
}

# Skip obvious noise so you're not burning LLM calls on dependencies/build output.
SKIP_DIR_NAMES = {
    ".git", ".cache",
    "node_modules", "venv", ".venv", "__pycache__",
    "dist", "build", "target", "vendor", "out", "bin", "obj",
}


def _iter_source_files(scan_target: Path) -> List[Path]:
    if scan_target.is_file():
        return [scan_target] if scan_target.suffix in SCANNABLE_EXTENSIONS else []

    files = []
    for path in scan_target.rglob("*"):
        if not path.is_file():
            continue
        if path.suffix not in SCANNABLE_EXTENSIONS:
            continue
        if any(part in SKIP_DIR_NAMES for part in path.parts):
            continue
        files.append(path)
    return files


def _number_lines(source_code: str) -> str:
    lines = source_code.splitlines()
    width = len(str(len(lines)))
    return "\n".join(f"{str(i).rjust(width)}: {line}" for i, line in enumerate(lines, start=1))


def _extract_code_window(path: Path, start_line: int, end_line: int, padding: int = 4) -> str:
    if not path.exists():
        return ""
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    start = max(1, start_line - padding)
    end = min(len(lines), end_line + padding)
    return "\n".join(f"{i}: {lines[i - 1]}" for i in range(start, end + 1))


def detect_file(path: Path, min_confidence: float = 0.0) -> List[Dict[str, Any]]:
    """Run the LLM detector on a single file. Returns findings shaped like
    semgrep_runner.simplify_findings() output, tagged with source='llm_detector'."""
    try:
        source_code = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []

    if not source_code.strip():
        return []

    prompt = build_detection_prompt(str(path), _number_lines(source_code))

    try:
        response = call_llm(
            [
                {"role": "system", "content": "You are a precise application security assistant."},
                {"role": "user", "content": prompt},
            ],
            expect_json=True,
        )
    except RuntimeError as exc:
        print(f"[!] LLM detector failed on {path}: {exc}")
        return []

    raw_findings = response.get("findings", []) if isinstance(response, dict) else []
    findings: List[Dict[str, Any]] = []

    for item in raw_findings:
        confidence = float(item.get("confidence", 0.0) or 0.0)
        if confidence < min_confidence:
            continue

        start_line = int(item.get("start_line", 0) or 0)
        end_line = int(item.get("end_line", start_line) or start_line)

        findings.append({
            "rule_id": f"llm-detector.{item.get('vulnerability_type', 'unknown').lower().replace(' ', '-')}",
            "message": item.get("explanation", ""),
            "severity": item.get("severity", "Unknown"),
            "path": str(path.resolve()),
            "start_line": start_line,
            "end_line": end_line,
            "code": _extract_code_window(path, start_line, end_line),
            "source": "llm_detector",
            "llm_detector_metadata": {
                "vulnerability_type": item.get("vulnerability_type", ""),
                "cwe": item.get("cwe", ""),
                "impact": item.get("impact", ""),
                "exploit_scenario": item.get("exploit_scenario", ""),
                "remediation": item.get("remediation", ""),
                "confidence": confidence,
            },
        })

    return findings


def verify_finding(path: Path, original_finding: Dict[str, Any]) -> Dict[str, Any]:
    """
    Check whether ONE specific pre-patch finding still applies to a patched
    file. Unlike detect_file (which hunts for any issue and can hallucinate
    one to comply), this can only confirm or deny the ONE issue it's given,
    and any "still vulnerable" claim must be backed by a verbatim quote from
    the file -- if the quote doesn't actually appear in the file, the claim
    is rejected outright rather than trusted.

    original_finding should carry at least: vulnerability_type, cwe, message
    (the same shape as an llm_analysis dict / detect_file finding).
    """
    try:
        source_code = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return {"still_vulnerable": False, "quoted_line": "", "explanation": "file not found"}

    prompt = build_verify_prompt(str(path), _number_lines(source_code), original_finding)

    try:
        response = call_llm(
            [
                {"role": "system", "content": "You are a precise application security assistant."},
                {"role": "user", "content": prompt},
            ],
            expect_json=True,
        )
    except RuntimeError as exc:
        print(f"[!] LLM verify failed on {path}: {exc}")
        return {"still_vulnerable": False, "quoted_line": "", "explanation": f"verify call failed: {exc}"}

    if not isinstance(response, dict):
        return {"still_vulnerable": False, "quoted_line": "", "explanation": "malformed response"}

    quoted = response.get("quoted_line", "") or ""
    still_vuln = bool(response.get("still_vulnerable", False))

    # Grounding check: reject the claim outright if the "quoted" line isn't
    # actually present in the file. This is what stops hallucinated findings
    # (e.g. a verifier claiming a fixed format-string bug is still present)
    # from reaching the report.
    if still_vuln and quoted.strip() and quoted.strip() not in source_code:
        still_vuln = False
        response["explanation"] = (
            "Rejected: quoted_line did not match file content verbatim "
            "(likely hallucinated). " + response.get("explanation", "")
        )
    elif still_vuln and not quoted.strip():
        # No quote at all but claims still vulnerable -- can't be trusted
        # per the prompt's own rules, so reject defensively.
        still_vuln = False
        response["explanation"] = (
            "Rejected: still_vulnerable=true but no quoted_line was provided. "
            + response.get("explanation", "")
        )

    return {
        "still_vulnerable": still_vuln,
        "quoted_line": quoted,
        "explanation": response.get("explanation", ""),
    }


def run_llm_detector(
    scan_target: Path,
    min_confidence: float = 0.0,
    max_files: int = 0,
) -> List[Dict[str, Any]]:
    """Run the LLM detector across every scannable file under scan_target.

    max_files=0 means no limit. Use it while testing so you don't burn
    minutes/tokens scanning an entire benchmark repo file-by-file.
    """
    files = _iter_source_files(scan_target)
    if max_files:
        files = files[:max_files]

    all_findings: List[Dict[str, Any]] = []
    for idx, path in enumerate(files, start=1):
        print(f"[+] LLM detector scanning {idx}/{len(files)}: {path}")
        all_findings.extend(detect_file(path, min_confidence=min_confidence))

    return all_findings
