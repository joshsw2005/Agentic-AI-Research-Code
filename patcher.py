import shutil
from pathlib import Path
from typing import Dict, List

from llm_client import call_llm
from prompts import build_patch_prompt, build_patch_code_prompt


def group_findings_by_file(analyzed_findings: List[Dict]) -> Dict[str, List[Dict]]:
    grouped: Dict[str, List[Dict]] = {}
    for item in analyzed_findings:
        llm_analysis = item.get("llm_analysis", {})
        if not llm_analysis.get("is_true_positive", False):
            continue

        file_path = item["finding"]["path"]
        grouped.setdefault(file_path, []).append(
            {
                "rule_id": item["finding"].get("rule_id", ""),
                "message": item["finding"].get("message", ""),
                "severity": item["finding"].get("severity", ""),
                "start_line": item["finding"].get("start_line", 0),
                "end_line": item["finding"].get("end_line", 0),
                "llm_analysis": llm_analysis,
            }
        )
    return grouped


def create_patched_copy(scan_target: Path, patched_root: Path) -> Path:
    patched_root.mkdir(parents=True, exist_ok=True)
    destination = patched_root / scan_target.name

    if destination.exists():
        if destination.is_dir():
            shutil.rmtree(destination)
        else:
            destination.unlink()

    if scan_target.is_dir():
        shutil.copytree(scan_target, destination)
    else:
        shutil.copy2(scan_target, destination)

    return destination


def _call_metadata(messages: list) -> Dict:
    """Call LLM expecting a JSON metadata dict (no patched code inside)."""
    response = call_llm(messages, expect_json=True)
    if not isinstance(response, dict):
        raise RuntimeError(
            f"Metadata call returned unexpected type: {type(response).__name__}"
        )
    return response


def _call_patch_code(messages: list) -> str:
    """
    Call LLM expecting raw patched source code as plain text.

    Returning code as plain text (not embedded in JSON) avoids the common
    failure where the model mis-escapes newlines/quotes inside a JSON string,
    producing unparseable output and silently losing the patch.
    """
    raw = call_llm(messages, expect_json=False)
    if not isinstance(raw, str):
        raise RuntimeError(
            f"Code call returned unexpected type: {type(raw).__name__}"
        )

    # Strip any accidental markdown fences the model may add despite instructions.
    lines = raw.strip().splitlines()
    if lines and lines[0].startswith("```"):
        lines = lines[1:]
    if lines and lines[-1].startswith("```"):
        lines = lines[:-1]

    return "\n".join(lines).strip()


def _is_meaningfully_unchanged(original: str, patched: str) -> bool:
    """
    Detect when the model returned the original code (or a trivial
    whitespace/comment variant of it) despite metadata claiming a fix.

    This guards against cases like java_deserialize_001, where the metadata
    call reports a fix (changes, patch_rationale, etc.) but the code call
    returns source that is functionally identical to the original -- no
    actual patch was applied, just relabeled.
    """
    def normalize(code: str) -> str:
        lines = [ln.strip() for ln in code.splitlines()]
        lines = [
            ln for ln in lines
            if ln and not ln.startswith(("#", "//", "/*", "*"))
        ]
        return "\n".join(lines)

    return normalize(original) == normalize(patched)


def apply_patches(
    scan_target: Path, patched_target: Path, analyzed_findings: List[Dict]
) -> List[Dict]:
    grouped = group_findings_by_file(analyzed_findings)
    patch_results: List[Dict] = []
    resolved_scan_target = scan_target.resolve()

    for original_file_path, findings in grouped.items():
        original_path = Path(original_file_path).resolve()

        if scan_target.is_dir():
            relative_path = original_path.relative_to(resolved_scan_target)
            target_path = patched_target / relative_path
        else:
            target_path = patched_target

        if not target_path.exists():
            patch_results.append(
                {
                    "file": str(target_path),
                    "original_file": str(target_path),
                    "summary": "",
                    "patch_rationale": "",
                    "remaining_risk": f"Skipped: expected file not found at {target_path}",
                    "applied": False,
                }
            )
            continue

        original_code = target_path.read_text(encoding="utf-8", errors="replace")
        system_msg = {"role": "system", "content": "You are a precise application security assistant."}

        # ------------------------------------------------------------------ #
        # Call 1 — JSON metadata (summary, rationale, remaining risk, etc.)  #
        # patched_code is intentionally NOT part of this schema so the model  #
        # never has to JSON-escape a full source file.                         #
        # ------------------------------------------------------------------ #
        metadata_prompt = build_patch_prompt(str(target_path), original_code, findings)
        try:
            metadata = _call_metadata(
                [system_msg, {"role": "user", "content": metadata_prompt}]
            )
        except Exception as exc:
            patch_results.append(
                {
                    "file": str(target_path),
                    "original_file": str(target_path),
                    "summary": "",
                    "patch_rationale": "",
                    "remaining_risk": f"Metadata call failed: {exc}",
                    "applied": False,
                }
            )
            continue

        # ------------------------------------------------------------------ #
        # Call 2 — raw patched source code as plain text                      #
        # ------------------------------------------------------------------ #
        code_prompt = build_patch_code_prompt(str(target_path), original_code, findings)
        try:
            patched_code = _call_patch_code(
                [system_msg, {"role": "user", "content": code_prompt}]
            )
        except Exception as exc:
            patched_code = ""
            metadata.setdefault("remaining_risk", "")
            metadata["remaining_risk"] = (
                f"Code generation failed ({exc}). "
                + (metadata.get("remaining_risk") or "")
            ).strip()

        # ------------------------------------------------------------------ #
        # Guard — reject "patches" that are identical to the original code.  #
        # Catches cases where metadata claims a fix but no code actually     #
        # changed (e.g. java_deserialize_001).                                #
        # ------------------------------------------------------------------ #
        if patched_code and _is_meaningfully_unchanged(original_code, patched_code):
            patched_code = ""
            metadata["remaining_risk"] = (
                "Patch generation returned code identical (or trivially "
                "identical) to the original; no actual fix was applied. "
                + (metadata.get("remaining_risk") or "")
            ).strip()

        renamed_path = target_path.with_name(f"patched_{target_path.name}")

        if patched_code:
            renamed_path.write_text(patched_code, encoding="utf-8")
            target_path.unlink()
        else:
            # No code produced — keep original in place under the patched_ name.
            target_path.rename(renamed_path)

        patch_rationale = metadata.get("patch_rationale", "") or "Not provided by model"
        remaining_risk  = metadata.get("remaining_risk",  "") or "Not assessed by model"

        patch_results.append(
            {
                "file": str(renamed_path),
                "original_file": str(target_path),
                "summary": metadata.get("summary", ""),
                "patch_rationale": patch_rationale,
                "remaining_risk": remaining_risk,
                "applied": bool(patched_code),
            }
        )

    return patch_results
