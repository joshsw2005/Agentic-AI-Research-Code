"""
Optimized combine_findings.py

Same behavior as the original implementation, but much faster.

Optimizations:
- Normalize paths once.
- Group findings by file.
- Sort by start line.
- Only compare findings within the same file.
- Preserve corroboration metadata.
"""

from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List

LINE_OVERLAP_TOLERANCE = 2


def _normalize_path(path: str) -> str:
    try:
        return str(Path(path).resolve())
    except OSError:
        return path


def _ranges_overlap(
    a_start: int,
    a_end: int,
    b_start: int,
    b_end: int,
    tolerance: int,
) -> bool:
    return (a_start - tolerance) <= b_end and (b_start - tolerance) <= a_end


def _prepare(finding: Dict[str, Any]) -> Dict[str, Any]:
    """
    Cache commonly used values so we don't repeatedly perform
    dictionary lookups and path resolution.
    """
    entry = dict(finding)

    start = entry.get("start_line", 0)
    end = entry.get("end_line", start)

    entry["_norm_path"] = _normalize_path(entry["path"])
    entry["_start"] = start
    entry["_end"] = end

    return entry


def _group_overlapping_semgrep(
    semgrep_findings: List[Dict[str, Any]],
    tolerance: int,
) -> List[Dict[str, Any]]:

    by_file = defaultdict(list)

    for finding in semgrep_findings:
        prepared = _prepare(finding)
        by_file[prepared["_norm_path"]].append(prepared)

    grouped = []

    for findings in by_file.values():

        findings.sort(key=lambda x: x["_start"])

        file_groups = []

        for entry in findings:

            matched = None

            #
            # Because everything is sorted,
            # we only compare nearby findings.
            #
            for existing in reversed(file_groups):

                if existing["_end"] + tolerance < entry["_start"]:
                    break

                if _ranges_overlap(
                    existing["_start"],
                    existing["_end"],
                    entry["_start"],
                    entry["_end"],
                    tolerance,
                ):
                    matched = existing
                    break

            if matched is None:
                entry.setdefault("semgrep_corroboration", [])
                file_groups.append(entry)

            else:
                matched.setdefault("semgrep_corroboration", []).append(
                    {
                        "rule_id": entry.get("rule_id"),
                        "message": entry.get("message"),
                        "severity": entry.get("severity"),
                    }
                )

        grouped.extend(file_groups)

    return grouped


def combine_findings(
    semgrep_findings: List[Dict[str, Any]],
    llm_findings: List[Dict[str, Any]],
    tolerance: int = LINE_OVERLAP_TOLERANCE,
) -> List[Dict[str, Any]]:

    deduped_semgrep = _group_overlapping_semgrep(
        semgrep_findings,
        tolerance,
    )

    combined = []
    by_file = defaultdict(list)

    #
    # Seed with Semgrep findings.
    #
    for finding in deduped_semgrep:

        finding.setdefault("source", "semgrep")
        finding["sources"] = [finding["source"]]

        combined.append(finding)
        by_file[finding["_norm_path"]].append(finding)

    #
    # Sort once.
    #
    for findings in by_file.values():
        findings.sort(key=lambda x: x["_start"])

    #
    # Merge LLM findings.
    #
    for llm in llm_findings:

        llm = _prepare(llm)

        candidates = by_file.get(llm["_norm_path"], [])

        matched = None

        for existing in candidates:

            #
            # Since sorted,
            # stop once we're past possible overlap.
            #
            if existing["_start"] > llm["_end"] + tolerance:
                break

            if existing["_end"] + tolerance < llm["_start"]:
                continue

            if _ranges_overlap(
                existing["_start"],
                existing["_end"],
                llm["_start"],
                llm["_end"],
                tolerance,
            ):
                matched = existing
                break

        if matched:

            sources = matched.setdefault("sources", [])

            if "llm_detector" not in sources:
                sources.append("llm_detector")

            matched.setdefault(
                "corroboration",
                {},
            )["llm_detector"] = {
                "rule_id": llm.get("rule_id"),
                "message": llm.get("message"),
                "severity": llm.get("severity"),
                "metadata": llm.get(
                    "llm_detector_metadata",
                    {},
                ),
            }

        else:

            llm["sources"] = ["llm_detector"]

            combined.append(llm)
            by_file[llm["_norm_path"]].append(llm)

    #
    # Remove internal cached fields.
    #
    for finding in combined:
        finding.pop("_norm_path", None)
        finding.pop("_start", None)
        finding.pop("_end", None)

    return combined
