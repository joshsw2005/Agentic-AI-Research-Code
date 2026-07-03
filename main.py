import argparse
import json
import os
import random
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import Dict, List

from combine_findings import combine_findings
from llm_client import chat_completion
from llm_detector import run_llm_detector, detect_file
from patcher import apply_patches, create_patched_copy
from prompts import build_analysis_prompt
from semgrep_runner import run_semgrep, run_semgrep_multi, simplify_findings


def load_env_file(env_path: str = ".env") -> None:
    path = Path(env_path)
    if not path.exists():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip())


def analyze_findings(findings: List[Dict], max_findings: int, workers: int = 3) -> List[Dict]:
    """
    Analyze findings in parallel using a thread pool.
    workers=3 is safe for a 30B model on 2x A30 — enough to keep the GPU
    busy without OOM. Tune down to 1 if you see memory errors.
    """
    selected = findings if max_findings == 0 else findings[:max_findings]
    total = len(selected)
    results = [None] * total

    def _analyze(idx_finding):
        idx, finding = idx_finding
        print(f"[+] Analyzing finding {idx + 1}/{total}: {finding['rule_id']}")
        prompt = build_analysis_prompt(finding)
        llm_result = chat_completion(prompt)
        return idx, {"finding": finding, "llm_analysis": llm_result}

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(_analyze, (i, f)): i for i, f in enumerate(selected)}
        for future in as_completed(futures):
            try:
                idx, result = future.result()
                results[idx] = result
            except Exception as exc:
                idx = futures[future]
                print(f"[!] Analysis failed for finding {idx + 1}: {exc}")
                results[idx] = {
                    "finding": selected[idx],
                    "llm_analysis": {"error": str(exc)},
                }

    return [r for r in results if r is not None]


# Rule/category suffixes where the LLM detector historically catches things
# Semgrep's ruleset misses (context-dependent logic, not pattern-matchable).
# Seed/tune this from BENCHMARK_KEY.json results as you collect more data.
LLM_PRONE_CATEGORIES = {
    "race-condition",
    "insecure-direct-object-reference",
    "ldap-injection",
    "prototype-pollution",
}


def _rule_category(rule_id: str) -> str:
    # Rule ids can come from either detector:
    #   Semgrep:      "p/security-audit.some-rule-name" (or nested dotted paths)
    #   LLM detector: "llm-detector.race-condition"
    # In both cases the trailing dot-separated segment is the category.
    return rule_id.rsplit(".", 1)[-1]


def _finding_key(finding: Dict) -> tuple:
    # Identity for diffing pre/post patch findings on the same file.
    return (finding.get("rule_id"), finding.get("start_line"), finding.get("end_line"))


def verify_patches(
    patched_target: Path,
    patch_results: List[Dict],
    semgrep_config: str,
    pre_patch_findings: List[Dict] = None,
    llm_sample_rate: float = 0.0,
    llm_detector_max_files: int = 0,
    workers: int = 3,
) -> Dict:
    """
    Hybrid verification:
      - Semgrep always runs on every patched file (cheap, catches regressions
        against the full ruleset, not just the original finding).
      - LLM detector only runs on a file when:
          (a) Semgrep found a NEW finding on that file post-patch (possible
              regression — confirm/expand with the LLM), OR
          (b) the original finding's category is known LLM-prone, OR
          (c) the file is hit by random sampling (llm_sample_rate).
    """
    pre_patch_findings = pre_patch_findings or []
    applied_files = [r["file"] for r in patch_results if r.get("applied")]

    if not applied_files:
        return {
            "total_semgrep_findings_after_patch": 0,
            "total_llm_detector_findings_after_patch": 0,
            "remaining_findings": [],
            "remaining_findings_count": 0,
            "verified_files": [],
            "verification_methods": {},
        }

    # simplify_findings() resolves everything to absolute paths (see
    # _resolve_result_path in semgrep_runner.py), so normalize applied_files
    # the same way for reliable dict lookups below.
    def _norm(p: str) -> str:
        return str(Path(p).resolve())

    applied_files_norm = [_norm(f) for f in applied_files]

    # Pre-patch findings, grouped by file (field is "path", not "file" —
    # see simplify_findings() in semgrep_runner.py).
    pre_by_file: Dict[str, List[Dict]] = {}
    for f in pre_patch_findings:
        pre_by_file.setdefault(_norm(f.get("path", "")), []).append(f)

    # Single Semgrep invocation across all patched files — rule loading
    # only happens once here, instead of once per file. This is the main
    # cost when verifying many files individually, since each subprocess
    # call re-parses the full ruleset from scratch before scanning even
    # a single small file.
    combined_semgrep = run_semgrep_multi(applied_files, config=semgrep_config)
    all_post_findings = simplify_findings(combined_semgrep, str(patched_target))

    semgrep_by_file: Dict[str, List[Dict]] = {}
    for finding in all_post_findings:
        semgrep_by_file.setdefault(_norm(finding.get("path", "")), []).append(finding)

    # Decide which files need LLM verification.
    llm_targets: List[str] = []
    verification_methods: Dict[str, str] = {}

    for file_path, file_key in zip(applied_files, applied_files_norm):
        post_findings = semgrep_by_file.get(file_key, [])
        pre_findings = pre_by_file.get(file_key, [])

        pre_keys = {_finding_key(f) for f in pre_findings}
        post_keys = {_finding_key(f) for f in post_findings}
        has_new_semgrep_finding = bool(post_keys - pre_keys)

        original_categories = {_rule_category(f.get("rule_id", "")) for f in pre_findings}
        is_llm_prone = bool(original_categories & LLM_PRONE_CATEGORIES)

        sampled = llm_sample_rate > 0 and random.random() < llm_sample_rate

        if has_new_semgrep_finding:
            llm_targets.append(file_path)
            verification_methods[file_path] = "semgrep+llm (new finding detected)"
        elif is_llm_prone:
            llm_targets.append(file_path)
            verification_methods[file_path] = "semgrep+llm (prone category)"
        elif sampled:
            llm_targets.append(file_path)
            verification_methods[file_path] = "semgrep+llm (sampled)"
        else:
            verification_methods[file_path] = "semgrep_only"

    if llm_detector_max_files:
        llm_targets = llm_targets[:llm_detector_max_files]

    llm_findings: List[Dict] = []
    if llm_targets:
        def _verify_file(fp):
            return detect_file(Path(fp), min_confidence=0.85)

        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = [pool.submit(_verify_file, fp) for fp in llm_targets]
            for future in as_completed(futures):
                try:
                    llm_findings.extend(future.result())
                except Exception as exc:
                    print(f"[!] LLM verify failed: {exc}")

    semgrep_findings = all_post_findings
    remaining = combine_findings(semgrep_findings, llm_findings)

    return {
        "total_semgrep_findings_after_patch": len(combined_semgrep["results"]),
        "total_llm_detector_findings_after_patch": len(llm_findings),
        "llm_verified_files": llm_targets,
        "remaining_findings": remaining,
        "remaining_findings_count": len(remaining),
        "verified_files": applied_files,
        "verification_methods": verification_methods,
    }


def build_report(
    repo: str,
    config: str,
    semgrep_json: Dict,
    llm_detector_findings: List[Dict],
    combined_findings: List[Dict],
    analyzed_findings: List[Dict],
    patch_results: List[Dict],
    patched_target: str,
    verification: Dict,
) -> Dict:
    return {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "repo": repo,
        "semgrep_config": config,
        "summary": {
            "total_semgrep_findings": len(semgrep_json.get("results", [])),
            "total_llm_detector_findings": len(llm_detector_findings),
            "total_combined_findings": len(combined_findings),
            "analyzed_findings": len(analyzed_findings),
            "patched_files": len(patch_results),
            "files_verified": len(verification.get("verified_files", [])),
            "files_llm_verified": len(verification.get("llm_verified_files", [])),
            "remaining_findings_after_patch": verification.get("remaining_findings_count", 0),
        },
        "results": analyzed_findings,
        "patched_output": {
            "path": patched_target,
            "files": patch_results,
        },
        "verification": verification,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Run Semgrep and analyze findings with an LLM.")
    parser.add_argument("--repo", required=True,
        help="Path to the code target to scan.")
    parser.add_argument("--output", default="results/latest_report.json",
        help="Path to output JSON report")
    parser.add_argument("--max-findings", type=int, default=0,
        help="Maximum number of findings to analyze (0 = no limit)")
    parser.add_argument("--semgrep-config",
        default="/opt/agentic-vuln-ai/semgrep-rules-develop",
        help="Semgrep config ruleset.")
    parser.add_argument("--patched-dir", default="results/patched",
        help="Directory where patched code copies will be written")
    parser.add_argument("--skip-llm-detector", action="store_true",
        help="Skip the independent LLM detection pass")
    parser.add_argument("--llm-sample-rate", type=float, default=0.15,
        help="Fraction (0.0-1.0) of non-flagged, non-prone-category patched "
             "files to still spot-check with the LLM detector on verify. "
             "Default 0.15. Set to 0 to disable sampling entirely.")
    parser.add_argument("--llm-detector-max-files", type=int, default=0,
        help="Limit how many files the LLM detector scans (0 = no limit)")
    parser.add_argument("--workers", type=int, default=3,
        help="Parallel LLM workers for analysis and patching (default: 3). "
             "Reduce to 1 if you see GPU memory errors.")
    args = parser.parse_args()

    load_env_file()

    repo_path = Path(args.repo)
    if not repo_path.exists():
        raise FileNotFoundError(f"Repository path not found: {repo_path}")

    semgrep_config = args.semgrep_config

    print(f"[+] Running Semgrep on: {repo_path}")
    print(f"[+] Using Semgrep config: {semgrep_config}")
    semgrep_json = run_semgrep(str(repo_path), config=semgrep_config)
    semgrep_findings = simplify_findings(semgrep_json, str(repo_path))
    print(f"[+] Semgrep found {len(semgrep_findings)} result(s)")

    llm_detector_findings: List[Dict] = []
    if not args.skip_llm_detector:
        print("[+] Running independent LLM detector")
        llm_detector_findings = run_llm_detector(
            repo_path,
            max_files=args.llm_detector_max_files,
        )
        print(f"[+] LLM detector found {len(llm_detector_findings)} result(s)")

    findings = combine_findings(semgrep_findings, llm_detector_findings)
    print(f"[+] Combined findings: {len(findings)} (after merging overlaps)")

    patched_target_path = create_patched_copy(repo_path, Path(args.patched_dir))

    if not findings:
        print("[+] No findings to analyze")
        verification = verify_patches(
            patched_target_path, [], semgrep_config,
            pre_patch_findings=[],
            llm_sample_rate=0.0,
        )
        report = build_report(
            str(repo_path), semgrep_config, semgrep_json,
            llm_detector_findings, findings, [], [], str(patched_target_path),
            verification,
        )
    else:
        print(f"[+] Analyzing {len(findings)} findings ({args.workers} parallel workers)")
        analyzed = analyze_findings(findings, args.max_findings, workers=args.workers)

        print(f"[+] Writing patched copy to: {patched_target_path}")
        patch_results = apply_patches(repo_path, patched_target_path, analyzed)

        print("[+] Re-running detection on patched files "
              "(Semgrep always; LLM only on regressions / prone categories / sample)")
        verification = verify_patches(
            patched_target_path,
            patch_results,
            semgrep_config,
            pre_patch_findings=findings,
            llm_sample_rate=0.0 if args.skip_llm_detector else args.llm_sample_rate,
            llm_detector_max_files=args.llm_detector_max_files,
            workers=args.workers,
        )
        n_llm = len(verification.get("llm_verified_files", []))
        n_total = len(verification.get("verified_files", []))
        print(f"[+] LLM-verified {n_llm}/{n_total} patched files "
              f"(rest confirmed by Semgrep only)")

        report = build_report(
            str(repo_path), semgrep_config, semgrep_json,
            llm_detector_findings, findings, analyzed, patch_results,
            str(patched_target_path), verification,
        )

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"[+] Report written to: {output_path}")


if __name__ == "__main__":
    main()
