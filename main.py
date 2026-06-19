import argparse
import json
import os
from datetime import datetime
from pathlib import Path
from typing import Dict, List

from llm_client import chat_completion
from patcher import apply_patches, create_patched_copy
from prompts import build_analysis_prompt
from semgrep_runner import run_semgrep, simplify_findings


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


def analyze_findings(findings: List[Dict], max_findings: int) -> List[Dict]:
    analyzed = []
    for idx, finding in enumerate(findings[:max_findings], start=1):
        print(f"[+] Analyzing finding {idx}/{min(len(findings), max_findings)}: {finding['rule_id']}")
        prompt = build_analysis_prompt(finding)
        llm_result = chat_completion(prompt)
        analyzed.append({
            "finding": finding,
            "llm_analysis": llm_result,
        })
    return analyzed


def verify_patches(patched_target: Path, semgrep_config: str) -> Dict:
    verification_semgrep = run_semgrep(str(patched_target), config=semgrep_config)
    verification_findings = simplify_findings(verification_semgrep, str(patched_target))
    return {
        "total_semgrep_findings_after_patch": len(verification_semgrep.get("results", [])),
        "remaining_findings": verification_findings,
    }


def build_report(
    repo: str,
    config: str,
    semgrep_json: Dict,
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
            "analyzed_findings": len(analyzed_findings),
            "patched_files": len(patch_results),
            "remaining_findings_after_patch": verification.get("total_semgrep_findings_after_patch", 0),
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
    parser.add_argument(
        "--repo",
        required=True,
        help="Path to the code target to scan. This can be a repository, folder, or single source file.",
    )
    parser.add_argument("--output", default="results/latest_report.json", help="Path to output JSON report")
    parser.add_argument("--max-findings", type=int, default=3, help="Maximum number of findings to analyze")
    parser.add_argument("--semgrep-config", default=None, help="Semgrep config. Defaults to SEMGREP_CONFIG or auto")
    parser.add_argument(
        "--patched-dir",
        default="results/patched",
        help="Directory where patched code copies will be written",
    )
    args = parser.parse_args()

    load_env_file()

    repo_path = Path(args.repo)
    if not repo_path.exists():
        raise FileNotFoundError(f"Repository path not found: {repo_path}")

    semgrep_config = args.semgrep_config or os.environ.get("SEMGREP_CONFIG", "auto")

    print(f"[+] Running Semgrep on: {repo_path}")
    semgrep_json = run_semgrep(str(repo_path), config=semgrep_config)

    findings = simplify_findings(semgrep_json, str(repo_path))
    print(f"[+] Semgrep found {len(findings)} result(s)")

    if not findings:
        print("[+] No findings to analyze")
        patched_target_path = create_patched_copy(repo_path, Path(args.patched_dir))
        verification = verify_patches(patched_target_path, semgrep_config)
        report = build_report(
            str(repo_path),
            semgrep_config,
            semgrep_json,
            [],
            [],
            str(patched_target_path),
            verification,
        )
    else:
        analyzed = analyze_findings(findings, args.max_findings)
        patched_target_path = create_patched_copy(repo_path, Path(args.patched_dir))
        print(f"[+] Writing patched copy to: {patched_target_path}")
        patch_results = apply_patches(repo_path, patched_target_path, analyzed)
        print("[+] Re-running Semgrep on patched output")
        verification = verify_patches(patched_target_path, semgrep_config)
        report = build_report(
            str(repo_path),
            semgrep_config,
            semgrep_json,
            analyzed,
            patch_results,
            str(patched_target_path),
            verification,
        )

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"[+] Report written to: {output_path}")


if __name__ == "__main__":
    main()
