def build_analysis_prompt(finding: dict) -> str:
    return f"""
You are a senior application security engineer.

Analyze the Semgrep finding below and determine whether it represents a real security vulnerability.

Return JSON only with this exact schema:

{{
  "is_true_positive": true,
  "vulnerability_type": "",
  "cwe": "",
  "severity": "Low|Medium|High|Critical|Unknown",
  "explanation": "",
  "impact": "",
  "exploit_scenario": "",
  "remediation": "",
  "confidence": 0.0
}}

Requirements:
- Be conservative and evidence-based.
- Use the code snippet and Semgrep metadata only.
- If uncertain, explain why and lower confidence.
- Use CWE identifiers when possible.
- Explain how the vulnerability could be exploited.
- Explain the potential impact if exploited.
- Recommend a secure remediation.
- Do not include markdown.
- Return valid JSON only.

Semgrep finding:

rule_id: {finding.get('rule_id', '')}
message: {finding.get('message', '')}
severity: {finding.get('severity', '')}
path: {finding.get('path', '')}
start_line: {finding.get('start_line', '')}
end_line: {finding.get('end_line', '')}

Code snippet:

{finding.get('code', '')}
""".strip()


def build_patch_prompt(file_path: str, original_code: str, findings: list) -> str:

    findings_text = "\n\n".join(
        [
            (
                f"Finding {idx}\n"
                f"Rule ID: {item.get('rule_id', '')}\n"
                f"Message: {item.get('message', '')}\n"
                f"Severity: {item.get('severity', '')}\n"
                f"Start Line: {item.get('start_line', '')}\n"
                f"End Line: {item.get('end_line', '')}\n\n"
                f"Analysis:\n"
                f"Type: {item.get('llm_analysis', {}).get('vulnerability_type', '')}\n"
                f"CWE: {item.get('llm_analysis', {}).get('cwe', '')}\n"
                f"Severity: {item.get('llm_analysis', {}).get('severity', '')}\n"
                f"Explanation: {item.get('llm_analysis', {}).get('explanation', '')}\n"
                f"Impact: {item.get('llm_analysis', {}).get('impact', '')}\n"
                f"Remediation: {item.get('llm_analysis', {}).get('remediation', '')}"
            )
            for idx, item in enumerate(findings, start=1)
        ]
    )

    return f"""
You are a senior secure software engineer.

Your task is to repair the vulnerable source file.

Objectives:
1. Fix all vulnerabilities identified below.
2. Preserve original functionality whenever possible.
3. Minimize unnecessary code changes.
4. Follow secure coding best practices.
5. Explain every change made.
6. Identify any vulnerabilities that remain.
7. If a vulnerability cannot be safely fixed, explain why.

Return JSON only.

Return JSON with this exact schema:

{{
  "summary": "",
  "changes": [
    {{
      "vulnerability_type": "",
      "cwe": "",
      "severity": "",
      "description": "",
      "why_vulnerable": "",
      "original_snippet": "",
      "patched_snippet": "",
      "fix_explanation": "",
      "fixed": true
    }}
  ],
  "remaining_vulnerabilities": [
    {{
      "type": "",
      "severity": "",
      "reason": ""
    }}
  ],
  "patched_code": "",
  "overall_patch_rationale": "",
  "patch_confidence": 0.0
}}

Rules:
- Return valid JSON only.
- Do not include markdown.
- Do not omit fields.
- The patched_code field must contain the complete updated file.
- Preserve existing functionality unless doing so would leave a serious security vulnerability.

File Path:

{file_path}

Findings:

{findings_text}

Original File:

{original_code}
""".strip()