from pathlib import Path


# ---------------------------------------------------------------------------
# Language detection
# ---------------------------------------------------------------------------

_LANGUAGE_MAP = {
    ".py":   "Python",
    ".js":   "JavaScript",
    ".ts":   "TypeScript",
    ".java": "Java",
    ".c":    "C",
    ".cpp":  "C++",
    ".cc":   "C++",
    ".cxx":  "C++",
    ".h":    "C/C++ header",
    ".hpp":  "C++ header",
    ".cs":   "C#",
    ".go":   "Go",
    ".rb":   "Ruby",
    ".php":  "PHP",
    ".rs":   "Rust",
}

def _detect_language(file_path: str) -> str:
    ext = Path(file_path).suffix.lower()
    return _LANGUAGE_MAP.get(ext, "unknown")


# ---------------------------------------------------------------------------
# Per-language security guidance
# ---------------------------------------------------------------------------

_GUIDANCE_COMMON = """
- Never use MD5, SHA-1, SHA-256, SHA-3, or any other general-purpose/fast hash
  function for password hashing or password storage, even as an interim fix.
  Fast hashes are not salted and not computationally expensive — they are
  themselves a vulnerability for passwords. Use a purpose-built slow hash.
- For SQL, always use parameterized queries / prepared statements.
- Never trust user-supplied input in file paths, shell commands, or queries
  without strict validation and sanitisation.
- When a tool's suggested fix is inadequate (e.g. "use SHA256 instead of MD5"
  for a password hash), apply the actually-correct fix instead.
""".strip()

_GUIDANCE_BY_LANGUAGE = {
    "Python": """
Language-specific guidance (Python):
- Password hashing: use bcrypt, scrypt, or Argon2 (e.g. via the `bcrypt` or
  `argon2-cffi` library). Never use hashlib for passwords.
- Command execution: always use subprocess with a list of arguments and
  shell=False. Never pass user input to os.system() or shell=True.
- Deserialisation: never use pickle, marshal, or shelve on untrusted data.
  Use json.loads() or a validated schema library instead.
- Constant-time comparison: use hmac.compare_digest() for secrets.
""".strip(),

    "JavaScript": """
Language-specific guidance (JavaScript / Node.js):
- Password hashing: use bcrypt (e.g. `bcryptjs` or `bcrypt`), scrypt
  (Node built-in `crypto.scrypt`), or Argon2 (`argon2` package).
  Never use crypto.createHash() for passwords.
- Command execution: use execFile() or spawn() with an argument array instead
  of exec() with string interpolation.
- Deserialisation: never pass untrusted input to eval(), Function(),
  vm.runInNewContext(), or unserialise libraries.
- SQL: use parameterised queries (e.g. `?` placeholders in mysql2,
  `$1` in pg). Never concatenate user input into query strings.
- XSS: always escape output; use textContent instead of innerHTML where
  possible, or a trusted sanitiser like DOMPurify.
""".strip(),

    "TypeScript": """
Language-specific guidance (TypeScript):
- Same as JavaScript/Node.js guidance above.
- Additionally: do not use `as any` to bypass type-safety around untrusted
  input; validate and type-narrow before use.
""".strip(),

    "Java": """
Language-specific guidance (Java):
- Password hashing: use BCrypt (Spring Security's BCryptPasswordEncoder or
  jBCrypt), PBKDF2WithHmacSHA256 via SecretKeyFactory, or Argon2.
  Never use MessageDigest (MD5/SHA) for passwords.
- Command execution: use ProcessBuilder with a List<String> of arguments.
  Never pass user input to Runtime.exec(String) or a shell.
- Deserialisation: never deserialise untrusted data with ObjectInputStream.
  Use JSON (Jackson, Gson) or validate with a serialisation filter
  (ObjectInputFilter) if Java serialisation is unavoidable.
- SQL: always use PreparedStatement with ? placeholders.
- XXE: disable external entities on XML parsers:
    factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)
""".strip(),

    "C": """
Language-specific guidance (C):
- Buffer overflows: replace unsafe functions (strcpy, strcat, sprintf, gets,
  scanf %s without width) with safe equivalents (strncpy+explicit null,
  strncat, snprintf, fgets).
- Format string: never pass user input as the format argument to printf-family
  functions; always use a literal format string.
- Integer overflow: validate arithmetic before use, especially when computing
  buffer sizes or array indices from user input.
- Use-after-free / double-free: ensure every allocated pointer is freed
  exactly once and set to NULL afterwards.
- Command injection: avoid system(); use execv/execve with a NULL-terminated
  argv array built from validated, separate arguments.
""".strip(),

    "C++": """
Language-specific guidance (C++):
- Prefer std::string, std::vector, and smart pointers (unique_ptr, shared_ptr)
  over raw arrays and manual memory management.
- Same buffer-overflow and format-string rules as C apply to any C-style APIs
  still in use.
- Avoid strcpy, sprintf, gets — use their safe C++ or bounded-C equivalents.
- Use std::array or size-checked containers instead of C-style arrays where
  possible.
""".strip(),
}

def _build_security_guidance(file_path: str) -> str:
    lang = _detect_language(file_path)
    lang_guidance = _GUIDANCE_BY_LANGUAGE.get(lang, "")
    parts = [
        "Security-specific guidance (apply even if it means a larger change than "
        "the minimum suggested by a tool's message):",
        _GUIDANCE_COMMON,
    ]
    if lang_guidance:
        parts.append(lang_guidance)
    return "\n\n".join(parts)


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _build_findings_text(findings: list) -> str:
    """Format findings list for patch prompts."""
    return "\n\n".join(
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


# ---------------------------------------------------------------------------
# Prompts
# ---------------------------------------------------------------------------

def build_analysis_prompt(finding: dict) -> str:
    lang = _detect_language(finding.get("path", ""))
    return f"""
You are a senior application security engineer.

Analyse the following security finding and determine whether it represents a
real vulnerability. The source language is {lang}.

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
- Use the code snippet and finding metadata only.
- If uncertain, explain why and lower confidence.
- Use CWE identifiers when possible.
- Explain how the vulnerability could be exploited.
- Explain the potential impact if exploited.
- Recommend a secure remediation appropriate for {lang}.
- Do not include markdown.
- Return valid JSON only.

Finding:

rule_id: {finding.get('rule_id', '')}
message: {finding.get('message', '')}
severity: {finding.get('severity', '')}
path: {finding.get('path', '')}
start_line: {finding.get('start_line', '')}
end_line: {finding.get('end_line', '')}

Code snippet:

{finding.get('code', '')}
""".strip()


def build_detection_prompt(file_path: str, source_code: str) -> str:
    lang = _detect_language(file_path)
    return f"""
You are a senior application security engineer performing manual security review.

Read the {lang} source file below and identify security vulnerabilities a static
analysis tool based on syntactic rules could plausibly miss. Examples include
business-logic flaws, authentication/authorization gaps, insecure design
decisions, improper trust boundaries, and issues that require understanding
intent rather than pattern-matching.

Do not limit yourself to a fixed checklist. Use your judgement.

Return JSON only with this exact schema:

{{
  "findings": [
    {{
      "vulnerability_type": "",
      "cwe": "",
      "severity": "Low|Medium|High|Critical",
      "start_line": 0,
      "end_line": 0,
      "explanation": "",
      "impact": "",
      "exploit_scenario": "",
      "remediation": "",
      "confidence": 0.0
    }}
  ]
}}

Requirements:
- Only report issues you are reasonably confident about; omit speculative findings.
- start_line and end_line must refer to actual line numbers in the file below.
- Use CWE identifiers when possible.
- Return an empty "findings" array if nothing concerning is found.
- Do not include markdown.
- Return valid JSON only.

File Path:

{file_path}

Source Code (line numbers shown for reference, do not include them in any code you quote):

{source_code}
""".strip()


def build_patch_prompt(file_path: str, original_code: str, findings: list) -> str:
    """
    Call 1 of 2: ask the model for patch metadata as JSON only.
    patched_code is intentionally absent — a separate plain-text call
    (build_patch_code_prompt) retrieves the fixed source, avoiding the
    JSON-escaping failures that occur when full source is in a JSON string.
    """
    lang = _detect_language(file_path)
    findings_text = _build_findings_text(findings)
    security_guidance = _build_security_guidance(file_path)

    return f"""
You are a senior secure software engineer.

Your task is to plan the repair of the vulnerable {lang} source file described
below. Do NOT include the patched source code in this response — that will be
requested separately.

{security_guidance}

Return JSON only with this exact schema:

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
  "patch_rationale": "",
  "remaining_risk": "",
  "patch_confidence": 0.0
}}

Rules:
- Return valid JSON only. Do not include markdown. Do not omit fields.
- patch_rationale: 2-4 sentences explaining why the chosen fixes are correct
  and sufficient — not just a restatement of what was changed.
- remaining_risk: 1-3 sentences summarising residual risk after patching,
  consistent with remaining_vulnerabilities. Write "None identified" if clean.
- original_snippet and patched_snippet: short representative excerpts only,
  not the full file.

File Path: {file_path}

Findings:

{findings_text}

Original File:

{original_code}
""".strip()


def build_patch_code_prompt(file_path: str, original_code: str, findings: list) -> str:
    """
    Call 2 of 2: ask the model for the complete patched source as raw plain
    text. No JSON wrapper — avoids JSON-escaping failures for larger files.
    """
    lang = _detect_language(file_path)
    findings_text = _build_findings_text(findings)
    security_guidance = _build_security_guidance(file_path)

    return f"""
You are a senior secure software engineer.

Rewrite the {lang} source file below to fix all of the listed security
vulnerabilities.

{security_guidance}

Rules:
- Output ONLY the complete corrected source file. No explanation, no JSON,
  no markdown fences, no preamble, no commentary — raw {lang} source only.
- Preserve all original functionality that is not itself a security risk.
- Minimise unnecessary changes beyond what is required to fix each vulnerability.
- If a vulnerability cannot be safely fixed without breaking functionality,
  add a TODO comment at the relevant line explaining why and what is needed.

File Path: {file_path}

Findings:

{findings_text}

Original File:

{original_code}
""".strip()
