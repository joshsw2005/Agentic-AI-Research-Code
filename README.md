# Agentic-AI-Research-Code

# Agentic AI Workflow for Software Vulnerability Discovery, Analysis, and Remediation

## Overview

This research project investigates the use of Agentic Artificial Intelligence (AI) for automated software vulnerability management. The objective is to design and evaluate an autonomous AI workflow capable of identifying, analyzing, explaining, and ultimately remediating software vulnerabilities within source code repositories.

The system combines traditional static analysis techniques with Large Language Model (LLM) reasoning to create a hybrid cybersecurity framework. Static analysis is used to detect potential vulnerabilities, while an LLM provides contextual analysis, root-cause explanations, severity assessments, and remediation recommendations.

The long-term goal is to compare the effectiveness of this custom-built agentic workflow against existing AI-based vulnerability management approaches described in current research literature.

---

## Research Objectives

The proposed framework aims to:

1. Automatically detect software vulnerabilities using static analysis.
2. Analyze identified vulnerabilities using a Large Language Model.
3. Generate human-readable explanations of security issues.
4. Map findings to Common Weakness Enumeration (CWE) categories.
5. Recommend secure remediation strategies.
6. Generate structured vulnerability reports.
7. Evaluate performance against existing agentic cybersecurity systems.
8. Extend the workflow to support automated patch generation and validation.

---

## Current System Architecture

```text
GitHub Repository
        │
        ▼
 Source Code Collection
        │
        ▼
     Semgrep Scan
        │
        ▼
 Vulnerability Findings
        │
        ▼
 Qwen3-Coder-Next Analysis
        │
        ▼
 Vulnerability Explanation
 Severity Assessment
 CWE Classification
 Remediation Suggestions
        │
        ▼
 Security Report Generation
```

---

## Dataset

The project uses publicly available GitHub repositories containing intentionally vulnerable applications and security training environments.

Potential repositories include:

* OWASP Juice Shop
* OWASP WebGoat

Source code files serve as the primary dataset for analysis.

The workflow processes:

* Python
* Java
* JavaScript
* C/C++
* Additional supported languages

---

## Vulnerability Detection

Automated vulnerability detection is performed using:

### Semgrep

Semgrep is used as the primary static analysis engine to identify common software vulnerabilities, including:

* SQL Injection
* Command Injection
* Cross-Site Scripting (XSS)
* Hardcoded Credentials
* Insecure Authentication
* Other CWE-related weaknesses

Semgrep findings are converted into structured records that are passed to the LLM for further analysis.

---

## LLM-Based Vulnerability Analysis

### Model

The current implementation uses:

**Qwen3-Coder-Next**

The model receives:

* Vulnerable code snippets
* Semgrep findings
* File metadata
* Vulnerability context

The model generates:

* Vulnerability descriptions
* Root-cause explanations
* Severity assessments
* CWE mappings
* Remediation recommendations

This enables contextual reasoning beyond traditional static analysis tools.

---

## Technologies

### Core Technologies

* Python
* Semgrep
* SQLite
* GitHub API
* Hugging Face Ecosystem

### AI Models

* Qwen3-Coder-Next

### Planned Frameworks

* LangChain
* LangGraph
* Multi-Agent Architectures

---

## Planned Agentic Workflow

Future development will expand the framework into a multi-agent system consisting of:

### Detection Agent

Identifies potential vulnerabilities.

### Analysis Agent

Explains vulnerabilities and assesses risk.

### Remediation Agent

Generates secure code fixes.

### Validation Agent

Tests whether generated patches successfully mitigate vulnerabilities.

### Reporting Agent

Produces comprehensive security reports.

---


## Current Progress

### Completed

* Literature review of Agentic AI and vulnerability management systems
* System architecture design
* Semgrep integration
* Vulnerability detection pipeline
* Qwen3-Coder-Next integration
* Automated vulnerability explanation generation
* Security report generation

### In Progress

* Repository dataset collection
* Multi-agent workflow implementation
* Automated remediation generation
* Patch validation

### Planned

* Vulnerability reproduction module
* Benchmark evaluation
* Comparative performance analysis
* End-to-end autonomous remediation pipeline

---

## Status

Active Development

Current Version: Vulnerability Detection + LLM-Based Analysis

Next Milestone: Automated Vulnerability Remediation and Validation
