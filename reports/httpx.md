# Vulnerability Report

## Summary

The scan detected **10 vulnerabilities** across **4 packages**: `mkdocs`, `build`, `cryptography`, `pytest`, `trio`, and `uvicorn`. The most critical finding is a **CVSS 9.1** integer overflow/buffer overflow in `cryptography` and a **CVSS 9.1** directory traversal in `uvicorn`, both allowing high-impact remote attacks without authentication. Overall, the environment has a mix of critical, high, and medium severity issues that require prioritized remediation.

## Vulnerabilities

| Package | Version | CVE | Severity | CVSS | Recommendation |
|---------|---------|-----|----------|------|----------------|
| cryptography | 45.0.7 | CVE-2020-36242 | CRITICAL | 9.1 | Upgrade to cryptography >= 3.3.2 |
| uvicorn | 0.35.0 | CVE-2025-55526 | CRITICAL | 9.1 | Upgrade to a fixed version; review directory traversal fix |
| mkdocs | 1.6.1 | CVE-2021-40978 | HIGH | 7.5 | Upgrade mkdocs to latest version; vendor dispute noted, evaluate risk |
| cryptography | 45.0.7 | CVE-2016-9243 | HIGH | 7.5 | Upgrade to cryptography >= 1.5.2 |
| cryptography | 45.0.7 | CVE-2023-38325 | HIGH | 7.5 | Upgrade to cryptography >= 41.0.2 |
| cryptography | 45.0.7 | CVE-2026-26007 | HIGH | 8.2 (CVSS 4.0) | Upgrade to cryptography >= 46.0.5 |
| pytest | 8.4.1 | CVE-2020-29651 | HIGH | 7.5 | Review dependency; vulnerability is in `py` library, not pytest itself |
| pytest | 8.4.1 | CVE-2022-42969 | HIGH | 7.5 | Review dependency; vulnerability is in `py` library (disputed) |
| trio | 0.31.0 | CVE-2008-3418 | HIGH | 7.5 | Upgrade to Trio > 2.1; SQL injection in unrelated product version |
| build | 1.3.0 | CVE-2017-14804 | MEDIUM | 5.3 | Upgrade build package to version >= 20171128 |
| build | 1.3.0 | CVE-2025-26869 | MEDIUM | 6.5 | Upgrade Build package; stored XSS fix in current version line |
| cryptography | 45.0.7 | CVE-2020-25659 | MEDIUM | 5.9 | Upgrade to cryptography >= 3.3.1 |
| cryptography | 45.0.7 | CVE-2026-39892 | MEDIUM | 6.9 (CVSS 4.0) | Upgrade to cryptography >= 46.0.7 |
| cryptography | 45.0.7 | CVE-2026-34073 | LOW | 1.7 (CVSS 4.0) | Upgrade to cryptography >= 46.0.6 |

## Conclusion

The overall risk is **High**, driven by two critical CVEs (integer overflow in `cryptography` and directory traversal in `uvicorn`) that allow remote attackers to compromise confidentiality, integrity, or availability without authentication. Additionally, several high-severity vulnerabilities in `cryptography` and disputed findings in `pytest`/`mkdocs` warrant attention. The recommended immediate steps are: **1) Upgrade `cryptography` to version ≥ 46.0.7.** **2) Patch `uvicorn` (apply fix for CVE-2025-55526) or upgrade to a secure version.** **3) Evaluate and apply updates for `mkdocs`, `build`, `pytest` dependencies, and `trio` as per recommendations above.**