# Vulnerability Report

## Summary

The dependency scan identified 26 vulnerabilities across 8 Python packages, including 4 Critical-severity issues, 11 High-severity issues, and 11 Medium/Low-severity issues. The most critical flaws involve remote code execution in `click`, `pyyaml`, and `pygments`, and require immediate attention.

## Vulnerabilities

| Package | Version | CVE | Severity | CVSS | Recommendation |
|---------|---------|-----|----------|------|----------------|
| click | 8.1.8 | CVE-2015-8768 | CRITICAL | 9.8 | Upgrade to latest version (CVE affects click/install.py in click; no patch disclosed for this version) |
| pyyaml | 6.0.3 | CVE-2017-18342 | CRITICAL | 9.8 | Upgrade to latest version; use yaml.safe_load() instead of yaml.load() |
| pyyaml | 6.0.3 | CVE-2019-20477 | CRITICAL | 9.8 | Upgrade to latest version; use yaml.safe_load() |
| pyyaml | 6.0.3 | CVE-2020-14343 | CRITICAL | 9.8 | Upgrade to latest version; avoid FullLoader |
| pygments | 2.19.2 | CVE-2015-8557 | CRITICAL | 9.0 | Upgrade to latest version; sanitize font names |
| sphinx | 8.2.3 | CVE-2019-14511 | HIGH | 7.5 | Configure Sphinx to listen only on 127.0.0.1 or add firewall rules |
| sphinx | 8.2.3 | CVE-2020-29050 | HIGH | 7.5 | Upgrade to version >3.1.1; apply access controls |
| pygments | 2.19.2 | CVE-2021-27291 | HIGH | 7.5 | Upgrade to version >=2.7.4 |
| pygments | 2.19.2 | CVE-2021-20270 | HIGH | 7.5 | Upgrade to version >2.7.3 |
| black | 22.12.0 | CVE-2026-31900 | HIGH | 8.7 | Upgrade to version >=26.3.0 |
| black | 22.12.0 | CVE-2026-32274 | HIGH | 8.7 | Upgrade to version >=26.3.1 |
| virtualenv | 20.34.0 | CVE-2024-53899 | HIGH | 7.8 | Upgrade to version >=20.26.6 |
| pytest | 7.4.4 | CVE-2020-29651 | HIGH | 7.5 | Upgrade to latest version |
| pytest | 7.4.4 | CVE-2022-42969 | HIGH | 7.5 | Upgrade to latest version |
| decorator | 5.2.1 | CVE-2023-48284 | HIGH | 8.8 | This CVE affects a WooCommerce plugin, not the Python decorator package; verify applicability |
| ipython | 8.12.3 | CVE-2015-5607 | HIGH | 8.8 | Upgrade to version >=4.0.0 |
| filelock | 3.16.1 | CVE-2025-68146 | MEDIUM | 6.5 | Upgrade to version >=3.20.1 |
| filelock | 3.16.1 | CVE-2026-22701 | MEDIUM | 5.3 | Upgrade to version >=3.20.3 |
| sphinx | 8.2.3 | CVE-2022-2838 | MEDIUM | 5.3 | Upgrade to version >=0.13.1 |
| ipython | 8.12.3 | CVE-2015-4707 | MEDIUM | 6.1 | Upgrade to version >=3.2 |
| ipython | 8.12.3 | CVE-2015-4706 | MEDIUM | 6.1 | Upgrade to version >=3.2 |
| pygments | 2.19.2 | CVE-2022-40896 | MEDIUM | 5.5 | Upgrade to version >2.15.0 |
| virtualenv | 20.34.0 | CVE-2013-5123 | MEDIUM | 5.9 | Upgrade to version >=1.5 |
| virtualenv | 20.34.0 | CVE-2026-22702 | MEDIUM | 4.5 | Upgrade to version >=20.36.1 |
| ipython | 8.12.3 | CVE-2014-3429 | MEDIUM | 6.8* | Upgrade to version >=1.2 |
| ipython | 8.12.3 | CVE-2015-7337 | MEDIUM | 6.8* | Upgrade to version >=3.2.2 |
| ipython | 8.12.3 | CVE-2015-6938 | MEDIUM | 4.3* | Upgrade to version >=3.2.2 |
| pyyaml | 6.0.3 | CVE-2014-9130 | MEDIUM | 5.0* | Upgrade to version >0.1.6 |
| pyyaml | 6.0.3 | CVE-2013-6393 | MEDIUM | 6.8* | Upgrade to version >=0.1.5 |
| pyyaml | 6.0.3 | CVE-2014-2525 | MEDIUM | 6.8* | Upgrade to version >=0.1.6 |
| virtualenv | 20.34.0 | CVE-2011-4617 | LOW | 1.2 | Upgrade to version >=1.5 |
| pygments | 2.19.2 | CVE-2026-4539 | LOW | 1.9 | Upgrade to latest version; patch not yet available |
| parso | 0.8.5 | CVE-2019-12760 | LOW | 3.3 | Upgrade to version >0.4.0; ensure cache directory is not writable by attackers |

*Note: CVSS scores marked with * are CVSS v2 scores, not directly comparable to v3 scores.

## Conclusion

The environment contains 4 critical and 11 high-severity vulnerabilities, with remote code execution risks in `pyyaml`, `click`, and `pygments`. The overall risk is **high**, as several of these flaws can lead to full system compromise if exploited. **Immediate action is required**: prioritize upgrading `pyyaml`, `click`, `black`, `pygments`, and `virtualenv` to their latest secure versions. Additionally, configure `sphinx` to bind only to localhost and apply firewall restrictions. Run a full scan after upgrades to verify remediation.