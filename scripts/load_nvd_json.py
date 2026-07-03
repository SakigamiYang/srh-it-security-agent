import re
from pathlib import Path
from typing import Any

import orjson
from packaging.specifiers import InvalidSpecifier, SpecifierSet

INVALID_VALUES = {
    "",
    "n/a",
    "unknown",
}

VERSION_OPERATORS = (
    ">=",
    "<=",
    "!=",
    "==",
    ">",
    "<",
    "=",
    "~=",
)


def _is_valid_text(value: str | None) -> bool:
    if not value:
        return False

    return value.strip().lower() not in INVALID_VALUES


def _normalize_text(value: str | None) -> str | None:
    if not _is_valid_text(value):
        return None

    return value.strip()


def _get_en_description(descriptions: list[dict[str, Any]]) -> str | None:
    for item in descriptions or []:
        if item.get("lang") == "en":
            return item.get("value")

    if descriptions:
        return descriptions[0].get("value")

    return None


def _normalize_specifier(raw_version: str | None) -> str | None:
    """
    Convert simple version expressions into PEP 440 compatible specifiers.

    Examples:
        ">= 6.49, < 6.52" -> ">=6.49,<6.52"
        "< 0.30.0" -> "<0.30.0"
        "1.0" -> "==1.0"

    Non-standard expressions are kept as raw_version only.
    """
    if not raw_version:
        return None

    value = raw_version.strip()

    if not value or value in {"*", "-"}:
        return None

    lowered = value.lower()

    if lowered in {
        "unspecified",
        "unknown",
        "n/a",
        "all",
        "any",
    }:
        return None

    # Remove spaces around commas.
    value = re.sub(r"\s*,\s*", ",", value)

    parts = value.split(",")

    normalized_parts: list[str] = []

    for part in parts:
        part = part.strip()

        if not part:
            continue

        # Convert single "=" into "==".
        if part.startswith("=") and not part.startswith("=="):
            part = "=" + part

        # Remove spaces after operators.
        matched_operator = None

        for operator in VERSION_OPERATORS:
            if part.startswith(operator):
                matched_operator = operator
                version = part[len(operator):].strip()

                if operator == "=":
                    operator = "=="

                normalized_parts.append(f"{operator}{version}")
                break

        if matched_operator is None:
            # Plain version, e.g. "1.0"
            normalized_parts.append(f"=={part}")

    if not normalized_parts:
        return None

    specifier = ",".join(normalized_parts)

    try:
        SpecifierSet(specifier)
    except InvalidSpecifier:
        return None

    return specifier


def _parse_cpe23_uri(criteria: str | None) -> dict[str, str | None]:
    """
    Parse basic fields from a CPE 2.3 URI.

    CPE 2.3 format:
    cpe:2.3:part:vendor:product:version:update:edition:language:sw_edition:target_sw:target_hw:other
    """
    if not criteria:
        return {
            "part": None,
            "vendor": None,
            "product": None,
            "version": None,
        }

    parts = criteria.split(":")

    if len(parts) < 6:
        return {
            "part": None,
            "vendor": None,
            "product": None,
            "version": None,
        }

    return {
        "part": parts[2] if len(parts) > 2 else None,
        "vendor": parts[3] if len(parts) > 3 else None,
        "product": parts[4] if len(parts) > 4 else None,
        "version": parts[5] if len(parts) > 5 else None,
    }


def _extract_affected(
        affected: list[dict[str, Any]],
) -> tuple[list[str], list[str], list[str], list[dict[str, Any]]]:
    vendors: set[str] = set()
    products: set[str] = set()
    cpes: set[str] = set()

    affected_versions: list[dict[str, Any]] = []

    for source in affected or []:
        source_name = source.get("source")

        for item in source.get("affectedData", []) or []:
            vendor = _normalize_text(item.get("vendor"))
            product = _normalize_text(item.get("product"))

            if vendor:
                vendors.add(vendor)

            if product:
                products.add(product)

            for cpe in item.get("cpes", []) or []:
                if cpe:
                    cpes.add(cpe)

            for version in item.get("versions", []) or []:
                raw_version = version.get("version")
                specifier = _normalize_specifier(raw_version)

                affected_versions.append(
                    {
                        "source": source_name,
                        "vendor": vendor,
                        "product": product,
                        "raw_version": raw_version,
                        "specifier": specifier,
                        "status": version.get("status"),
                        "lessThan": version.get("lessThan"),
                        "lessThanOrEqual": version.get("lessThanOrEqual"),
                        "versionType": version.get("versionType"),
                    }
                )

    return (
        sorted(vendors),
        sorted(products),
        sorted(cpes),
        affected_versions,
    )


def _extract_configurations(
        configurations: list[dict[str, Any]],
) -> tuple[list[str], list[dict[str, Any]], list[str], list[str]]:
    cpes: set[str] = set()
    matches: list[dict[str, Any]] = []
    config_vendors: set[str] = set()
    config_products: set[str] = set()

    for config in configurations or []:
        for node in config.get("nodes", []) or []:
            stack = [node]

            while stack:
                current = stack.pop()

                for match in current.get("cpeMatch", []) or []:
                    criteria = match.get("criteria")

                    if criteria:
                        cpes.add(criteria)

                    parsed_cpe = _parse_cpe23_uri(criteria)

                    vendor = parsed_cpe["vendor"]
                    product = parsed_cpe["product"]

                    if _is_valid_text(vendor) and vendor != "*":
                        config_vendors.add(vendor)

                    if _is_valid_text(product) and product != "*":
                        config_products.add(product)

                    matches.append(
                        {
                            "criteria": criteria,
                            "vulnerable": match.get("vulnerable"),
                            "part": parsed_cpe["part"],
                            "vendor": parsed_cpe["vendor"],
                            "product": parsed_cpe["product"],
                            "version": parsed_cpe["version"],
                            "versionStartIncluding": match.get("versionStartIncluding"),
                            "versionStartExcluding": match.get("versionStartExcluding"),
                            "versionEndIncluding": match.get("versionEndIncluding"),
                            "versionEndExcluding": match.get("versionEndExcluding"),
                            "matchCriteriaId": match.get("matchCriteriaId"),
                        }
                    )

                stack.extend(current.get("nodes", []) or [])

    return sorted(cpes), matches, sorted(config_vendors), sorted(config_products)


def _extract_cwes(
        weaknesses: list[dict[str, Any]],
) -> list[str]:
    cwes: set[str] = set()

    for weakness in weaknesses or []:
        for desc in weakness.get("description", []) or []:
            value = desc.get("value")
            if value:
                cwes.add(value)

    return sorted(cwes)


def _choose_cvss(
        metrics: dict[str, Any],
) -> dict[str, Any] | None:
    priority = [
        "cvssMetricV40",
        "cvssMetricV31",
        "cvssMetricV30",
        "cvssMetricV2",
    ]

    for key in priority:
        metric_list = metrics.get(key)

        if not metric_list:
            continue

        metric = next(
            (
                item
                for item in metric_list
                if item.get("type") == "Primary"
            ),
            metric_list[0],
        )

        cvss = metric.get("cvssData", {})

        return {
            "version": cvss.get("version"),
            "score": cvss.get("baseScore"),
            "severity": cvss.get("baseSeverity"),
            "vector": cvss.get("vectorString"),
            "source": metric.get("source"),
            "type": metric.get("type"),
            "data": cvss,
        }

    return None


def _extract_ssvc(
        metrics: dict[str, Any],
) -> dict[str, Any] | None:
    items = metrics.get("ssvcV203")

    if not items:
        return None

    ssvc = items[0].get("ssvcData", {})

    result: dict[str, Any] = {}

    for option in ssvc.get("options", []) or []:
        result.update(option)

    result["version"] = ssvc.get("version")
    result["role"] = ssvc.get("role")
    result["timestamp"] = ssvc.get("timestamp")

    return result


def parse_cve(
        cve: dict[str, Any],
) -> dict[str, Any]:
    affected = cve.get("affected", [])
    configurations = cve.get("configurations", [])
    weaknesses = cve.get("weaknesses", [])
    metrics = cve.get("metrics", {})

    (
        vendors,
        products,
        affected_cpes,
        affected_versions,
    ) = _extract_affected(affected)

    (
        config_cpes,
        cpe_matches,
        config_vendors,
        config_products,
    ) = _extract_configurations(configurations)

    cpes = sorted(
        set(affected_cpes).union(config_cpes)
    )

    vendors = sorted(
        set(vendors).union(config_vendors)
    )

    products = sorted(
        set(products).union(config_products)
    )

    cwes = _extract_cwes(weaknesses)

    searchable = sorted(
        set(
            vendors
            + products
            + cpes
            + cwes
        )
    )

    return {
        "_id": cve["id"],
        "year": int(cve["id"][4:8]),

        "published": cve.get("published"),
        "last_modified": cve.get("lastModified"),
        "status": cve.get("vulnStatus"),

        "description": _get_en_description(
            cve.get("descriptions", [])
        ),

        "vendors": vendors,
        "products": products,

        # Fast lookup
        "cpes": cpes,

        # Exact version matching
        "cpe_matches": cpe_matches,

        # CNA version information
        "affected_versions": affected_versions,

        "cwes": cwes,

        "cvss": _choose_cvss(metrics),
        "ssvc": _extract_ssvc(metrics),

        "references": cve.get("references", []),

        # Preserve original structures for LLM reasoning
        "affected": affected,
        "configurations": configurations,

        # Search index
        "searchable": searchable,
    }


def load_nvd_json(
        path: Path,
):
    with open(path, "rb") as f:
        root = orjson.loads(f.read())

    for item in root.get("vulnerabilities", []):
        cve = item.get("cve")

        if cve:
            yield parse_cve(cve)
