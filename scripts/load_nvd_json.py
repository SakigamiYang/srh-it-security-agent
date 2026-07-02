from pathlib import Path
from typing import Any

import orjson


def _get_en_description(descriptions: list[dict[str, Any]]) -> str | None:
    for item in descriptions:
        if item.get("lang") == "en":
            return item.get("value")
    return descriptions[0]["value"] if descriptions else None


def _extract_vendors_products_cpes(affected: list[dict[str, Any]]) -> tuple[list[str], list[str], list[str]]:
    vendors: set[str] = set()
    products: set[str] = set()
    cpes: set[str] = set()

    for source in affected or []:
        for item in source.get("affectedData", []):
            vendor = item.get("vendor")
            product = item.get("product")

            if vendor:
                vendors.add(vendor)

            if product:
                products.add(product)

            for cpe in item.get("cpes", []):
                cpes.add(cpe)

    return sorted(vendors), sorted(products), sorted(cpes)


def _extract_config_cpes(configurations: list[dict[str, Any]]) -> list[str]:
    result: set[str] = set()

    for config in configurations or []:
        for node in config.get("nodes", []):

            stack = [node]

            while stack:
                current = stack.pop()

                for match in current.get("cpeMatch", []):
                    criteria = match.get("criteria")
                    if criteria:
                        result.add(criteria)

                stack.extend(current.get("nodes", []))

    return sorted(result)


def _extract_cwes(weaknesses: list[dict[str, Any]]) -> list[str]:
    result: set[str] = set()

    for weakness in weaknesses or []:
        for desc in weakness.get("description", []):
            value = desc.get("value")
            if value:
                result.add(value)

    return sorted(result)


def _choose_cvss(metrics: dict[str, Any]) -> dict[str, Any] | None:
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

        primary = None

        for metric in metric_list:
            if metric.get("type") == "Primary":
                primary = metric
                break

        metric = primary or metric_list[0]

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


def _extract_ssvc(metrics: dict[str, Any]) -> dict[str, Any] | None:
    items = metrics.get("ssvcV203")

    if not items:
        return None

    ssvc = items[0].get("ssvcData", {})

    result = {}

    for option in ssvc.get("options", []):
        result.update(option)

    result["version"] = ssvc.get("version")
    result["role"] = ssvc.get("role")
    result["timestamp"] = ssvc.get("timestamp")

    return result


def parse_cve(cve: dict[str, Any]) -> dict[str, Any]:
    affected = cve.get("affected", [])
    configurations = cve.get("configurations", [])
    weaknesses = cve.get("weaknesses", [])
    metrics = cve.get("metrics", {})

    vendors, products, affected_cpes = _extract_vendors_products_cpes(affected)
    config_cpes = _extract_config_cpes(configurations)

    cpes = sorted(set(affected_cpes + config_cpes))

    cwes = _extract_cwes(weaknesses)

    doc = {
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
        "cpes": cpes,
        "cwes": cwes,

        "cvss": _choose_cvss(metrics),
        "ssvc": _extract_ssvc(metrics),

        "references": cve.get("references", []),

        # keep original structures for LLM
        "affected": affected,
        "configurations": configurations,

        "searchable": sorted(
            set(
                vendors
                + products
                + cpes
                + cwes
            )
        ),
    }

    return doc


def load_nvd_json(path: Path):
    with open(path, "rb") as f:
        root = orjson.loads(f.read())

    for item in root["vulnerabilities"]:
        yield parse_cve(item["cve"])
