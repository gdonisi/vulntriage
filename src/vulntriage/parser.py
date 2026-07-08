"""Parsers that normalize scanner output into List[RawFinding].

Supported formats:
  - Nmap XML       (.xml)
  - Nuclei JSONL   (.jsonl)
  - Synthetic JSON (.json) — our own schema for test data
  - OpenVAS CSV    (.csv)  — Greenbone OpenVAS exported results
"""

from __future__ import annotations

import csv
import json
import uuid
import xml.etree.ElementTree as ET
from pathlib import Path

from .models import RawFinding


def parse(path: str | Path) -> list[RawFinding]:
    """Auto-detect format from file extension and parse accordingly."""
    p = Path(path)
    suffix = p.suffix.lower()
    if suffix == ".xml":
        return _parse_nmap(p)
    if suffix == ".jsonl":
        return _parse_nuclei(p)
    if suffix == ".json":
        return _parse_synthetic(p)
    if suffix == ".csv":
        return _parse_openvas(p)
    msg = f"Unsupported input format {suffix!r} for {p}"
    raise ValueError(msg)


def _parse_nmap(path: Path) -> list[RawFinding]:
    tree = ET.parse(path)
    root = tree.getroot()
    findings: list[RawFinding] = []
    for host in root.findall("host"):
        addr = host.find("address")
        ip = addr.get("addr", "unknown") if addr is not None else "unknown"
        for port_el in host.iter("port"):
            port_id = int(port_el.get("portid", "0"))
            state_el = port_el.find("state")
            state = state_el.get("state") if state_el is not None else "unknown"
            if state != "open":
                continue
            service_el = port_el.find("service")
            service = service_el.get("name") if service_el is not None else None
            product = service_el.get("product") if service_el is not None else ""
            version = service_el.get("version") if service_el is not None else ""
            desc_parts = [f"Open {port_id}/tcp"]
            if service:
                desc_parts.append(service)
            if product or version:
                desc_parts.append(f"{product} {version}".strip())
            desc = " — ".join(desc_parts)
            findings.append(
                RawFinding(
                    id=f"nmap-{ip}-{port_id}-{uuid.uuid4().hex[:8]}",
                    source="nmap",
                    host=ip,
                    port=port_id,
                    service=service,
                    description=desc,
                    raw={
                        "port": port_id,
                        "state": state,
                        "service": service,
                        "product": product,
                        "version": version,
                    },
                )
            )
    return findings


def _parse_nuclei(path: Path) -> list[RawFinding]:
    findings: list[RawFinding] = []
    with path.open() as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            record = json.loads(line)
            template_id = record.get("template-id", "unknown")
            info = record.get("info", {})
            name = info.get("name", template_id)
            severity = info.get("severity", "")
            tags = info.get("tags", [])
            classification = info.get("classification", {})
            cvss = classification.get("cvss-score")
            cve_id = None
            cve_list = classification.get("cve-id") or info.get("classification", {}).get("cve-id")
            if isinstance(cve_list, list) and cve_list:
                cve_id = cve_list[0]
            elif isinstance(cve_list, str):
                cve_id = cve_list
            desc = f"{name} (severity: {severity})"
            if tags:
                desc += f" [tags: {', '.join(tags)}]"
            findings.append(
                RawFinding(
                    id=f"nuclei-{template_id}-{uuid.uuid4().hex[:8]}",
                    source="nuclei",
                    host=record.get("host", record.get("matched-at", "unknown")),
                    description=desc,
                    cvss=float(cvss) if cvss else None,
                    cve=cve_id,
                    raw=record,
                )
            )
    return findings


def _parse_openvas(path: Path) -> list[RawFinding]:
    """Parse a Greenbone OpenVAS CSV export into RawFindings.

    Expected columns (from the GSA CSV export dialog):
      IP, Hostname, Port, Port Protocol, CVSS, Severity, Solution Type,
      NVT Name, Summary, Specific Result, NVT OID, CVEs, Task ID,
      Task Name, Timestamp, Result ID, Impact, Solution,
      Affected Software/OS, Vulnerability Insight, Vulnerability Detection Method,
      Product Detection Result, BIDs, CERTs, Other References
    """
    findings: list[RawFinding] = []
    # The CSV may carry a BOM; utf-8-sig handles it transparently.
    with path.open(newline="", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        for row in reader:
            ip = row.get("IP") or "unknown"
            port_str = (row.get("Port") or "").strip()
            port = int(port_str) if port_str else None

            # Derive a service label from the affected software / product detection,
            # falling back to the port protocol.
            service = (
                row.get("Affected Software/OS")
                or row.get("Product Detection Result")
                or row.get("Port Protocol")
                or None
            )

            # Build a human-readable description from the most informative columns.
            nvt_name = row.get("NVT Name") or ""
            summary = row.get("Summary") or ""
            specific_result = row.get("Specific Result") or ""
            desc_parts: list[str] = []
            if nvt_name:
                desc_parts.append(nvt_name)
            if summary:
                desc_parts.append(summary)
            if specific_result:
                desc_parts.append(f"Result: {specific_result}")
            description = " — ".join(desc_parts) if desc_parts else "OpenVAS finding"

            # CVSS
            cvss_raw = (row.get("CVSS") or "").strip()
            cvss: float | None = None
            if cvss_raw:
                try:
                    cvss = float(cvss_raw)
                except ValueError:
                    pass

            # CVE — semicolon-separated list; take the first one.
            cves_raw = (row.get("CVEs") or "").strip()
            cve: str | None = None
            if cves_raw:
                cve = cves_raw.split(";", 1)[0].strip() or None

            # Unique identifier: OID + Result ID.
            oid = (row.get("NVT OID") or "").strip()
            result_id = (row.get("Result ID") or "").strip()
            if oid and result_id:
                finding_id = f"openvas-{oid}-{result_id}"
            else:
                finding_id = f"openvas-{uuid.uuid4().hex[:8]}"

            findings.append(
                RawFinding(
                    id=finding_id,
                    source="openvas",
                    host=ip,
                    port=port,
                    service=service,
                    description=description,
                    cvss=cvss,
                    cve=cve,
                    raw=dict(row),
                )
            )
    return findings


def _parse_synthetic(path: Path) -> list[RawFinding]:
    data = json.loads(path.read_text())
    findings: list[RawFinding] = []
    for i, item in enumerate(data):
        findings.append(
            RawFinding(
                id=item.get("id", f"synthetic-{i}"),
                source="synthetic",
                host=item.get("host", "unknown"),
                port=item.get("port"),
                service=item.get("service"),
                description=item["description"],
                cvss=item.get("cvss"),
                cve=item.get("cve"),
                raw=item,
            )
        )
    return findings
