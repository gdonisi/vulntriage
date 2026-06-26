"""Parsers that normalize scanner output into List[RawFinding].

Supported formats:
  - Nmap XML       (.xml)
  - Nuclei JSONL   (.jsonl)
  - Synthetic JSON (.json) — our own schema for test data
"""

from __future__ import annotations

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
    msg = f"Unsupported input format {suffix!r} for {p}"
    raise ValueError(msg)


def _parse_nmap(path: Path) -> list[RawFinding]:
    tree = ET.parse(path)
    root = tree.getroot()
    findings: list[RawFinding] = []
    for host in root.findall("host"):
        addr = host.find("address")
        ip = addr.get("addr") if addr is not None else "unknown"
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
