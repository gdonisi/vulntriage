"""Tests for the scanner input parsers."""

from __future__ import annotations

from pathlib import Path

import pytest

from vulntriage.parser import parse

DATA_DIR = Path(__file__).resolve().parent.parent / "data"


def test_parse_openvas_csv():
    """Parse a real OpenVAS CSV export and verify all findings are well-formed."""
    findings = parse(str(DATA_DIR / "openvas_sample.csv"))
    assert len(findings) == 14

    # Verify the general shape of every finding.
    for f in findings:
        assert f.source == "openvas"
        assert f.id.startswith("openvas-")
        assert f.host and f.host != "unknown"
        # Some findings may not have a port (rare), but all 14 in the sample do.
        assert isinstance(f.port, int) if f.port is not None else True
        assert f.description
        assert f.raw, "raw row dict should be populated"

    # Verify specific known findings from the sample.
    apache = next(f for f in findings if f.port == 80 and f.host == "192.168.10.25")
    assert apache.cvss == 8.1
    assert apache.cve == "CVE-2026-10001"
    assert "Apache HTTP Server" in apache.description
    assert "Apache 2.4.52" in apache.service

    # There are two port 3306 findings; pick the empty-password one (CVSS 5.0).
    mysql = next(
        f for f in findings
        if f.port == 3306 and f.host == "192.168.10.30" and f.cvss == 5.0
    )
    assert mysql.cvss == 5.0
    assert mysql.cve is None
    assert "Empty Password" in mysql.description


def test_parse_openvas_no_cve():
    """Findings with an empty CVEs column get cve=None."""
    findings = parse(str(DATA_DIR / "openvas_sample.csv"))
    # The SSH weak KEX finding has no CVE (row 2 in the sample).
    ssh = next(f for f in findings if f.port == 22)
    assert ssh.cve is None
    assert ssh.cvss == 5.3


def test_parse_openvas_unknown_format_raises():
    """Unsupported file extensions raise ValueError."""
    with pytest.raises(ValueError, match="Unsupported input format"):
        parse("data/unknown_file.docx")


def test_parse_nuclei_info_null(tmp_path):
    """A ``info: null`` nuclei record must not crash the parser."""
    p = tmp_path / "scan.jsonl"
    p.write_text(
        '{"template-id": "x", "info": null, "host": "10.0.0.1", '
        '"matched-at": "http://10.0.0.1"}\n'
    )
    findings = parse(str(p))
    assert len(findings) == 1
    assert findings[0].source == "nuclei"
    assert findings[0].cvss is None
    assert findings[0].cve is None


def test_parse_nuclei_non_numeric_cvss(tmp_path):
    """A non-numeric ``cvss-score`` (e.g. "N/A") must become None, not raise."""
    p = tmp_path / "scan.jsonl"
    p.write_text(
        '{"template-id": "y", "info": {"name": "Y", "severity": "info", '
        '"classification": {"cvss-score": "N/A", "cve-id": null}}, '
        '"host": "10.0.0.2"}\n'
    )
    findings = parse(str(p))
    assert len(findings) == 1
    assert findings[0].cvss is None


def test_parse_openvas_non_numeric_port(tmp_path):
    """A non-numeric Port (e.g. "general") must become None, not raise."""
    p = tmp_path / "openvas.csv"
    p.write_text(
        "IP,Port,Port Protocol,NVT Name,CVEs,Summary\n"
        "10.0.0.3,general,tcp,Some Finding,,desc\n"
    )
    findings = parse(str(p))
    assert len(findings) == 1
    assert findings[0].port is None
    assert findings[0].host == "10.0.0.3"
