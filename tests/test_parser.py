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
