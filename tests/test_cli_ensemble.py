"""CLI tests for --ensemble / --quorum."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

from vulntriage.cli import build_parser, main

DATA_DIR = Path(__file__).resolve().parent.parent / "data"


class _Client:
    total_tokens = 0

    def __init__(self, model: str, label: str) -> None:
        self.model = model
        self._label = label

    def complete(self, system: str, user: str) -> str:
        if "remediation guidance" in user or "senior security engineer" in system:
            return json.dumps({"rationale": "x", "steps": ["a"]})
        if "exploitability" in user.lower() or "rate this finding" in user.lower():
            return json.dumps({"exploitability": self._label, "rationale": "mock"})
        return json.dumps({"context": "ctx"})


def _make_client_factory():
    """Returns a fake make_client that maps model name -> canned label."""
    registry = {
        "primary": "High",
        "a": "High",
        "b": "Medium",
    }

    def _make(provider, model, reasoning_effort=None):
        return _Client(model, registry.get(model, "Medium"))

    return _make


def test_ensemble_arg_parses():
    p = build_parser()
    a = p.parse_args(
        [
            "--input",
            "x.json",
            "--provider",
            "lmstudio",
            "--model",
            "primary",
            "--ensemble",
            "ollama:a,lmstudio:b",
            "--quorum",
            "2",
        ]
    )
    assert a.ensemble == "ollama:a,lmstudio:b"
    assert a.quorum == 2


def test_ensemble_runs_pipeline_and_merges(tmp_path, capsys):
    fake = _make_client_factory()
    run_dir = tmp_path / "out"
    with patch("vulntriage.cli.make_client", side_effect=fake):
        rc = main(
            [
                "--input",
                str(DATA_DIR / "synthetic_findings.json"),
                "--provider",
                "lmstudio",
                "--model",
                "primary",
                "--ensemble",
                "ollama:a,lmstudio:b",
                "--output",
                str(run_dir),
                "--output-format",
                "html",
            ]
        )
    assert rc == 0
    # primary=High, a=High, b=Medium -> quorum 2 -> High resolved for every finding.
    # intermediates are not saved by default; just assert the report was written.
    assert (run_dir / "report.html").exists()


def test_ensemble_invalid_member_rejected(capsys):
    rc = main(
        [
            "--input",
            str(DATA_DIR / "synthetic_findings.json"),
            "--provider",
            "lmstudio",
            "--model",
            "primary",
            "--ensemble",
            "no-colon-here",
        ]
    )
    assert rc == 2
    assert "Invalid --ensemble member" in capsys.readouterr().err


def test_local_only_blocks_ensemble_cloud_member(capsys):
    rc = main(
        [
            "--input",
            str(DATA_DIR / "synthetic_findings.json"),
            "--provider",
            "lmstudio",
            "--model",
            "primary",
            "--ensemble",
            "openai:gpt-4o-mini",
            "--local-only",
        ]
    )
    assert rc == 2
    err = capsys.readouterr().err
    assert "openai:gpt-4o-mini" in err
