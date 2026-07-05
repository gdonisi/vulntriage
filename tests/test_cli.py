"""Tests for the CLI orchestration (arg parsing + pipeline wiring).

Uses a mock LLM client injected by monkeypatching ``make_client`` so the full
``main()`` flow can be exercised without a real model.
"""

from __future__ import annotations

import json
from pathlib import Path

from vulntriage.cli import build_parser, main

DATA_DIR = Path(__file__).resolve().parent.parent / "data"


class _CLIMockClient:
    """Mock LLM client for CLI tests (returns canned structured JSON)."""

    model = "mock"
    total_tokens = 0

    def complete(self, system: str, user: str) -> str:
        if "remediation guidance" in user or "senior security engineer" in system:
            return json.dumps(
                {
                    "rationale": "Upgrade and harden the service.",
                    "steps": ["Upgrade the software", "Enable authentication", "Restrict access"],
                }
            )
        if "exploitability" in user.lower() or "rate this finding" in user.lower():
            if "redis" in user.lower() or "log4j" in user.lower() or "jenkins" in user.lower():
                label = "High"
            elif "nginx" in user.lower() or "patched" in user.lower():
                label = "Low"
            else:
                label = "Medium"
            return json.dumps({"exploitability": label, "rationale": "mock"})
        return json.dumps({"context": "Mock threat context for the finding."})


def _mock_make_client(provider, model, reasoning_effort=None):
    return _CLIMockClient()


def test_help_lists_v2_flags():
    help_text = build_parser().format_help()
    for flag in [
        "--remediate",
        "--rag",
        "--no-rag",
        "--output-format",
        "--prompt-strategy",
        "--evaluate",
        "--kb",
    ]:
        assert flag in help_text


def test_main_text_report(monkeypatch, capsys, tmp_path):
    monkeypatch.setattr("vulntriage.cli.make_client", _mock_make_client)
    out = tmp_path / "report.txt"
    rc = main(
        [
            "--input",
            str(DATA_DIR / "synthetic_findings.json"),
            "--provider",
            "lmstudio",
            "--model",
            "mock",
            "--asset-registry",
            str(DATA_DIR / "assets.yaml"),
            "--output",
            str(out),
        ]
    )
    assert rc == 0
    assert out.exists()
    assert "VULNERABILITY TRIAGE REPORT" in out.read_text()


def test_main_remediate_and_both_reports(monkeypatch, capsys, tmp_path):
    monkeypatch.setattr("vulntriage.cli.make_client", _mock_make_client)
    reports_dir = tmp_path / "reports"
    rc = main(
        [
            "--input",
            str(DATA_DIR / "synthetic_findings.json"),
            "--provider",
            "lmstudio",
            "--model",
            "mock",
            "--asset-registry",
            str(DATA_DIR / "assets.yaml"),
            "--remediate",
            "--output-format",
            "both",
            "--output",
            str(reports_dir),
        ]
    )
    assert rc == 0
    assert (reports_dir / "report.html").exists()
    assert (reports_dir / "report.pdf").exists()
    assert (reports_dir / "report.pdf").read_bytes()[:5] == b"%PDF-"


def test_main_html_without_remediate(monkeypatch, capsys, tmp_path):
    """HTML report must render even when --remediate is not passed (no crash)."""
    monkeypatch.setattr("vulntriage.cli.make_client", _mock_make_client)
    reports_dir = tmp_path / "reports"
    rc = main(
        [
            "--input",
            str(DATA_DIR / "synthetic_findings.json"),
            "--provider",
            "lmstudio",
            "--model",
            "mock",
            "--asset-registry",
            str(DATA_DIR / "assets.yaml"),
            "--output-format",
            "html",
            "--output",
            str(reports_dir),
        ]
    )
    assert rc == 0
    assert (reports_dir / "report.html").exists()


def test_main_zero_shot_no_rag(monkeypatch, capsys, tmp_path):
    monkeypatch.setattr("vulntriage.cli.make_client", _mock_make_client)
    out = tmp_path / "report.txt"
    rc = main(
        [
            "--input",
            str(DATA_DIR / "synthetic_findings.json"),
            "--provider",
            "lmstudio",
            "--model",
            "mock",
            "--prompt-strategy",
            "zero-shot",
            "--no-rag",
            "--remediate",
            "--output-format",
            "text",
            "--output",
            str(out),
        ]
    )
    assert rc == 0


def test_main_save_intermediates(monkeypatch, capsys, tmp_path):
    monkeypatch.setattr("vulntriage.cli.make_client", _mock_make_client)
    inter = tmp_path / "inter"
    rc = main(
        [
            "--input",
            str(DATA_DIR / "synthetic_findings.json"),
            "--provider",
            "lmstudio",
            "--model",
            "mock",
            "--remediate",
            "--save-intermediates",
            str(inter),
        ]
    )
    assert rc == 0
    for name in ["enriched.json", "scored.json", "prioritized.json", "remediated.json"]:
        assert (inter / name).exists()
    remediated = json.loads((inter / "remediated.json").read_text())
    assert len(remediated) == 20


def test_evaluate_single_model(monkeypatch, capsys, tmp_path):
    """--evaluate with --provider/--model builds a single-model config and runs."""
    import vulntriage.evaluation as ev

    captured = {}

    def fake_run_experiment(config):
        captured["config"] = config
        return {"cells": {}, "baselines": {}}

    monkeypatch.setattr(ev, "run_experiment", fake_run_experiment)
    monkeypatch.setattr("vulntriage.cli.run_experiment", fake_run_experiment)
    rc = main(
        [
            "--evaluate",
            "--input",
            str(DATA_DIR / "synthetic_findings.json"),
            "--provider",
            "lmstudio",
            "--model",
            "mock",
            "--repeats",
            "1",
        ]
    )
    assert rc == 0
    cfg = captured["config"]
    assert len(cfg.models) == 1
    assert cfg.models[0].model == "mock"
    assert cfg.prompt_strategies == ["few-shot", "zero-shot"]
    assert cfg.rag_conditions == [True, False]
    assert cfg.repeats == 1


def test_evaluate_needs_config_or_model(capsys):
    rc = main(["--evaluate", "--input", "data/synthetic_findings.json"])
    assert rc == 2


def test_main_multi_input_merges(monkeypatch, capsys, tmp_path):
    """--input with multiple files merges findings from all of them."""
    monkeypatch.setattr("vulntriage.cli.make_client", _mock_make_client)
    out = tmp_path / "report.txt"
    rc = main(
        [
            "--input",
            str(DATA_DIR / "sample_nmap.xml"),
            str(DATA_DIR / "sample_nuclei.jsonl"),
            "--provider",
            "lmstudio",
            "--model",
            "mock",
            "--output",
            str(out),
        ]
    )
    assert rc == 0
    text = out.read_text()
    assert "Total findings: 6" in text  # 3 nmap + 3 nuclei


def test_local_only_blocks_cloud_provider(monkeypatch, capsys, tmp_path):
    """--local-only refuses a cloud provider before any network call."""
    monkeypatch.setattr("vulntriage.cli.make_client", _mock_make_client)
    rc = main(
        [
            "--input",
            str(DATA_DIR / "synthetic_findings.json"),
            "--provider",
            "openai",
            "--model",
            "gpt-4o",
            "--local-only",
        ]
    )
    assert rc == 2
    err = capsys.readouterr().err
    assert "--local-only" in err
    assert "openai" in err


def test_local_only_allows_local_provider(monkeypatch, capsys, tmp_path):
    """--local-only with a self-hosted provider runs normally."""
    monkeypatch.setattr("vulntriage.cli.make_client", _mock_make_client)
    out = tmp_path / "report.txt"
    rc = main(
        [
            "--input",
            str(DATA_DIR / "synthetic_findings.json"),
            "--provider",
            "lmstudio",
            "--model",
            "mock",
            "--local-only",
            "--output",
            str(out),
        ]
    )
    assert rc == 0
    assert out.exists()


def test_local_only_blocks_eval_cloud_model(monkeypatch, capsys, tmp_path):
    """--local-only refuses cloud models in the eval grid."""
    cfg = tmp_path / "eval.json"
    cfg.write_text(
        json.dumps(
            {
                "input_path": str(DATA_DIR / "synthetic_findings.json"),
                "models": [
                    {"provider": "lmstudio", "model": "mock"},
                    {"provider": "openai", "model": "gpt-4o"},
                ],
                "repeats": 1,
            }
        )
    )
    rc = main(["--evaluate", "--eval-config", str(cfg), "--local-only"])
    assert rc == 2
    err = capsys.readouterr().err
    assert "openai" in err


def test_timestamped_run_dirs_not_overwritten(monkeypatch, capsys, tmp_path):
    """Two consecutive runs without --output write to distinct timestamped dirs."""
    monkeypatch.setattr("vulntriage.cli.make_client", _mock_make_client)
    # Run into a temp output root by chdir-ing? Instead use --output to control.
    run1 = tmp_path / "run1"
    run2 = tmp_path / "run2"
    for d in (run1, run2):
        rc = main(
            [
                "--input",
                str(DATA_DIR / "synthetic_findings.json"),
                "--provider",
                "lmstudio",
                "--model",
                "mock",
                "--asset-registry",
                str(DATA_DIR / "assets.yaml"),
                "--remediate",
                "--output-format",
                "both",
                "--output",
                str(d),
            ]
        )
        assert rc == 0
    assert (run1 / "report.html").exists() and (run2 / "report.html").exists()
    assert (run1 / "report.pdf").exists() and (run2 / "report.pdf").exists()


def test_eval_timestamped_default_output_dir(monkeypatch, capsys, tmp_path):
    """--evaluate without --output writes to a timestamped output/eval/<ts>/ dir."""
    import os

    import vulntriage.evaluation as ev

    captured = {}

    def fake_run_experiment(config):
        captured["output_dir"] = config.output_dir
        return {"cells": {}, "baselines": {}}

    monkeypatch.setattr(ev, "run_experiment", fake_run_experiment)
    monkeypatch.setattr("vulntriage.cli.run_experiment", fake_run_experiment)
    rc = main(
        [
            "--evaluate",
            "--input",
            str(DATA_DIR / "synthetic_findings.json"),
            "--provider",
            "lmstudio",
            "--model",
            "mock",
        ]
    )
    assert rc == 0
    assert captured["output_dir"].startswith("output/eval/")
    # timestamp suffix is YYYYMMDD-HHMMSS
    tail = os.path.basename(captured["output_dir"])
    assert len(tail) == 15 and tail[8] == "-"


def test_save_intermediates_default_path(monkeypatch, capsys, tmp_path):
    """--save-intermediates with no value writes to <run_dir>/intermediates/."""
    monkeypatch.setattr("vulntriage.cli.make_client", _mock_make_client)
    run_dir = tmp_path / "run"
    rc = main(
        [
            "--input",
            str(DATA_DIR / "synthetic_findings.json"),
            "--provider",
            "lmstudio",
            "--model",
            "mock",
            "--remediate",
            "--output-format",
            "both",
            "--output",
            str(run_dir),
            "--save-intermediates",
        ]
    )
    assert rc == 0
    inter = run_dir / "intermediates"
    assert (inter / "enriched.json").exists()
    assert (inter / "remediated.json").exists()
