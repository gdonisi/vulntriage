"""Dockerized Nuclei scanner runner.

Wraps the local Docker image built from docker/nuclei/Dockerfile and captures
its JSONL output into a file the parser can read.

Usage:
    from vulntriage.scanner import run_nuclei
    out = run_nuclei(targets="192.168.1.5", output_path="data/scan.jsonl")
    # then parser.parse(out)
"""

from __future__ import annotations

import subprocess
from pathlib import Path


def run_nuclei(
    targets: str | list[str],
    output_path: str | Path,
    image: str = "my-nuclei:latest",
    templates: str | None = None,
    extra_args: list[str] | None = None,
) -> Path:
    """Run the dockerized Nuclei image against one or more targets.

    Args:
        targets: A single host/URL or a list of them.
        output_path: Where to write the JSONL results.
        image: Docker image tag (build with: docker build -t my-nuclei:latest docker/nuclei).
        templates: Optional Nuclei template tag/path filter.
        extra_args: Extra flags forwarded to the nuclei binary.

    Returns:
        The Path to the written JSONL file.
    """
    if isinstance(targets, list):
        target_list = ",".join(targets)
    else:
        target_list = targets

    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)

    cmd = [
        "docker",
        "run",
        "--rm",
        "-v",
        f"{out.parent.resolve()}:/out",
        image,
        "-u",
        target_list,
        "-jsonl",
        "-o",
        f"/out/{out.name}",
    ]
    if templates:
        cmd.extend(["-t", templates])
    if extra_args:
        cmd.extend(extra_args)

    print(f"[scanner] running nuclei: {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if result.returncode != 0:
        msg = f"nuclei failed (exit {result.returncode}):\n{result.stderr}"
        raise RuntimeError(msg)
    if not out.exists():
        out.write_text("")
    print(f"[scanner] wrote {out}")
    return out
