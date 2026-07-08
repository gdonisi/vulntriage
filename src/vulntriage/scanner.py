"""Dockerized scanner runners (Nuclei + Nmap).

Wraps the local Docker images built from docker/nuclei/Dockerfile and
docker/nmap/Dockerfile, capturing their output into files the parser can read.

Usage:
    from vulntriage.scanner import run_nuclei, run_nmap
    out = run_nuclei(targets="192.168.1.5", output_path="data/scan.jsonl")
    out = run_nmap(targets="192.168.1.0/24", output_path="data/scan.xml")
    # then parser.parse(out)
"""

from __future__ import annotations

import ipaddress
import re
import shutil
import subprocess
from pathlib import Path
from typing import NamedTuple

_DOCKER_NETWORK = "vuln-net"


def _nuclei_binary() -> str | None:
    """Return the path to the nuclei binary, or ``None`` if not found."""
    return shutil.which("nuclei")


class _DockerResolveResult(NamedTuple):
    hostname: str
    ip: str | None


def _is_ip(s: str) -> bool:
    """Return True if *s* is a bare IPv4 address."""
    try:
        ipaddress.IPv4Address(s)
        return True
    except ipaddress.AddressValueError:
        return False


def _extract_host(s: str) -> str:
    """Extract the bare hostname/IP from a target string.

    Handles:
      - ``hostname``         -> ``hostname``
      - ``hostname:port``    -> ``hostname``
      - ``http://hostname``  -> ``hostname``
      - ``http://h:8080/p``  -> ``h``
      - ``192.168.1.1``      -> ``192.168.1.1`` (passthrough)
    """
    # Strip scheme
    no_scheme = re.sub(r"^https?://", "", s)
    # Strip port and path
    host = no_scheme.split(":", 1)[0] if ":" in no_scheme else no_scheme
    # Remove any trailing slash/path
    host = host.split("/", 1)[0]
    return host


def _is_single_label_hostname(s: str) -> bool:
    """Return True if *s* contains a bare hostname (no dots, not an IP)."""
    host = _extract_host(s)
    return "." not in host and not _is_ip(host)


def _resolve_docker_hostname(hostname: str) -> str | None:
    """Resolve a container name to its IP on the Docker network.

    Uses ``docker inspect`` on the host (requires docker CLI and
    the container to be running on ``vuln-net``).  Returns ``None``
    when the container is not found / not on the expected network.
    """
    clean = _extract_host(hostname)
    try:
        result = subprocess.run(
            [
                "docker",
                "inspect",
                clean,
                "--format",
                '{{index .NetworkSettings.Networks "' + _DOCKER_NETWORK + '" "IPAddress"}}',
            ],
            capture_output=True,
            text=True,
            check=True,
            timeout=10,
        )
        ip = result.stdout.strip()
        return ip if _is_ip(ip) else None
    except (subprocess.CalledProcessError, FileNotFoundError, OSError):
        return None


def _resolve_targets(targets: str | list[str]) -> str:
    """Replace single-label hostnames with their Docker IPs,
    preserving port/path if present."""
    items = [targets] if isinstance(targets, str) else targets
    resolved: list[str] = []
    for t in items:
        if _is_single_label_hostname(t):
            ip = _resolve_docker_hostname(t)
            if ip:
                # Reconstruct: replace hostname with IP, keep port/path
                host = _extract_host(t)
                resolved.append(t.replace(host, ip, 1))
                continue
        resolved.append(t)
    return ",".join(resolved)


def run_nuclei(
    targets: str | list[str],
    output_path: str | Path,
    image: str = "my-nuclei:latest",
    templates: str | None = None,
    extra_args: list[str] | None = None,
) -> Path:
    """Run Nuclei against one or more targets.

    When the ``nuclei`` binary is available on ``$PATH`` (e.g. inside the
    Docker image) it is invoked directly.  Otherwise the function falls back
    to a ``docker run`` call against *image* — hostnames that look like bare
    Docker container names are automatically resolved to their container IP
    via ``docker inspect`` so that nuclei's httpx can reach them inside the
    ``vuln-net`` Docker network.

    Args:
        targets: A single host/URL or a list of them.
        output_path: Where to write the JSONL results.
        image: Docker image tag (used only in the Docker fallback path).
        templates: Optional Nuclei template tag/path filter.
        extra_args: Extra flags forwarded to the nuclei binary.

    Returns:
        The Path to the written JSONL file.
    """
    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)

    binary = _nuclei_binary()
    if binary is not None:
        return _run_nuclei_binary(binary, targets, out, templates, extra_args)
    return _run_nuclei_docker(targets, out, image, templates, extra_args)


def _run_nuclei_binary(
    binary: str,
    targets: str | list[str],
    out: Path,
    templates: str | None,
    extra_args: list[str] | None,
) -> Path:
    """Run the nuclei binary directly (no Docker)."""
    target_list = targets if isinstance(targets, str) else ",".join(targets)
    cmd = [
        binary,
        "-u",
        target_list,
        "-jsonl",
        "-o",
        str(out),
    ]
    if templates:
        cmd.extend(["-t", templates])
    if extra_args:
        cmd.extend(extra_args)

    print(f"[scanner] running nuclei (binary): {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if result.returncode != 0:
        msg = f"nuclei failed (exit {result.returncode}):\n{result.stderr}"
        raise RuntimeError(msg)
    if not out.exists():
        out.write_text("")
    print(f"[scanner] wrote {out}")
    return out


def _run_nuclei_docker(
    targets: str | list[str],
    out: Path,
    image: str,
    templates: str | None,
    extra_args: list[str] | None,
) -> Path:
    """Run nuclei inside a Docker container (host fallback)."""
    target_list = _resolve_targets(targets)

    cmd = [
        "docker",
        "run",
        f"--network={_DOCKER_NETWORK}",
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

    print(f"[scanner] running nuclei (docker): {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if result.returncode != 0:
        msg = f"nuclei failed (exit {result.returncode}):\n{result.stderr}"
        raise RuntimeError(msg)
    if not out.exists():
        out.write_text("")
    print(f"[scanner] wrote {out}")
    return out


# ---------------------------------------------------------------------------
# Nmap scanner runner
# ---------------------------------------------------------------------------


def _nmap_binary() -> str | None:
    """Return the path to the nmap binary, or ``None`` if not found."""
    return shutil.which("nmap")


def run_nmap(
    targets: str | list[str],
    output_path: str | Path,
    image: str = "my-nmap:latest",
    extra_args: list[str] | None = None,
) -> Path:
    """Run Nmap against one or more targets.

    When the ``nmap`` binary is available on ``$PATH`` (e.g. inside the
    Docker image) it is invoked directly.  Otherwise the function falls back
    to a ``docker run`` call against *image* — hostnames that look like bare
    Docker container names are automatically resolved to their container IP
    via ``docker inspect`` so that nmap can reach them inside the
    ``vuln-net`` Docker network.

    Args:
        targets: A single target or a list of them (IPs, CIDR ranges, hostnames).
        output_path: Where to write the XML results.
        image: Docker image tag (used only in the Docker fallback path).
        extra_args: Extra flags forwarded to the nmap binary.

    Returns:
        The Path to the written XML file.
    """
    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)

    binary = _nmap_binary()
    if binary is not None:
        return _run_nmap_binary(binary, targets, out, extra_args)
    return _run_nmap_docker(targets, out, image, extra_args)


def _run_nmap_binary(
    binary: str,
    targets: str | list[str],
    out: Path,
    extra_args: list[str] | None,
) -> Path:
    """Run the nmap binary directly (no Docker)."""
    target_list = targets if isinstance(targets, str) else " ".join(targets)
    cmd = [binary, "-oX", "-", target_list]
    if extra_args:
        cmd.extend(extra_args)

    print(f"[scanner] running nmap (binary): {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if result.returncode != 0:
        msg = f"nmap failed (exit {result.returncode}):\n{result.stderr}"
        raise RuntimeError(msg)
    out.write_text(result.stdout)
    print(f"[scanner] wrote {out}")
    return out


def _run_nmap_docker(
    targets: str | list[str],
    out: Path,
    image: str,
    extra_args: list[str] | None,
) -> Path:
    """Run nmap inside a Docker container (host fallback).

    Nmap XML output is written to stdout via ``-oX -`` and captured here,
    so no volume mount is needed.
    """
    target_list = _resolve_targets(targets)

    cmd = [
        "docker",
        "run",
        f"--network={_DOCKER_NETWORK}",
        "--rm",
        image,
        "-oX",
        "-",
        target_list,
    ]
    if extra_args:
        cmd.extend(extra_args)

    print(f"[scanner] running nmap (docker): {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if result.returncode != 0:
        msg = f"nmap failed (exit {result.returncode}):\n{result.stderr}"
        raise RuntimeError(msg)
    out.write_text(result.stdout)
    print(f"[scanner] wrote {out}")
    return out
