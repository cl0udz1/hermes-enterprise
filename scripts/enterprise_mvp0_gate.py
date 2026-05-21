"""Run the downstream Enterprise MVP-0 release gate."""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]


@dataclass(frozen=True)
class GateStep:
    name: str
    command: tuple[str, ...]


def _run_step(step: GateStep) -> None:
    printable = " ".join(step.command)
    print(f"\n==> {step.name}", flush=True)
    print(printable, flush=True)
    subprocess.run(step.command, cwd=REPO_ROOT, check=True)


def _cleanup_basetemps() -> None:
    for name in (".pytest-tmp-enterprise", ".pytest-tmp-enterprise-upstream"):
        target = (REPO_ROOT / name).resolve()
        try:
            target.relative_to(REPO_ROOT)
        except ValueError:
            raise RuntimeError(f"Refusing to remove path outside repo: {target}") from None
        if target.exists():
            shutil.rmtree(target)


def _steps(python: str, *, include_upstream_targets: bool) -> list[GateStep]:
    steps = [
        GateStep(
            "Enterprise package compile check",
            (python, "-m", "compileall", "-q", "enterprise"),
        ),
        GateStep(
            "Enterprise MVP-0 package tests",
            (
                python,
                "-m",
                "pytest",
                "-o",
                "addopts=",
                "--basetemp",
                ".pytest-tmp-enterprise",
                "tests/enterprise",
            ),
        ),
    ]
    if include_upstream_targets:
        steps.append(
            GateStep(
                "Targeted Hermes authority seam regression tests",
                (
                    python,
                    "-m",
                    "pytest",
                    "-o",
                    "addopts=",
                    "--basetemp",
                    ".pytest-tmp-enterprise-upstream",
                    "tests/run_agent/test_tool_call_guardrail_runtime.py",
                    "tests/run_agent/test_tool_name_db_persistence.py",
                    "tests/hermes_cli/test_doctor.py::TestDoctorToolAvailabilityOverrides",
                ),
            )
        )
    return steps


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--python",
        default=sys.executable,
        help="Python executable to use for gate commands.",
    )
    parser.add_argument(
        "--skip-upstream-targets",
        action="store_true",
        help="Run only enterprise package checks.",
    )
    args = parser.parse_args(argv)

    _cleanup_basetemps()
    try:
        for step in _steps(args.python, include_upstream_targets=not args.skip_upstream_targets):
            _run_step(step)
    finally:
        _cleanup_basetemps()
    print("\nEnterprise MVP-0 gate passed.", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
