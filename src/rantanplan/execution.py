"""
Execution sandbox engine for running external scanner subprocesses safely.
"""

import os
import shutil
import tempfile
import time
import subprocess
from typing import Dict, List, Optional, Tuple

from rantanplan.models import RawExecution, RunProfile, TestCase


class SandboxRunner:
    """Executes subprocess commands without shell=True, applying environment sanitization and resource limits."""

    def __init__(self, timeout_seconds: int = 30):
        self.timeout_seconds = timeout_seconds

    def execute(
        self,
        command: List[str],
        cwd: Optional[str] = None,
        env_overrides: Optional[Dict[str, str]] = None,
        scanner_name: str = "generic",
    ) -> RawExecution:
        if not command:
            return RawExecution(
                scanner=scanner_name,
                command=[],
                exit_code=-1,
                stdout="",
                stderr="Empty command slice",
                duration_ms=0,
                error_message="Empty command slice",
            )

        # Environment Sanitization
        temp_home = tempfile.mkdtemp(prefix="rantanplan-home-")
        safe_env = {
            "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
            "HOME": temp_home,
            "TMPDIR": tempfile.gettempdir(),
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
        }

        # Add explicit non-secret env overrides
        if env_overrides:
            for k, v in env_overrides.items():
                safe_env[k] = v

        start_time = time.time()
        timed_out = False
        stdout_str = ""
        stderr_str = ""
        exit_code = -1

        try:
            process = subprocess.Popen(
                command,
                cwd=cwd,
                env=safe_env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                shell=False,  # SAFETY: Never execute via shell wrapper
            )

            try:
                stdout_str, stderr_str = process.communicate(timeout=self.timeout_seconds)
                exit_code = process.returncode
            except subprocess.TimeoutExpired:
                timed_out = True
                process.kill()
                stdout_str, stderr_str = process.communicate()
                exit_code = -1
        except Exception as e:
            stderr_str = f"Execution error: {str(e)}"
            exit_code = -1
        finally:
            shutil.rmtree(temp_home, ignore_errors=True)

        duration_ms = int((time.time() - start_time) * 1000)

        return RawExecution(
            scanner=scanner_name,
            command=command,
            exit_code=exit_code,
            stdout=stdout_str or "",
            stderr=stderr_str or "",
            duration_ms=duration_ms,
            timed_out=timed_out,
            error_message="Execution timed out" if timed_out else None,
        )


def create_temp_fixture_dir(files: List[Dict[str, str]]) -> Tuple[str, callable]:
    """Creates a temporary workspace containing the fixture files."""
    tmp_dir = tempfile.mkdtemp(prefix="rantanplan-fixture-")

    def cleanup():
        shutil.rmtree(tmp_dir, ignore_errors=True)

    for file_info in files:
        rel_path = file_info.get("path", "SKILL.md")
        content = file_info.get("content", "")
        full_path = os.path.join(tmp_dir, rel_path)

        os.makedirs(os.path.dirname(full_path), exist_ok=True)
        with open(full_path, "w", encoding="utf-8") as f:
            f.write(content)

    return tmp_dir, cleanup

