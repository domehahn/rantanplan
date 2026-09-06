"""
Execution sandbox engine with dynamic binary resolution and real version discovery.
"""

import hashlib
import os
import shutil
import subprocess
import tempfile
import time

from rantanplan.models import ExecutionStatus, RawExecution


def resolve_binary_path(tool_name: str, cli_override: str | None = None) -> str:
    """
    Executable resolution order:
    1. Explicit CLI override
    2. Environment variable RANTANPLAN_<TOOL_NAME>_BIN
    3. Configuration path
    4. PATH discovery via shutil.which
    """
    if cli_override and os.path.exists(cli_override):
        return cli_override

    env_var_name = f"RANTANPLAN_{tool_name.upper().replace('-', '_')}_BIN"
    env_override = os.environ.get(env_var_name)
    if env_override and os.path.exists(env_override):
        return env_override

    found_path = shutil.which(tool_name)
    if found_path:
        return found_path

    return tool_name  # Return binary name for PATH lookup attempt


def discover_binary_version(binary_path: str) -> str:
    """Discovers real version of binary by calling --version or version."""
    if not shutil.which(binary_path) and not os.path.exists(binary_path):
        return "VERSION_UNKNOWN"

    for flag in ["--version", "version", "-v"]:
        try:
            res = subprocess.run(
                [binary_path, flag],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=5,
                shell=False,
            )
            out = (res.stdout or res.stderr).strip()
            if out and res.returncode == 0:
                first_line = out.split("\n")[0]
                return first_line[:64]
        except Exception:
            continue

    return "VERSION_UNKNOWN"


def compute_file_sha256(file_path: str) -> str | None:
    if not os.path.exists(file_path):
        return None
    try:
        hasher = hashlib.sha256()
        with open(file_path, "rb") as f:
            while chunk := f.read(8192):
                hasher.update(chunk)
        return hasher.hexdigest()
    except Exception:
        return None


class SandboxRunner:
    """Executes subprocess commands without shell=True, applying environment sanitization and resource limits."""

    def __init__(self, timeout_seconds: int = 30):
        self.timeout_seconds = timeout_seconds

    def execute(
        self,
        command: list[str],
        cwd: str | None = None,
        env_overrides: dict[str, str] | None = None,
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
                execution_status=ExecutionStatus.INVALID_COMMAND,
                error_message="Empty command slice",
            )

        temp_home = tempfile.mkdtemp(prefix="rantanplan-home-")
        safe_env = {
            "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
            "HOME": temp_home,
            "TMPDIR": tempfile.gettempdir(),
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
        }

        if env_overrides:
            for k, v in env_overrides.items():
                safe_env[k] = v

        start_time = time.time()
        timed_out = False
        stdout_str = ""
        stderr_str = ""
        exit_code = -1
        exec_status = ExecutionStatus.SUCCESS

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
                if exit_code != 0 and exit_code != 1:
                    exec_status = ExecutionStatus.TARGET_ERROR
            except subprocess.TimeoutExpired:
                timed_out = True
                process.kill()
                stdout_str, stderr_str = process.communicate()
                exit_code = -1
                exec_status = ExecutionStatus.TIMEOUT
        except FileNotFoundError:
            exec_status = ExecutionStatus.TARGET_UNAVAILABLE
            stderr_str = f"Binary not found: {command[0]}"
            exit_code = -1
        except Exception as e:
            exec_status = ExecutionStatus.CRASH
            stderr_str = f"Execution crash error: {e!s}"
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
            execution_status=exec_status,
            error_message="Execution timed out" if timed_out else None,
        )


# Aliases for backward/adapter compatibility
get_binary_path = resolve_binary_path


class ExecutionSandbox:
    """Convenience wrapper for sandbox command execution."""

    @staticmethod
    def run_command(
        command: list[str],
        timeout: int = 30,
        target_name: str = "generic",
        cwd: str | None = None,
        env_overrides: dict[str, str] | None = None,
    ) -> RawExecution:
        runner = SandboxRunner(timeout_seconds=timeout)
        return runner.execute(command, cwd=cwd, env_overrides=env_overrides, scanner_name=target_name)


def create_temp_fixture_dir(files: list[dict[str, str]]) -> tuple[str, callable]:
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
