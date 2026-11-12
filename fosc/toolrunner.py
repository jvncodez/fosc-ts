"""Thin, defensive wrapper around external CLI recon tools."""
import shutil
import subprocess


def have(binary: str) -> bool:
    return shutil.which(binary) is not None


def run_lines(cmd: list[str], timeout: int) -> list[str]:
    """Run a command, return stdout split into non-empty lines.

    Never raises: missing binary, timeout, or non-zero exit all just
    produce an empty/partial result plus a stderr note so one dead tool
    never takes the whole run down with it.
    """
    if not have(cmd[0]):
        print(f"[fosc] tool not found, skipping: {cmd[0]}")
        return []
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, check=False
        )
    except subprocess.TimeoutExpired:
        print(f"[fosc] tool timed out after {timeout}s: {' '.join(cmd)}")
        return []
    except Exception as e:
        print(f"[fosc] tool failed: {' '.join(cmd)}: {e}")
        return []
    if proc.returncode not in (0, None) and not proc.stdout:
        if proc.stderr:
            print(f"[fosc] {cmd[0]} stderr: {proc.stderr.strip()[:300]}")
    return [l for l in proc.stdout.splitlines() if l.strip()]
