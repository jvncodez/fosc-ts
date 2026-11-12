import os
import stat
import sys
import tempfile
from pathlib import Path

from fosc import config

FAKE = Path(__file__).resolve().parent / "fake_claude.py"


def isolate(testcase):
    """Point every FOSC path at a throwaway dir and swap in the fake claude CLI."""
    tmp = Path(tempfile.mkdtemp(prefix="fosc-test-"))
    saved = (config.FOSC_HOME, config.STATE_ROOT, config.KNOWLEDGE_ROOT, config.CHAT_ROOT,
             config.CONFIG_PATH, config.CLAUDE_BIN)
    config.FOSC_HOME = tmp
    config.STATE_ROOT = tmp / "runs"
    config.KNOWLEDGE_ROOT = tmp / "knowledge"
    config.CHAT_ROOT = tmp / "chat"
    config.CONFIG_PATH = tmp / "config.json"
    wrapper = tmp / "claude"
    wrapper.write_text(f"#!/bin/sh\nexec {sys.executable} {FAKE} \"$@\"\n")
    wrapper.chmod(wrapper.stat().st_mode | stat.S_IEXEC)
    config.CLAUDE_BIN = str(wrapper)

    def restore():
        (config.FOSC_HOME, config.STATE_ROOT, config.KNOWLEDGE_ROOT, config.CHAT_ROOT,
         config.CONFIG_PATH, config.CLAUDE_BIN) = saved
        for k in ("FAKE_HUNT", "FAKE_REVIEW"):
            os.environ.pop(k, None)
    testcase.addCleanup(restore)
    return tmp
