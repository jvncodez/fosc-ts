"""Themed 'thinking' indicator for the FOSC terminal chat — Claude-Code style.

A single animated status line that shows a rotating hacker-themed verb plus the
elapsed time while the agent works, e.g.:

    ⠹ quebrando…  (8s · hydra -l admin -P rockyou …)

The verb rotates on its own; when a tool fires (fed via `note()`) it pins the
matching verb and a short detail for a few seconds. Runs on a daemon thread and
rewrites one line in place, so it never scrolls. Stdlib only.
"""
import itertools
import sys
import threading
import time

ACCENT = "\033[1;38;2;255;64;64m"
DIM = "\033[38;2;120;120;128m"
TEXT = "\033[38;2;225;225;230m"
RESET = "\033[0m"

FRAMES = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]

# verbs that cycle while the agent reasons
VERBS = [
    "pensando", "investigando", "vasculhando", "analisando", "explorando",
    "enumerando", "farejando", "quebrando", "forjando", "bypassando",
    "injetando", "hackeando",
]

# tool name (substring) -> pinned verb when that tool runs
TOOL_VERB = {
    "sqlmap": "injetando", "hydra": "quebrando", "medusa": "quebrando",
    "john": "quebrando", "hashcat": "quebrando", "ffuf": "fuzzando",
    "wfuzz": "fuzzando", "nuclei": "escaneando", "dalfox": "caçando XSS",
    "arjun": "farejando params", "curl": "sondando", "nmap": "escaneando",
    "nikto": "escaneando", "gobuster": "fuzzando", "git": "lendo fonte",
    "grep": "vasculhando", "cat": "lendo", "read": "lendo",
}


class Thinking:
    """Animated status line. start() to begin, note(msg) to feed tool activity,
    stop() to erase the line. Safe to stop() more than once."""

    def __init__(self, stream=None, interval: float = 0.1, rotate: float = 2.2,
                 interrupt_hint: str = ""):
        self.stream = stream or sys.stdout
        self.interval = interval
        self.rotate = rotate
        self.interrupt_hint = interrupt_hint
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._thread = None
        self._started = 0.0
        self._last_rot = 0.0
        self._idx = 0
        self._pin_verb = None
        self._pin_detail = ""
        self._pin_until = 0.0

    def start(self):
        if self._thread:
            return
        now = time.time()
        self._started = now
        self._last_rot = now
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def note(self, msg: str):
        """Feed a tool-activity line; pins the matching verb + short detail."""
        low = (msg or "").lower()
        verb = None
        for key, v in TOOL_VERB.items():
            if key in low:
                verb = v
                break
        detail = (msg or "").strip().replace("\n", " ")
        if len(detail) > 54:
            detail = detail[:53] + "…"
        with self._lock:
            self._pin_verb = verb or self._verb_now_locked()
            self._pin_detail = detail
            self._pin_until = time.time() + 3.5

    def _verb_now_locked(self):
        return VERBS[self._idx % len(VERBS)]

    def _loop(self):
        spin = itertools.cycle(FRAMES)
        while not self._stop.is_set():
            now = time.time()
            with self._lock:
                pinned = now < self._pin_until
                if pinned:
                    verb = self._pin_verb or self._verb_now_locked()
                    detail = self._pin_detail
                else:
                    if now - self._last_rot >= self.rotate:
                        self._idx = (self._idx + 1) % len(VERBS)
                        self._last_rot = now
                    verb = self._verb_now_locked()
                    detail = ""
            elapsed = int(now - self._started)
            bits = [f"{elapsed}s"]
            if detail:
                bits.append(detail)
            # show the interrupt hint only once the wait is long enough to matter
            if self.interrupt_hint and elapsed >= 2 and not detail:
                bits.append(self.interrupt_hint)
            meta = " · ".join(bits)
            line = (f"\r\033[0K{ACCENT}{next(spin)}{RESET} "
                    f"{TEXT}{verb}…{RESET} {DIM}({meta}){RESET}")
            try:
                self.stream.write(line)
                self.stream.flush()
            except (ValueError, OSError):
                break
            self._stop.wait(self.interval)

    def stop(self):
        if not self._thread:
            return
        self._stop.set()
        self._thread.join(timeout=0.5)
        self._thread = None
        try:
            self.stream.write("\r\033[0K")  # erase the status line
            self.stream.flush()
        except (ValueError, OSError):
            pass
