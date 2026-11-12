"""Multi-line terminal composer for the FOSC chat prompt — Claude-Code style.

A boxed input area where Enter inserts a newline (you keep writing, even a
"thinking line") and Ctrl+E sends. Pure stdlib (termios raw mode on POSIX);
falls back to plain input() when there is no TTY or termios is unavailable.

The editor state (`Composer`) is separated from terminal IO so it can be unit
tested without a real terminal.
"""
import os
import sys
import shutil

try:
    import termios
    import tty
    _HAS_TERMIOS = True
except ImportError:  # Windows / no POSIX tty
    _HAS_TERMIOS = False

ACCENT = "\033[1;38;2;255;64;64m"
DIM = "\033[38;2;120;120;128m"
TEXT = "\033[38;2;225;225;230m"
RESET = "\033[0m"


class Composer:
    """Pure editor state: a list of characters plus a cursor index.

    All mutation goes through the small methods below so the behaviour can be
    driven and asserted in tests. `layout()` turns the buffer into the display
    lines (wrapped to an inner width) and the cursor's (row, col)."""

    def __init__(self, text=""):
        self.chars = list(text)
        self.cur = len(self.chars)

    # --- queries ---------------------------------------------------------- #
    def value(self) -> str:
        return "".join(self.chars)

    def is_empty(self) -> bool:
        return len(self.chars) == 0

    # --- editing ---------------------------------------------------------- #
    def insert(self, s: str):
        for ch in s:
            self.chars.insert(self.cur, ch)
            self.cur += 1

    def backspace(self):
        if self.cur > 0:
            del self.chars[self.cur - 1]
            self.cur -= 1

    def delete(self):  # forward delete
        if self.cur < len(self.chars):
            del self.chars[self.cur]

    def left(self):
        if self.cur > 0:
            self.cur -= 1

    def right(self):
        if self.cur < len(self.chars):
            self.cur += 1

    def _line_bounds(self):
        """Start and end buffer index of the logical line the cursor is on."""
        start = self.cur
        while start > 0 and self.chars[start - 1] != "\n":
            start -= 1
        end = self.cur
        while end < len(self.chars) and self.chars[end] != "\n":
            end += 1
        return start, end

    def home(self):
        self.cur, _ = self._line_bounds()

    def end(self):
        _, self.cur = self._line_bounds()

    def kill_line(self):
        """Ctrl+U: delete from line start to cursor."""
        start, _ = self._line_bounds()
        del self.chars[start:self.cur]
        self.cur = start

    def up(self, inner_w):
        self._vmove(-1, inner_w)

    def down(self, inner_w):
        self._vmove(1, inner_w)

    def _vmove(self, delta, inner_w):
        lines, (row, col) = self.layout(inner_w)
        target = row + delta
        if target < 0 or target >= len(lines):
            return
        new_col = min(col, len(lines[target]))
        self.cur = self._index_of(lines, target, new_col)

    # --- layout ----------------------------------------------------------- #
    def layout(self, inner_w: int):
        """Return (lines, (cursor_row, cursor_col)).

        Lines are wrapped to inner_w so terminal wrapping never desyncs the
        cursor math — we wrap manually and place the cursor ourselves."""
        inner_w = max(1, inner_w)
        lines = [""]
        row = col = 0
        cur_rc = (0, 0)
        for i, ch in enumerate(self.chars):
            if i == self.cur:
                cur_rc = (row, col)
            if ch == "\n":
                row += 1
                col = 0
                lines.append("")
            else:
                if col >= inner_w:
                    row += 1
                    col = 0
                    lines.append("")
                lines[row] += ch
                col += 1
        if self.cur >= len(self.chars):
            if col >= inner_w:  # cursor would sit past the edge -> next row
                row += 1
                col = 0
                lines.append("")
            cur_rc = (row, col)
        return lines, cur_rc

    @staticmethod
    def _index_of(lines, target_row, target_col):
        """Buffer index at display (row, col) for a given layout."""
        idx = 0
        for r, ln in enumerate(lines):
            if r == target_row:
                return idx + target_col
            idx += len(ln) + 1  # +1 for the newline / wrap boundary
        return idx


# ------------------------------------------------------------------------- #
# Terminal front-end
# ------------------------------------------------------------------------- #
def _render(comp: Composer, hint: str, inner_w: int, cursor_from_top):
    """Repaint the box in place and leave the terminal cursor at the edit point.

    `cursor_from_top` is where the cursor was left by the PREVIOUS render (rows
    below the box's top line), or None on the first paint. We move back up by
    exactly that to reach the box top, so the math never desyncs. Returns the
    new cursor_from_top to pass in next time."""
    lines, (crow, ccol) = comp.layout(inner_w)
    out = []
    # 1. return to the box's top-left (cursor is wherever edit position was)
    if cursor_from_top is not None:
        if cursor_from_top > 0:
            out.append(f"\033[{cursor_from_top}A")
        out.append("\r")
    out.append("\033[0J")  # clear from here to end of screen

    # 2. build the box
    top = f"{ACCENT}╭{'─' * (inner_w + 2)}╮{RESET}"
    body = []
    for ln in (lines or [""]):
        pad = ln + " " * max(0, inner_w - len(ln))
        body.append(f"{ACCENT}│{RESET} {TEXT}{pad}{RESET} {ACCENT}│{RESET}")
    fill = max(0, inner_w - len(hint) - 1)
    bottom = f"{ACCENT}╰─ {DIM}{hint}{RESET} {ACCENT}{'─' * fill}╯{RESET}"
    box = [top] + body + [bottom]
    # raw mode disables ONLCR, so a bare '\n' moves DOWN but not to column 0.
    # Join with '\r\n' so every row starts at the left edge instead of drifting
    # right by the previous row's width.
    out.append("\r\n".join(box))

    # 3. move from the bottom line up to the edit line, then to the edit column
    total = len(box)
    cursor_line = 1 + crow            # +1 for the top border
    up = (total - 1) - cursor_line    # bottom line -> edit line
    if up > 0:
        out.append(f"\033[{up}A")
    out.append("\r")
    if 2 + ccol > 0:
        out.append(f"\033[{2 + ccol}C")   # 2 = "│ " prefix inside the box
    return "".join(out), cursor_line


def _erase_box(cursor_from_top: int) -> str:
    """ANSI to move to the box top from the edit position and wipe the box."""
    s = ""
    if cursor_from_top and cursor_from_top > 0:
        s += f"\033[{cursor_from_top}A"
    return s + "\r\033[0J"


def _read_key(fd):
    """Read one logical key: returns ('char', s) / ('ctrl', name) / ('key', name)."""
    b = os.read(fd, 1)
    if not b:
        return ("ctrl", "D")
    c = b[0]
    if c == 0x1b:  # ESC — maybe an arrow / nav sequence
        seq = os.read(fd, 2)
        if seq == b"[C":
            return ("key", "right")
        if seq == b"[D":
            return ("key", "left")
        if seq == b"[A":
            return ("key", "up")
        if seq == b"[B":
            return ("key", "down")
        if seq == b"[H" or seq == b"OH":
            return ("key", "home")
        if seq == b"[F" or seq == b"OF":
            return ("key", "end")
        if seq == b"[3":
            os.read(fd, 1)  # consume '~'
            return ("key", "delete")
        return ("key", "esc")
    if c in (0x7f, 0x08):
        return ("key", "backspace")
    if c in (0x0d, 0x0a):
        return ("key", "enter")
    if c == 0x05:
        return ("ctrl", "E")
    if c == 0x03:
        return ("ctrl", "C")
    if c == 0x04:
        return ("ctrl", "D")
    if c == 0x15:
        return ("ctrl", "U")
    if c == 0x01:
        return ("key", "home")
    if c < 0x20:
        return ("ctrl", "ignore")
    # printable: decode UTF-8 (read continuation bytes if needed)
    nbytes = 1
    if c >= 0xf0:
        nbytes = 4
    elif c >= 0xe0:
        nbytes = 3
    elif c >= 0xc0:
        nbytes = 2
    if nbytes > 1:
        b += os.read(fd, nbytes - 1)
    try:
        return ("char", b.decode("utf-8"))
    except UnicodeDecodeError:
        return ("ctrl", "ignore")


def read_composer(label: str = "fosc", hint: str = "enter = nova linha · ctrl+e = enviar · ctrl+c = cancela",
                  initial: str = "") -> str:
    """Open the multi-line composer and return the typed text.

    Raises EOFError on Ctrl+D with an empty buffer and KeyboardInterrupt on
    Ctrl+C. Falls back to input() when not on a POSIX TTY."""
    if not (_HAS_TERMIOS and sys.stdin.isatty() and sys.stdout.isatty()):
        return input(f"{ACCENT}{label}› {RESET}")

    cols = shutil.get_terminal_size((80, 24)).columns
    inner_w = max(20, min(cols, 100) - 4)
    comp = Composer(initial)
    fd = sys.stdin.fileno()
    old = termios.tcgetattr(fd)
    cft = None          # cursor rows below box top, from the last render
    outcome = "submit"  # submit | cancel | eof
    try:
        tty.setraw(fd)
        while True:
            s, cft = _render(comp, hint, inner_w, cft)
            sys.stdout.write(s)
            sys.stdout.flush()
            kind, name = _read_key(fd)
            if kind == "ctrl":
                if name == "E":
                    break
                if name == "C":
                    outcome = "cancel"
                    break
                if name == "D":
                    if comp.is_empty():
                        outcome = "eof"
                        break
                    continue
                if name == "U":
                    comp.kill_line()
                continue
            if kind == "char":
                comp.insert(name)
            elif kind == "key":
                if name == "enter":
                    comp.insert("\n")
                elif name == "backspace":
                    comp.backspace()
                elif name == "delete":
                    comp.delete()
                elif name == "left":
                    comp.left()
                elif name == "right":
                    comp.right()
                elif name == "up":
                    comp.up(inner_w)
                elif name == "down":
                    comp.down(inner_w)
                elif name == "home":
                    comp.home()
                elif name == "end":
                    comp.end()
    finally:
        # wipe the box so later output starts on a clean line
        sys.stdout.write(_erase_box(cft or 0))
        sys.stdout.flush()
        termios.tcsetattr(fd, termios.TCSADRAIN, old)

    if outcome == "cancel":
        raise KeyboardInterrupt
    if outcome == "eof":
        raise EOFError
    # echo the submitted prompt so there's a record above the answer
    text = comp.value()
    sent = text.split("\n")
    sys.stdout.write(f"{ACCENT}❯{RESET} {TEXT}{sent[0]}{RESET}\n")
    for ln in sent[1:]:
        sys.stdout.write(f"  {TEXT}{ln}{RESET}\n")
    sys.stdout.flush()
    return text
