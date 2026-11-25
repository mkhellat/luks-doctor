# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Mohammadreza Khellat <mkhellat@beavernets.com>
#
# Derive the keyboard-adjacency tables used by scripts/recover-passphrase
# from a physical ANSI key grid, and check them against the tables the
# script actually ships.
#
# Each physical key slot has a fixed (x, y) on an ANSI keyboard. Two
# keys are neighbours when they are on the same or an adjacent row and
# no more than ~1 key-unit apart horizontally. The same physical slots
# carry different letters on QWERTY, QWERTZ and Dvorak (all ANSI), so we
# relabel the slots per layout and keep each letter key's letter/digit
# neighbours -- exactly the convention the script's hand tables follow.
#
# The model is trusted only because it reproduces the QWERTY and QWERTZ
# tables in the script exactly; given that, the Dvorak table it derives
# has the same provenance. The script's Dvorak table is then required to
# match the derived one, so an accidental edit to it is caught here.
import re
import sys

# Row y and the x of the first key on each row (ANSI stagger, key units).
# Number row starts at 0; Tab=1.5u, Caps=1.75u, LShift=2.25u set the
# top/home/bottom offsets.
ROWS = {
    "num": (0, 0.0),
    "top": (1, 1.5),
    "home": (2, 1.75),
    "bottom": (3, 2.25),
}

# Physical slots per row, left to right, as QWERTY legends (our slot IDs).
SLOTS = {
    "num": list("`1234567890-="),
    "top": list("qwertyuiop[]"),
    "home": list("asdfghjkl;'"),
    "bottom": list("zxcvbnm,./"),
}

# Per-layout legend for each QWERTY slot. Only slots that differ from
# QWERTY are listed; the rest keep their QWERTY legend. AZERTY is not
# here: it is an ISO layout with a different physical arrangement, so it
# is kept as a separate hand table in the script and not modelled.
LAYOUTS = {
    "qwerty": {},
    "qwertz": {"y": "z", "z": "y"},
    "dvorak": {
        "q": "'", "w": ",", "e": ".", "r": "p", "t": "y", "y": "f",
        "u": "g", "i": "c", "o": "r", "p": "l", "[": "/", "]": "=",
        "s": "o", "d": "e", "f": "u", "g": "i", "h": "d", "j": "h",
        "k": "t", "l": "n", ";": "s", "'": "-",
        "z": ";", "x": "q", "c": "j", "v": "k", "b": "x", "n": "b",
        ",": "w", ".": "v", "/": "z",
    },
}

LETTERS = set("abcdefghijklmnopqrstuvwxyz")
DIGITS = set("0123456789")


def coords():
    pos = {}
    for row, (y, x0) in ROWS.items():
        for i, slot in enumerate(SLOTS[row]):
            pos[slot] = (x0 + i, y)
    return pos


def neighbours(pos, slot):
    x, y = pos[slot]
    out = []
    for other, (ox, oy) in pos.items():
        if other == slot:
            continue
        if abs(oy - y) <= 1 and abs(ox - x) <= 1.0 + 1e-9:
            out.append((ox, oy, other))
    # same row first (left->right), then the row above, then below.
    out.sort(key=lambda t: (abs(t[1] - y), t[1] - y, t[0]))
    return [s for _, _, s in out]


def model_table(layout):
    pos = coords()
    legend = LAYOUTS[layout]

    def relabel(s):
        return legend.get(s, s)

    result = {}
    for slot in pos:
        key = relabel(slot)
        if key not in LETTERS:
            continue
        nbrs = [relabel(n) for n in neighbours(pos, slot)]
        result[key] = "".join(c for c in nbrs if c in LETTERS or c in DIGITS)
    return result


def script_table(text, layout):
    """Parse adjacent_chars_<layout>() from the script source."""
    func = re.search(
        r"adjacent_chars_%s\(\)\s*\{(.*?)\n\}" % layout, text, re.S
    )
    if not func:
        raise SystemExit("could not find adjacent_chars_%s in script" % layout)
    table = {}
    for key, val in re.findall(r'(\S)\)\s*echo\s*"([^"]*)"', func.group(1)):
        if key in LETTERS:
            table[key] = val
    return table


def as_sets(d):
    return {k: "".join(sorted(v)) for k, v in d.items()}


def compare(name, got, expected):
    g, e = as_sets(got), as_sets(expected)
    if g == e:
        print("  %-24s MATCH (%d keys)" % (name, len(got)))
        return True
    print("  %-24s MISMATCH" % name)
    for k in sorted(set(g) | set(e)):
        if g.get(k) != e.get(k):
            print("      %s: a=%-12r b=%r" % (k, g.get(k), e.get(k)))
    return False


def main():
    if len(sys.argv) != 2:
        raise SystemExit("usage: keyboard_adjacency.py PATH/TO/recover-passphrase")
    text = open(sys.argv[1], encoding="utf-8").read()

    ok = True
    print("Model reproduces the script's QWERTY/QWERTZ tables:")
    for layout in ("qwerty", "qwertz"):
        ok = compare(layout, model_table(layout), script_table(text, layout)) and ok

    print("Script's Dvorak table matches the derived one:")
    ok = compare("dvorak", script_table(text, "dvorak"), model_table("dvorak")) and ok

    print()
    print("Derived Dvorak adjacency:")
    dv = model_table("dvorak")
    for k in sorted(dv):
        print('        %s) echo "%s" ;;' % (k, dv[k]))

    if not ok:
        raise SystemExit("ADJACENCY CHECK FAILED")
    print()
    print("adjacency check: OK")


if __name__ == "__main__":
    main()
