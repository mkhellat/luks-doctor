# Keyboard adjacency

## Claims

The keyboard-adjacency tables in `scripts/recover-passphrase` describe
physical key neighbours, not an arbitrary character map, and the Dvorak
table added for `--layout dvorak` was derived the same way as the
others:

- A single physical ANSI key grid, with each key placed by the standard
  row stagger, reproduces the script's `qwerty` and `qwertz` adjacency
  tables exactly when its slots are labelled with those layouts. This is
  the evidence that the grid models the keyboard correctly.
- Labelling the same grid with the US Dvorak legend yields the script's
  `dvorak` table, so that table has the same provenance; the experiment
  fails if the shipped table drifts from the derived one.
- End to end, `--layout dvorak` recovers a guess that differs from the
  passphrase by one key on a Dvorak keyboard but not on QWERTY: with
  passphrase `Tango-ok7`, the guess `Tando-ok7` (`d` for its Dvorak
  neighbour `g`) is recovered under `--layout dvorak` and not under the
  default `qwerty`.

AZERTY is not modelled here: it is an ISO layout with a different
physical arrangement, kept as a separate hand table in the script.

The Dvorak layout (US Simplified) used for the legend:

```
top:     ' , . p y f g c r l /
home:    a o e u i d h t n s -
bottom:  ; q j k x b m w v z
```

Used by [`docs/passphrase-recovery.md`](../../docs/passphrase-recovery.md).

## Requirements

- `python3` (standard library only) for the derivation and check.
- `cryptsetup` and `truncate` for the end-to-end recovery (PBKDF2 with a
  low iteration count, so it needs no root and only a little RAM).

## Run

From the repository root:

```
experiments/keyboard-adjacency/run
```

`keyboard_adjacency.py` parses the adjacency tables straight out of
`scripts/recover-passphrase`, so the check always runs against the
shipped tables. The script exits non-zero if any table disagrees with
the model, so the experiment fails CI on a bad edit.

## Result (2026-11-25)

The model reproduced the `qwerty` and `qwertz` tables (26 keys each) and
matched the shipped `dvorak` table (26 keys). The end-to-end search
recovered `Tango-ok7` from `Tando-ok7` under `--layout dvorak`
(substitution at position 3, from 263 candidates) and reported no match
under `--layout qwerty` (275 candidates), confirming the layout is what
makes the difference.
