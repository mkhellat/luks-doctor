# Passphrase Recovery: Bounded Edit-Distance-1 Search

This document explains the one recovery technique this project
implements, why it's structured the way it is, and its explicit limits.
If you haven't already, read
[`checking-for-corruption.md`](checking-for-corruption.md) first and
confirm the header and keyslot data both look clean — this tool is for
the case where the disk itself is fine and the passphrase is the
problem.

## What this is (and, importantly, what it is not)

**This is not a password cracker.** It does not attempt to guess an
unknown passphrase from nothing, and it is not a general brute-force
tool. It is a narrow **recovery aid** for one very specific, very
common situation: you are highly confident you know the passphrase —
confident enough to recite it — but the volume won't unlock, and you
suspect you fat-fingered exactly one character when you originally set
it, or you're mis-typing exactly one character now.

The scope is deliberately narrow because of how Argon2id works (see
[`luks2-header-anatomy.md#argon2id`](luks2-header-anatomy.md#argon2id)):
each single guess against the real keyslot costs a meaningful,
deliberately-tuned amount of time and memory — that's Argon2id's whole
purpose, and it's working exactly as intended even when it's
inconvenient for you. A keyslot configured with `Time cost: 5`,
`Memory: 1048576` (1 GiB), `Threads: 4` might take on the order of a
second or more per attempt. That is completely fine for a few hundred
candidates near a known-good guess. It is hopeless for anything
resembling a dictionary attack or brute-forcing an unknown passphrase
from scratch — at even a generous 1 guess/second, testing all
combinations of a modest keyspace would take longer than is useful to
anyone. If you don't have a strong, specific guess to start from, this
tool cannot help you; see the [Roadmap](../README.md#roadmap) in the
README for what larger-scale approaches would require (GPU-accelerated
tools like `hashcat`'s LUKS mode, which trade Argon2id's memory-hardness
advantage against attackers for raw parallel hardware, at real
financial and time cost).

## Why `--test-passphrase` is safe

```
echo -n "$candidate" | cryptsetup open --test-passphrase /dev/sdX
```

`--test-passphrase` tells `cryptsetup` to run the passphrase through the
normal unwrap-and-verify process (derive a key via the keyslot's KDF,
attempt to unwrap the keyslot, check the result against the volume's
digest) **without** creating a device-mapper mapping. Concretely, that
means:

- **No `/dev/mapper/<name>` device is created.** There is nothing to
  forget to close, nothing that could get mounted accidentally, no
  mapping left dangling if a script crashes mid-run.
- **Nothing is written to the volume.** The operation is purely a read
  of the header/keyslot region plus in-memory cryptographic computation
  on the candidate passphrase. It does not touch the data segment at
  all.
- **It can be run any number of times, safely**, including in a tight
  loop across hundreds of candidates — which is exactly what this
  tool does. There is no lockout, rate-limiting, or wear concern at the
  `cryptsetup` level (though see the Argon2id cost note above — the
  *practical* limit is your own patience and CPU/RAM, not any risk of
  harm from repeated attempts).

The exit code tells you the result: `0` means the passphrase unwrapped
a keyslot successfully; non-zero means it didn't. `recover-passphrase`
just automates checking that exit code across a generated candidate
list and reports the first (and, information-theoretically, only
plausible) match.

## The three edit operations

Given a base guess, the script generates every candidate reachable by
exactly one of these edits, applied at every applicable position in the
string:

1. **Substitution**, using a physical-keyboard-adjacency map plus a
   shift/symbol-confusion table. Covers the case where you meant one
   key but your finger landed on (or you now recall) an adjacent one —
   e.g. `s` for `a` (their neighbors on a QWERTY row), or `@` for `2`
   (the shifted vs. unshifted character sharing a physical key). This
   is the most common real-world typo pattern for passphrases typed on
   a physical keyboard. The adjacency map depends on which physical
   layout the passphrase was actually typed on — select it with
   `--layout {qwerty,azerty,qwertz}` (default `qwerty`); see
   [Keyboard layouts](#keyboard-layouts) below.
2. **Deletion**, removing exactly one character at each position. Covers
   the case where a keystroke didn't register when the passphrase was
   originally set (a common failure mode with worn keyboards, fast
   typing, or certain USB keyboard/hub combinations dropping the
   occasional keypress) — you've been confidently typing the passphrase
   *as you remember setting it*, but what actually got stored is one
   character shorter.
3. **Insertion**, adding one likely character (digits 0-9 and a small
   set of common passphrase symbols) at each position. Covers the
   reverse case — an extra character crept in, e.g. a doubled keystroke,
   or you're now adding a character that was never actually part of the
   original passphrase.

These three operations are the standard definition of "edit distance 1"
(specifically, Damerau-Levenshtein distance 1 without transposition —
this tool does not currently generate adjacent-character-swap
candidates; see the [Roadmap](../README.md#roadmap)). They're chosen
because, empirically, the overwhelming majority of "I'm sure of this
passphrase but it's not working" situations trace back to exactly one
of these three slip types — not to systematically misremembering the
whole passphrase, which this tool does not attempt to address.

## Usage walkthrough

```
sudo ./scripts/recover-passphrase /dev/sdX 'my-best-guess-passphrase'
```

Example output:

```
luks-doctor: testing keyslot(s) on /dev/sdX
luks-doctor: base guess: my-best-guess-passphrase
luks-doctor: generated 187 candidates (substitution + deletion + insertion)
luks-doctor: [1/187] testing candidate (substitution, pos 3)... no match
luks-doctor: [2/187] testing candidate (substitution, pos 3)... no match
...
luks-doctor: [61/187] testing candidate (deletion, pos 8)... MATCH

luks-doctor: recovered passphrase:
  my-best-guess-passphrase   (original guess, for reference)
  my-best-uess-passphrase    (working passphrase - note: dropped 'g' at position 8)

luks-doctor: SECURITY REMINDER
  This passphrase is now confirmed and was found via automated search.
  You should:
    1. Unlock the volume normally and mount it to confirm data access.
    2. Add a new keyslot with a passphrase you're confident you can type
       reliably: cryptsetup luksAddKey /dev/sdX
    3. Once confirmed working, consider removing the old/typo-prone
       keyslot: cryptsetup luksKillSlot /dev/sdX <slot>
  Treat any passphrase that was ever tested in bulk, or written to a
  terminal/log, as lower-confidence going forward - rotate it if this
  volume protects anything sensitive.
```

Run `./scripts/recover-passphrase --help` for the full option list,
including limiting which edit operations run and adjusting the
insertion character set.

## Keyboard layouts

`--layout` selects which physical-key adjacency map substitution
candidates are generated from:

- **`qwerty`** (default) — US QWERTY. The original, hand-tuned map this
  tool started with.
- **`azerty`** — French AZERTY. Row 1 is `a z e r t y u i o p` (not
  `q w e r t y u i o p`), row 2 gains a trailing `m`, row 3 loses `m` and
  gains a leading `w`. Digit substitution additionally covers the
  ASCII-safe subset of AZERTY's unshifted-symbol/shifted-digit number
  row (`1`↔`&`, `4`↔`'`, `5`↔`(`) — the remaining number-row keys
  unshift to accented characters (`é`, `"`, `è`, `_`, `ç`, `à`) outside
  this tool's ASCII-only candidate set and are intentionally skipped.
- **`qwertz`** — German/Central European QWERTZ. Physically identical
  to QWERTY except the `Y` and `Z` keys are swapped; every other key,
  including the whole number row, sits in the same place.

Pick whichever layout the passphrase was actually typed on when the
suspected typo happened — that's what determines which key a
mistyped finger would actually have landed on. If you're unsure or the
passphrase was typed on a layout not listed here (e.g. Dvorak — not yet
supported, see the [Roadmap](../README.md#roadmap)), the default
`qwerty` map is still a reasonable first attempt, since deletion and
insertion candidates are layout-independent and unaffected either way.

---

For what's deliberately *not* built yet — larger edit distances,
a Dvorak layout map, dictionary-based candidates, GPU-accelerated
search — see the [Roadmap section of the README](../README.md#roadmap).
