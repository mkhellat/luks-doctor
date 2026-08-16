# luks-doctor

[![License: GPL v3+](https://img.shields.io/badge/license-GPL%20v3+-green.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![Shell: POSIX sh](https://img.shields.io/badge/shell-POSIX%20sh-4EAA25.svg)](https://pubs.opengroup.org/onlinepubs/9699919799/utilities/sh.html)

**LUKS2 header/keyslot internals, explained in depth — plus one proven,
narrowly-scoped passphrase-recovery technique.**

## What this is (and isn't)

`luks-doctor` is two things bundled together:

1. **Comprehensive documentation** of LUKS2's on-disk header and keyslot
   structure — how to read it, how to inspect it directly with standard
   tools, and how to tell real corruption apart from LUKS2's normal,
   by-design quirks (like the primary and secondary headers legitimately
   differing from each other). See [`docs/`](docs/).
2. **One recovery script** implementing a bounded edit-distance-1 search
   for a passphrase you're highly confident about but suspect you
   fat-fingered by exactly one character.

It is deliberately **not**:

- A password cracker or general brute-force tool. See
  [`docs/passphrase-recovery.md`](docs/passphrase-recovery.md) for why
  Argon2id makes that intractable by design, and why this tool only
  covers the "I'm 95% sure of this passphrase" case.
- A comparison of LUKS1 vs. LUKS2, or coverage of other disk-encryption
  formats (BitLocker, VeraCrypt, TrueCrypt, etc.). Scope here is LUKS2,
  specifically.
- A tool that recovers data when the keyslot's key material is actually
  corrupted. AF-splitting (explained in the docs) makes partial keyslot
  damage unrecoverable by design — that's a security property, not a
  bug, and no amount of clever tooling gets around it.

The docs are intentionally broader and deeper than the tooling. The
name was chosen with that in mind: this project's job is to make LUKS2
internals genuinely understandable, and to package the one recovery
technique that's actually been proven to work, rather than to promise
more than it delivers.

## Why this exists

A LUKS2-encrypted external drive stopped unlocking with a passphrase
its owner was confident about. Working through it methodically:

- `cryptsetup luksDump` showed a single keyslot, Argon2id KDF, and a
  precise `Area offset`/`Area length` describing exactly where the
  keyslot's encrypted key material lived on disk.
- Extracting that byte range with `dd`+`xxd` showed clean, high-entropy
  noise — no zero-runs, no repeating patterns, no signs of a corrupted
  or truncated write.
- Diffing the primary header (offset 0) against the secondary/backup
  header (offset 0x4000) showed expected differences (byte-reversed
  magic bytes, independent checksums and salts) rather than anything
  alarming.
- `cryptsetup repair` found nothing to fix — the header was structurally
  sound.

With disk corruption ruled out, the remaining explanation was a
slightly-wrong passphrase. A bounded search over every single-character
substitution (QWERTY-adjacency and shift/symbol confusion), deletion,
and insertion — verified safely via `cryptsetup open --test-passphrase`,
which checks a passphrase without activating the device — found the
actual passphrase: one character shorter than the confident guess, most
likely a keystroke that hadn't registered when it was originally set.

This project packages that whole process — the diagnostic methodology
and the recovery tool — for anyone in the same situation.

## Background: Argon2id and LUKS2 structure, briefly

LUKS2 protects data with a single random **master key**, never derived
from a passphrase, wrapped separately in one or more **keyslots** so
multiple passphrases (or other credentials) can unlock the same volume
without re-encrypting anything. Each keyslot's key material is
protected by **Argon2id**, a memory-hard key-derivation function chosen
specifically because it resists GPU/ASIC-accelerated brute-forcing far
better than LUKS1's PBKDF2 — every guess costs real time *and* real
memory, not just CPU cycles.

Before being written to disk, a keyslot's key material is
**AF-split** (anti-forensic split) across thousands of stripes, such
that partial recovery of a damaged or incompletely-erased keyslot
yields nothing — you need every stripe to reconstruct anything.

Full depth on all of this — on-disk layout, JSON metadata fields, how
to compute exact byte ranges from `luksDump` output, why the primary
and secondary headers legitimately differ — is in
[`docs/luks2-header-anatomy.md`](docs/luks2-header-anatomy.md).

## Documentation

- [`docs/luks2-header-anatomy.md`](docs/luks2-header-anatomy.md) — LUKS2
  header/keyslot structure, JSON metadata, Argon2id, AF-splitting,
  primary/secondary header differences, command reference.
- [`docs/af-splitting-explained.md`](docs/af-splitting-explained.md) —
  beginner-friendly, byte-by-byte deep dive into the AF-split/merge
  algorithm itself, with a hand-traceable worked example and a concrete
  demonstration of why a single flipped bit makes a keyslot
  unrecoverable.
- [`docs/checking-for-corruption.md`](docs/checking-for-corruption.md) —
  practical `dd`/`xxd` inspection walkthrough, healthy vs. corrupted
  example dumps, when `cryptsetup repair` helps and when it can't, and
  a step-by-step decision guide.
- [`docs/passphrase-recovery.md`](docs/passphrase-recovery.md) — the
  edit-distance-1 methodology in detail, why it's safe, and its
  explicit limits.

## Usage

### Inspect a keyslot

```
sudo ./scripts/inspect-keyslot /dev/sdX
```

Prompts for which keyslot to inspect if the volume has more than one,
computes the byte range from `luksDump` automatically (no manual offset
arithmetic), dumps the head/tail of the raw keyslot area, and runs a
rough zero-run heuristic as a visual aid. See
[`docs/checking-for-corruption.md`](docs/checking-for-corruption.md)
for how to interpret the output.

```
sudo ./scripts/inspect-keyslot --slot 0 /dev/sdX
./scripts/inspect-keyslot --help
```

### Recover a near-miss passphrase

```
sudo ./scripts/recover-passphrase /dev/sdX 'my-best-guess-passphrase'
```

Generates every substitution/deletion/insertion candidate at edit
distance 1 from your guess and tests each safely with
`cryptsetup open --test-passphrase` (never activates the device). See
[`docs/passphrase-recovery.md`](docs/passphrase-recovery.md) for the
full walkthrough and example output.

```
./scripts/recover-passphrase --help
```

Only reach for this after confirming (via `inspect-keyslot` and
[`docs/checking-for-corruption.md`](docs/checking-for-corruption.md))
that the header and keyslot data actually look clean — this tool
recovers typos, not disk damage.

## Roadmap

The documentation aims to be genuinely comprehensive about LUKS2
internals; the tooling today covers exactly one recovery technique. The
following are plausible, not-yet-built extensions — ideas and
contributions welcome, but none of these are half-implemented anywhere
in this repo:

- **Dvorak substitution table.** `recover-passphrase --layout` currently
  covers `qwerty` (default), `azerty`, and `qwertz` — the three most
  common physical layouts. Dvorak's fundamentally different key
  arrangement (optimized for typing efficiency, not physical/historical
  continuity with QWERTY) would need its own adjacency map built from
  scratch rather than derived from the QWERTY table, and is left for a
  future contribution.
- **Dictionary/mnemonic-based candidate generation.** For passphrases
  built from a memorable phrase or word list, generating candidates
  from likely word substitutions or common transformations (leetspeak,
  capitalization changes) rather than pure character-level edits.
- **Edit-distance-2 search.** Covering two simultaneous slips, with
  appropriate warnings about the combinatorial growth in candidate
  count (and therefore Argon2id wall-clock cost) as distance increases.
- **Transposition (adjacent character swap).** Full Damerau-Levenshtein
  distance 1 currently omits this fourth edit operation; it's a
  plausible addition to the existing three.
- **Integration with GPU-accelerated tools** like `hashcat`'s or
  `john`'s LUKS modes for cases that genuinely need larger search
  spaces than a CPU-bound `--test-passphrase` loop can cover in
  reasonable time — with clear documentation on the tradeoffs (hardware
  cost, time, and the fact that Argon2id's memory-hardness advantage
  narrows but doesn't vanish against GPU attackers).
- **Migrate documentation to Texinfo.** The current Markdown docs would
  become an Info manual (`info luks-doctor`), giving cross-referenced,
  indexed, offline-browsable documentation in the style of other GNU
  tooling — fitting for a project already following GNU-style commit
  conventions. This is a documentation-format migration, not a content
  rewrite: the existing depth/citations would carry over, restructured
  for `@node`/`@menu` navigation.
- **Scope a C or Rust rewrite of the tooling.** `scripts/recover-passphrase`
  and `scripts/inspect-keyslot` are POSIX `sh` today, which keeps them
  auditable and dependency-free but means candidate generation is
  inherently slower than a compiled implementation, which matters as
  search space grows (edit-distance-2, transposition, dictionary
  search — all listed above). Scoping work would need to weigh: startup
  overhead per `cryptsetup open --test-passphrase` call likely dominates
  actual wall-clock time regardless of language; whether a rewrite
  should shell out to `cryptsetup` as today or link `libcryptsetup`
  directly; and whether it's worth the loss of "read the whole script in
  one sitting" auditability that POSIX `sh` currently provides for a
  security-sensitive recovery tool. Not started — needs its own
  scoping/design discussion before any implementation.

If you build one of these, a PR is welcome — please keep new methods in
their own clearly-labeled script/doc pair rather than folding them into
the existing edit-distance-1 tool, so the safe/tractable case stays
simple and the more speculative/expensive methods stay clearly opt-in.

## Contributing

Issues and pull requests are welcome. Shell scripts should pass
`shellcheck` and follow the existing style (`set -euo pipefail`,
explicit `--help`, clear argument validation, comments only where the
*why* isn't obvious from the code itself). Documentation changes should
match the depth and structure of the existing `docs/` files.

## License

GPL-3.0-or-later. See [LICENSE](LICENSE).
