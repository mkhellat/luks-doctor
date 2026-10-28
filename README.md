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
- Coverage of LUKS1 or other disk-encryption formats (BitLocker,
  VeraCrypt, TrueCrypt, etc.). Scope here is LUKS2; LUKS1 comes up only
  where it explains LUKS2, as in the KDF comparison.
- A tool that recovers a damaged keyslot. Any damage to a keyslot's
  stored key material leaves at least 128 bits of the master key
  unknown, far too many to search (see
  [`docs/af-splitting-explained.md`](docs/af-splitting-explained.md#what-damage-does-to-the-key));
  the way back in is another keyslot or a header backup.

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
slightly-wrong passphrase. A bounded search over single-character
substitutions (QWERTY neighbours and shift/symbol pairs), deletions and
insertions — verified safely via `cryptsetup open --test-passphrase`,
which checks a passphrase without activating the device — found the
actual passphrase: one character shorter than the confident guess, most
likely a keystroke that hadn't registered when it was originally set.

This project packages that whole process — the diagnostic methodology
and the recovery tool — for anyone in the same situation.

## Background: Argon2id and LUKS2 structure, briefly

LUKS2 protects data with a single random **master key**, never derived
from a passphrase, wrapped separately in one or more **keyslots** so
multiple passphrases (or other credentials) can unlock the same volume
without re-encrypting anything. By default, the key that encrypts each
keyslot is derived from its passphrase with **Argon2id**, a
memory-hard key derivation function: every guess costs time *and*
memory, which makes large-scale guessing on GPUs much less effective
than against LUKS1's PBKDF2 (see
[`docs/kdf-comparison.md`](docs/kdf-comparison.md)).

Before being encrypted and written to disk, a keyslot's copy of the
master key is **AF-split** (anti-forensic split) into 4000 stripes,
all of which are needed to reconstruct it. The purpose is to make a
removed keyslot erasable: an overwrite that misses a few sectors still
destroys the key. This does not hold on SSDs and other flash storage,
which can keep old copies of a whole keyslot in internal spare areas.

Full depth on all of this — on-disk layout, JSON metadata fields, how
to compute exact byte ranges from `luksDump` output, why the primary
and secondary headers legitimately differ — is in
[`docs/luks2-header-anatomy.md`](docs/luks2-header-anatomy.md).

## Documentation

- [`docs/luks2-header-anatomy.md`](docs/luks2-header-anatomy.md) — LUKS2
  header/keyslot structure, JSON metadata, Argon2id, AF-splitting,
  primary/secondary header differences, command reference.
- [`docs/af-splitting-explained.md`](docs/af-splitting-explained.md) —
  what AF-splitting protects against, the split/merge algorithm from
  cryptsetup's source with a hand-traceable worked example, how the
  split key is encrypted on disk, and exactly how much of the key a
  damaged byte destroys, backed by experiments in
  [`experiments/`](experiments).
- [`docs/master-key-lifecycle.md`](docs/master-key-lifecycle.md) —
  where the plaintext master key lives in memory during unlock and
  while a volume is mapped, how the kernel keys and uses it for every
  sector, how it is wiped on close, and a source-verified call graph of
  that lifecycle.
- [`docs/checking-for-corruption.md`](docs/checking-for-corruption.md) —
  practical `dd`/`xxd` inspection walkthrough, real healthy and
  damaged dumps, what `luksDump`, `repair` and `--test-passphrase`
  report for each kind of damage, what no inspection can detect, and a
  step-by-step decision guide.
- [`docs/passphrase-recovery.md`](docs/passphrase-recovery.md) — the
  edit-distance-1 search in detail, why it's safe, and which slips it
  does and does not recover.
- [`docs/cold-boot-and-dma-attacks.md`](docs/cold-boot-and-dma-attacks.md) —
  a deliberately separate threat model: attacking the cleartext master
  key while it's resident in memory on an already-unlocked, running
  machine, covering the real cold-boot/DMA research and which
  mitigations (`luksSuspend`, IOMMU, UEFI reset-attack mitigation) do
  and don't actually help.
- [`docs/entropy-analysis.md`](docs/entropy-analysis.md) — quantitative
  chi-squared/entropy/NIST-SP-800-22 analysis of keyslot data: what
  statistical testing can and cannot detect about damage, measured on
  real on-disk keyslot areas.
- [`docs/kdf-comparison.md`](docs/kdf-comparison.md) — Argon2id vs.
  PBKDF2 grounded in the actual specs, cryptsetup's source, and real
  published GPU cracking-speed benchmarks.

[`experiments/`](experiments) holds the reproducible experiments behind
the docs' claims: each has a `run` script, needs no root, works on
throwaway image files, and records the output it produced.

## Usage

### Inspect a keyslot

```
sudo ./scripts/inspect-keyslot /dev/sdX
```

Prompts for which keyslot to inspect if the volume has more than one,
computes the byte range from `luksDump` automatically (no manual offset
arithmetic), dumps the head/tail of the raw keyslot area, and runs two
rough heuristics, for long zero runs and short repeating patterns, as
visual aids. See
[`docs/checking-for-corruption.md`](docs/checking-for-corruption.md)
for how to interpret the output.

```
sudo ./scripts/inspect-keyslot --slot 0 /dev/sdX
./scripts/inspect-keyslot --help
```

### Recover a near-miss passphrase

```
sudo ./scripts/recover-passphrase /dev/sdX 'my-best-guess-passphrase'
./scripts/recover-passphrase ./device.img 'my-best-guess-passphrase'
```

Tests the guess itself, then candidates one edit away from it
(substitutions by neighbouring keys and shift pairs, deletions, and
insertions of digits and common symbols), each with
`cryptsetup open --test-passphrase`, which never activates the device.
An image file of the device needs no root. It does not cover every
one-character difference: uppercase slips and missing letters are not
tried. See [`docs/passphrase-recovery.md`](docs/passphrase-recovery.md)
for the full walkthrough and real example output.

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
  covers `qwerty` (default), `azerty`, and `qwertz`. Dvorak arranges
  the keys differently enough that it would need its own adjacency
  table built from scratch rather than derived from the QWERTY one.
- **Wider substitution and insertion sets.** Substitution covers only
  lowercase letters, digits and shift/symbol pairs, and insertion only
  digits and a few symbols, so an uppercase slip or a missing letter
  is not found (see
  [`experiments/passphrase-recovery/`](experiments/passphrase-recovery)).
  Covering them, including case changes, would multiply the number of
  candidates, each costing about 2 seconds with default Argon2id.
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
  search — all listed above). Scoping work would need to weigh: each
  `cryptsetup open --test-passphrase` call spends about 2 seconds in
  Argon2id with default settings, which dominates the run time
  regardless of language; whether a rewrite
  should shell out to `cryptsetup` as today or link `libcryptsetup`
  directly; and whether it's worth the loss of "read the whole script in
  one sitting" auditability that POSIX `sh` currently provides for a
  security-sensitive recovery tool. Not started — needs its own
  scoping/design discussion before any implementation.

If you build one of these, a PR is welcome — please keep new methods in
their own clearly-labeled script/doc pair rather than folding them into
the existing edit-distance-1 tool, so the safe/tractable case stays
simple and the more speculative/expensive methods stay clearly opt-in.

### Research milestones (pre-roadmap)

These two are deeper and more open-ended than the extensions above —
research/analysis work, not scoped features. Both are now written up
in full; the intent is for their findings to *inform* future roadmap
items (e.g. a statistically-grounded corruption heuristic to replace or
supplement `inspect-keyslot`'s current zero-run/pattern-repeat checks,
or KDF-choice guidance grounded in an actual security comparison), not
that either doc is itself a scoped feature to implement directly:

- **Entropy/noise analysis of encrypted segments, done quantitatively.**
  `inspect-keyslot`'s current heuristics (see
  [`docs/af-splitting-explained.md`](docs/af-splitting-explained.md))
  are visual/structural — zero-run length, repeating-pattern detection
  — explicitly *not* a statistical measure, and incapable of catching
  damage that leaves random-looking bytes, such as flipped bits: a
  keyslot area is ciphertext, and so is what such damage leaves.
  **Done**: see [`docs/entropy-analysis.md`](docs/entropy-analysis.md)
  for chi-squared, NIST SP 800-22 and Shannon entropy tests run on
  real on-disk keyslot areas, intact and damaged, and what each test,
  `inspect-keyslot` and `cryptsetup repair` catch.
- **Argon2id vs. PBKDF2 comparison, LUKS1 vs. LUKS2, done
  cryptographically.** A rigorous comparison — memory-hardness
  properties, GPU/ASIC attack cost modeling, actual information
  leakage from KDF parameters stored in cleartext header/JSON metadata
  (iteration count, memory cost, salt) — grounding LUKS1-vs-LUKS2 KDF
  discussion in real cryptanalysis and the relevant math rather than
  the generic "Argon2id is memory-hard, PBKDF2 isn't" summary this
  project's docs otherwise rely on. **Done**: see
  [`docs/kdf-comparison.md`](docs/kdf-comparison.md).
- **Source-verified function-call diagrams of dm-crypt/LUKS2
  internals.** The master key's kernel-side lifecycle (tfm creation,
  keying, per-sector encrypt/decrypt, teardown/zeroization) is **done**
  — see the "Key-lifecycle call graph" in
  [`docs/master-key-lifecycle.md`](docs/master-key-lifecycle.md#key-lifecycle-call-graph).
  Two further diagrams, same standard (every edge fetched and
  line-verified against a pinned kernel commit, not narrated), are
  planned as separate future work, not yet started: **(1)** tweak/IV
  generation (`iv_gen_ops`, `crypt_iv_essiv`, etc.) — referenced by the
  key-lifecycle diagram's bio-dispatch layer but not itself traced;
  **(2)** the full userspace-to-kernel unlock path — keyslot unwrap,
  AF-merge, digest verification, and the `luksOpen` handoff into the
  kernel-side diagram that already exists. **(3)** Re-trace the
  existing key-lifecycle diagram against Linux v7.4 once it is
  released. The diagram's pinned commits are all part of v7.3; since
  then, kernel master has moved x86's AES-NI XTS code into the AES
  library
  ([`2bd68888`](https://github.com/torvalds/linux/commit/2bd6888849d6d2d5497c2470cc71c8d2cb170523))
  and raised the library-backed `xts-aes-lib`'s x86 priority to 500
  ([`f410daa3`](https://github.com/torvalds/linux/commit/f410daa32cfcd94263f156662a1ad2097505443c)),
  so on x86 the backend selection, keying and per-sector layers will
  likely change.

## Contributing

Issues and pull requests are welcome. Shell scripts are strict POSIX
`sh`, should pass `shellcheck --shell=sh`, and follow the existing
style (`set -eu`, explicit `--help`, clear argument validation,
comments only where the *why* isn't obvious from the code itself, and
an SPDX license line with a copyright notice at the top).
Documentation changes should match the depth and structure of the
existing `docs/` files, cite their sources with commit-pinned links and
section or page numbers, and back measurable claims with an experiment
in [`experiments/`](experiments).

## License

GPL-3.0-or-later. See [LICENSE](LICENSE).
