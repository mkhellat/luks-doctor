# Dictionary/Mnemonic Recovery: Wordlist-Based Search

This document explains the second recovery tool this project ships,
`scripts/recover-dictionary`, what it searches, and its limits. It is a
different method from [`passphrase-recovery.md`](passphrase-recovery.md):
that tool edits one guess character by character; this one starts from a
wordlist and applies the transformations people actually use when they
build a passphrase from a word or phrase. Read
[`checking-for-corruption.md`](checking-for-corruption.md) first and
confirm the header and keyslots look intact — this tool, like the other,
is for when the disk is fine and the passphrase is the problem. What it
recovers is recorded by
[`experiments/dictionary-recovery/`](../experiments/dictionary-recovery).

## What this is, and what it is not

**This is not a general password cracker.** Every candidate runs the
keyslot's key derivation function, and cryptsetup's default Argon2id
settings take about 2 seconds per test (see
[`luks2-header-anatomy.md#argon2id`](luks2-header-anatomy.md#argon2id)).
With the default transformations this tool generates roughly 175
candidates per single-word entry, so even a modest 10,000-word
dictionary is about 1.75 million tests — around 40 days of Argon2id. A
full system dictionary is out of reach.

It is useful in three situations instead:

- you remember the **word or phrase** the passphrase was built from, or
  a short list of likely ones, and only need to find which
  transformation was applied;
- the keyslot uses a **fast KDF** (PBKDF2 rather than Argon2id), where
  thousands of tests take seconds, not hours;
- you are willing to leave a **small, targeted wordlist** running for a
  long time.

If none of those hold, this tool cannot help; see the
[Roadmap](../README.md#roadmap) for what larger searches would involve.

## How each guess is tested

Exactly as in [`passphrase-recovery.md`](passphrase-recovery.md#how-each-guess-is-tested):
each candidate is passed to

```
printf '%s' "$candidate" | cryptsetup open --test-passphrase /dev/sdX
```

which verifies the passphrase without activating or mapping the device,
reads only the header and keyslot area, never touches the data, and can
be repeated freely (cryptsetup has no lockout). An exit status of `2`
means a wrong passphrase; any other error stops the search. With an
intact header the experiment found the image unchanged after every
search.

## The transformations

For each wordlist entry, the script generates candidates by combining
four transformations and tests every distinct result. Each can be turned
off with a `--no-*` option.

1. **Case** (`--no-case` to skip): the entry in lowercase, Capitalized
   (first letter only), and UPPERCASE.
2. **Leetspeak** (`--no-leet`): the common one-for-one swaps, applied all
   at once — `a`→`@`, `e`→`3`, `i`→`1`, `o`→`0`, `s`→`5`, `t`→`7`, in
   both letter cases. Only the fully-substituted form is tried, not every
   partial combination (`p@55w0rd`, not also `p@ssw0rd`).
3. **Append** (`--no-append`): each form followed by a common number or
   year. The built-in set is the single digits `0`–`9` and a short list
   of common endings and recent years (`00 01 11 12 13 21 22 23 69 99 123
   1234 321 007 420 1999 2000 2020`–`2026`); replace it with
   `--append-list "0 1 … 2026"`. Appending every 1–4 digit number instead
   would multiply the search by thousands, so the default set is
   deliberately short.
4. **Separators** (`--no-separators`): for an entry of several
   space-separated words, the words rejoined with `''` (no gap), `-`,
   `_`, `.`, and a space. This finds `correct-horse` or `correcthorse`
   from the entry `correct horse`.

Case changes and leetspeak are done with explicit character lists in
`tr` and `sed`, not `[a-z]`/`[A-Z]` ranges, because POSIX leaves bracket
ranges unspecified outside the C locale.

## The wordlist

`--wordlist FILE` reads candidate entries, one per line. Blank lines and
lines beginning with `#` are skipped, so a list can carry comments. If
`--wordlist` is omitted the script uses `/usr/share/dict/words` when it
exists, and otherwise stops and asks for a list rather than guessing.

A targeted list — the handful of words you actually suspect, one per
line, with multi-word phrases written with spaces so the separator
transformation applies — is far more likely to succeed in reasonable
time than a system dictionary.

## Usage walkthrough

```
./scripts/recover-dictionary --wordlist ./words ./device.img
```

Root is needed only for a block device; an image file you own needs
none. Real output for an image whose passphrase is `Summer2024`, with a
one-line wordlist containing `summer`:

```
luks-doctor: testing keyslot(s) on ./device.img
luks-doctor: wordlist: ./words (1 entries)
luks-doctor: generated 175 candidates (case + leetspeak + append + separators)
luks-doctor: WARNING: a wordlist search is large. At ~2 s per guess (cryptsetup's default Argon2id) this would take about 5 min; far less with a pbkdf2 keyslot. Each test is a full KDF run - use a shorter wordlist or the --no-* options if you can.
luks-doctor: [103/175] testing candidate (from 'summer')... MATCH

luks-doctor: recovered passphrase:
  Summer2024    (working passphrase - from 'summer')

luks-doctor: SECURITY REMINDER
  ...
```

The warning's time estimate assumes cryptsetup's default Argon2id
(~2 seconds per guess); a keyslot that uses PBKDF2 is far faster. If
nothing matches, the script says so and exits with status 1.

**The candidates are visible to other users while the script runs**, as
command-line arguments to `cryptsetup` in `/proc`, exactly as described
for [`passphrase-recovery.md`](passphrase-recovery.md#usage-walkthrough).
Run it where that matters as little as possible, and change the
passphrase afterwards, as the script's own reminder says.

`./scripts/recover-dictionary --help` lists the options: `--wordlist`,
`--no-case`, `--no-leet`, `--no-append`, `--no-separators` and
`--append-list`.

## Limits

The transformations are the common ones, not all of them: there is no
partial leetspeak, no character substitution mid-word, no combining of
two different wordlist entries, and the appended-number set is short by
design. A passphrase that mixes a dictionary word with genuinely random
characters is edit-distance work, not dictionary work, and belongs to
[`passphrase-recovery.md`](passphrase-recovery.md) instead.

---

For what is deliberately not built yet (combining multiple words,
larger transform sets, GPU search), see the
[Roadmap section of the README](../README.md#roadmap).
