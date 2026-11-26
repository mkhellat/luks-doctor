# Passphrase Recovery: Bounded Edit-Distance Search

This document explains the one recovery technique this project
implements, `scripts/recover-passphrase`, what it searches, and its
limits. Read [`checking-for-corruption.md`](checking-for-corruption.md)
first and check that the header and keyslots look intact: this tool is
for the case where the disk is fine and the passphrase is the problem.
What the script recovers and what it misses is recorded by
[`experiments/passphrase-recovery/`](../experiments/passphrase-recovery).

## What this is, and what it is not

**This is not a password cracker.** It does not guess an unknown
passphrase. It is for one situation: you know the passphrase well
enough to type it out, the volume won't open, and you suspect that one
character differs between what you type now and what was set, through
a slip either then or now.

The scope is narrow because every guess is expensive. Each test runs
the keyslot's key derivation function; cryptsetup's default Argon2id
settings are tuned to take about 2 seconds on the machine that
formatted the volume (see
[`luks2-header-anatomy.md#argon2id`](luks2-header-anatomy.md#argon2id)),
and in the experiment one test took about 1.95 seconds. A few hundred
guesses near a known passphrase take minutes; searching for an unknown
passphrase is out of reach this way. If you have no close guess, this
tool cannot help; see the [Roadmap](../README.md#roadmap) for what
larger searches would involve, such as GPU tools like hashcat, whose
7.0.0 release added LUKS2 among its new hash types.

## How each guess is tested

```
printf '%s' "$candidate" | cryptsetup open --test-passphrase /dev/sdX
```

`--test-passphrase` makes cryptsetup "not activate the device, just
verify the passphrase"
([`man/common_options.adoc`](https://gitlab.com/cryptsetup/cryptsetup/-/blob/bae21790d59897ac50e5471f953f76b3a58aeeb6/man/common_options.adoc),
lines 1040–1041): it derives the keyslot key from the passphrase,
decrypts and merges the keyslot, and checks the result against the
master-key digest (see
[`af-splitting-explained.md#how-a-wrong-key-is-detected`](af-splitting-explained.md#how-a-wrong-key-is-detected)).
A passphrase read from standard input ends at the first newline
(`cryptsetup(8)`, "Passphrase processing for LUKS"), so the script
passes each candidate with `printf '%s'`. This means:

- **No device mapping is created**, so there is nothing to close or
  accidentally mount.
- **The data is never read or written**; only the header and keyslot
  area are read.
- **The header can be rewritten, in one case.** If one of the two
  header copies is damaged, any cryptsetup command that reads the
  header, including `--test-passphrase`, rewrites the damaged copy
  from the good one (shown by
  [`experiments/corruption-signals/`](../experiments/corruption-signals)).
  With an intact header, the experiment found the image unchanged
  after every search. Working on an image of the device, rather than
  the device itself, avoids even that.
- **It can be repeated freely.** cryptsetup has no lockout or rate
  limit; the only limit is the time each guess takes.

The exit status says what happened: `0` means a keyslot accepted the
passphrase, and `2` means "no permission (bad passphrase)"; other
values are errors such as "wrong device specified" (`cryptsetup(8)`,
"RETURN CODES"). The script treats only `2` as a non-matching
candidate. Any other error stops the search and prints cryptsetup's
message, since it would make every remaining candidate fail the same
way. Before starting, the script also checks that the target is a LUKS
device at all, and it tests the guess itself first: if the guess
already works, it says so, since the problem is then not the
passphrase.

## The edits

From the base guess, the script generates every candidate reachable by
one of these edits at any position, removes duplicates, and tests them
in that order:

1. **Substitution**: one character replaced by one of its neighbours
   on the keyboard, or by the character sharing its key with Shift
   (for example `s` for `a`, or `@` for `2`). The neighbours come from
   a table for the chosen layout (see
   [Keyboard layouts](#keyboard-layouts)), which covers the lowercase
   letters and digits, and the Shift table covers digits and common
   symbols. An **uppercase** letter is handled as a Shift slip from its
   own key: its neighbours are offered in uppercase, and a neighbouring
   number key as the symbol Shift types there (so `R`, `Y`, `F`, `G`
   for `T` on QWERTY). A letter's own case is not changed here; that is
   a separate edit (5).
2. **Deletion**: one character removed. This finds a passphrase that
   is one character shorter than what you type, for instance because a
   keystroke did not register when the passphrase was set.
3. **Insertion**: one character added at any position. By default the
   inserted character comes only from the set `0123456789!@#$%^&*_-.`
   (change it with `--insert-chars`); a missing **letter** is found
   only with `--insert-letters`, which also tries each of `a`–`z`.
   Letters are opt-in because adding 26 characters at every position
   roughly doubles the candidate count, and so the search time.
4. **Transposition**: two adjacent characters swapped, for example
   `Tnago` for `Tango`. Swapping two equal characters gives the guess
   back, so those pairs are skipped.
5. **Case flip**: one letter's case inverted, for example `t` for `T`
   — a stray Shift or Caps Lock. Non-letters are skipped.

The first four are the errors of Damerau's spelling-correction method:
"a wrong, missing or extra letter or a single transposition" (F. J.
Damerau, "A technique for computer detection and correction of
spelling errors", *Communications of the ACM* 7(3), pp. 171–176, 1964,
DOI [10.1145/363958.363994](https://doi.org/10.1145/363958.363994));
the case flip is an addition beyond Damerau's set. The script tries
only some of the possible substitutions and insertions, so it searches
a subset of the passphrases one such edit away.

In the experiment, with the passphrase `Tango-ok7`, the script
recovered it from `Tango-okk7` (deletion), `Tango-ol7` (`l` for its
neighbour `k`), `Tango-ok` (inserting `7`), `Tnago-ok7` (swapping `n`
and `a`), `Rango-ok7` (`R` for the uppercase neighbour `T`) and
`tango-ok7` (a case flip of `T`). The one case it still misses by
default is `Tango-o7`, a missing letter — and that one too is
recovered when the search is run with `--insert-letters`.

## Two edits at once

By default the search covers one edit (edit distance 1). `--edit-distance
2` combines two of the edits above, for a passphrase two slips from your
guess rather than one. It applies every edit to every distance-1
candidate, so the candidate count grows roughly as the square of the
distance-1 count — tens of thousands for a typical passphrase, each still
a full KDF run. The script prints the count and a rough time estimate
before it starts and warns that the run can be long; narrow it with the
`--no-*` options, or run it against a keyslot with a fast KDF (PBKDF2).
In the experiment, `Rango-ol7` — two neighbour slips from `Tango-ok7`
(`R` for the uppercase `T`, and `l` for `k`) — is not found at distance
1 but is recovered at distance 2.

Edit distances beyond 2 are not implemented: the candidate count, and so
the running time, grows by roughly another few-hundred-fold at each
step.

## Usage walkthrough

```
sudo ./scripts/recover-passphrase /dev/sdX 'my-best-guess'
```

Root is needed for a block device. An image file of the device that
you own needs no root:

```
./scripts/recover-passphrase ./device.img 'my-best-guess'
```

Real output for an image whose passphrase is `Tango-ok7`, with the
guess `Tango-okk7` (candidates 4 to 55, all "no match", are left out):

```
luks-doctor: testing keyslot(s) on ./device.img
luks-doctor: base guess: Tango-okk7
luks-doctor: generated 302 candidates (substitution + deletion + insertion + transposition + case flip)
luks-doctor: testing the base guess itself... no match
luks-doctor: [1/302] testing candidate (substitution, pos 0)... no match
luks-doctor: [2/302] testing candidate (substitution, pos 0)... no match
luks-doctor: [3/302] testing candidate (substitution, pos 0)... no match
...
luks-doctor: [56/302] testing candidate (deletion, pos 7)... MATCH

luks-doctor: recovered passphrase:
  Tango-okk7   (original guess, for reference)
  Tango-ok7    (working passphrase - deletion, pos 7)

luks-doctor: SECURITY REMINDER
  This passphrase is now confirmed and was found via automated search.
  You should:
    1. Unlock the volume normally and mount it to confirm data access.
    2. Add a new keyslot with a passphrase you're confident you can type
       reliably: cryptsetup luksAddKey ./device.img
    3. Once confirmed working, consider removing the old/typo-prone
       keyslot: cryptsetup luksKillSlot ./device.img <slot>
  Treat any passphrase that was ever tested in bulk, or written to a
  terminal/log, as lower-confidence going forward - rotate it if this
  volume protects anything sensitive.
```

Positions count from 0, so position 0 is the uppercase `T`, which now
has substitution and case-flip candidates of its own. If nothing
matches, the script says so and exits with status 1.

**The guess is visible to other users while the script runs.** It is
a command-line argument, and `/proc/pid/cmdline` "holds the complete
command line for the process" (`proc_pid_cmdline(5)`), which every
user can read unless `/proc` is mounted with `hidepid` (the default is
`hidepid=0`, "Everybody may access all /proc/pid directories",
`proc(5)`). It may also end up in your shell history. Run the script
on a machine where that matters as little as possible, and change the
passphrase afterwards, as the script's own reminder says.

`./scripts/recover-passphrase --help` lists the options: `--layout`,
`--no-substitution`, `--no-deletion`, `--no-insertion`,
`--no-transposition`, `--no-case-flip`, `--insert-chars`,
`--insert-letters` and `--edit-distance`.

## Keyboard layouts

`--layout` selects the table of neighbouring keys used for
substitution:

- **`qwerty`** (default): US QWERTY.
- **`azerty`**: French AZERTY. The top letter row is `a z e r t y u i
  o p`, the middle row ends in `m`, and the bottom row starts with `w`.
  The Shift table also includes the ASCII pairs of AZERTY's number row
  (`1`/`&`, `4`/`'`, `5`/`(`); the other keys of that row give accented
  or other non-ASCII characters and are left out.
- **`qwertz`**: German QWERTZ, the QWERTY table with `y` and `z`
  swapped.
- **`dvorak`**: US Dvorak (Simplified). The same physical ANSI keys as
  QWERTY with the letters rearranged, so `d` and `g` are neighbours, for
  instance, where on QWERTY they are not. The number row is unchanged.

The tables are written into the script. The QWERTY, QWERTZ and Dvorak
tables are checked against a physical ANSI key grid by
[`experiments/keyboard-adjacency/`](../experiments/keyboard-adjacency):
the same grid reproduces QWERTY and QWERTZ exactly, which is the
evidence that it also derives Dvorak correctly. AZERTY, an ISO layout
with a different physical arrangement, was derived by hand instead. Pick
the layout the passphrase was typed on when the slip happened. If the
layout is not listed, `qwerty` is still worth trying: deletion and
insertion do not depend on the layout.

Passphrases with non-ASCII characters have not been tested. The
script counts characters with the shell's `${#var}` and picks them out
with `cut -c`, and both treat multibyte characters differently
depending on the shell, the locale and the version of `cut` (GNU
coreutils 9.12's `cut -c` handles UTF-8 characters whole; dash's
`${#var}` counts bytes), so candidates for such passphrases may be
wrong.

---

For what is deliberately not built yet (edit distances beyond 2,
dictionary-based candidates, GPU search), see the
[Roadmap section of the README](../README.md#roadmap).
