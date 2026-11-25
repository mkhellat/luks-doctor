# Passphrase recovery

## Claims

`scripts/recover-passphrase`, run against a LUKS2 image whose
passphrase is `Tango-ok7`:

- recovers the passphrase by default from a guess with one extra
  character, one letter or digit typed as a neighbouring key (an
  uppercase letter as the Shift-held neighbour, e.g. `R` for `T`), a
  missing digit or symbol from its insertion set, two adjacent
  characters swapped, or one letter in the wrong case;
- recovers it from a guess with a missing letter only with
  `--insert-letters`, which raises the candidate count for this guess
  from 246 to 475;
- does not recover it from a guess with a missing letter without that
  option (the default insertion set is digits and `!@#$%^&*_-.`), and
  does not recover a missing uppercase letter even with it (the
  letters it inserts are lowercase);
- tests the guess itself first, and reports when it already works;
- stops with an error, instead of testing candidates, when the target
  is not a LUKS device;
- does not change the image.

It also measures one `cryptsetup open --test-passphrase` with
cryptsetup's default Argon2id settings: about 2 seconds per guess.

Used in [`docs/passphrase-recovery.md`](../../docs/passphrase-recovery.md).

## Requirements

`cryptsetup`, `truncate`, `sha256sum`, and a `date` that supports `%N`
(GNU coreutils). No root. The default-Argon2id image needs up to 1 GiB
of RAM. A run takes about a minute.

## Run

```
experiments/passphrase-recovery/run
```

For each guess, the output shows the search summary lines from
`recover-passphrase` (the many "no match" lines are filtered out), its
exit status, and whether the image's SHA-256 changed during the search.

## Result (2026-11-25)

```
cryptsetup 2.8.9 flags: UDEV BLKID KEYRING KERNEL_CAPI HW_OPAL 
Real passphrase: Tango-ok7

== Guess 'Tango-ok7' (the real passphrase) ==
luks-doctor: generated 275 candidates (substitution + deletion + insertion + transposition + case flip)
luks-doctor: testing the base guess itself... MATCH
   exit status: 0
   image unchanged by the search

== Guess 'Tango-okk7' (one extra character) ==
luks-doctor: generated 302 candidates (substitution + deletion + insertion + transposition + case flip)
luks-doctor: [56/302] testing candidate (deletion, pos 7)... MATCH
  Tango-ok7    (working passphrase - deletion, pos 7)
   exit status: 0
   image unchanged by the search

== Guess 'Tango-ol7' (k typed as its neighbour l) ==
luks-doctor: generated 273 candidates (substitution + deletion + insertion + transposition + case flip)
luks-doctor: [34/273] testing candidate (substitution, pos 7)... MATCH
  Tango-ok7    (working passphrase - substitution, pos 7)
   exit status: 0
   image unchanged by the search

== Guess 'Tango-ok' (final digit missing) ==
luks-doctor: generated 248 candidates (substitution + deletion + insertion + transposition + case flip)
luks-doctor: [221/248] testing candidate (insertion, pos 8)... MATCH
  Tango-ok7    (working passphrase - insertion, pos 8)
   exit status: 0
   image unchanged by the search

== Guess 'Tango-o7' (letter missing) ==
luks-doctor: generated 246 candidates (substitution + deletion + insertion + transposition + case flip)
luks-doctor: no match found among 246 edit-distance-1 candidates.
   exit status: 1
   image unchanged by the search

== Guess 'Rango-ok7' (uppercase T typed as its neighbour R) ==
luks-doctor: generated 275 candidates (substitution + deletion + insertion + transposition + case flip)
luks-doctor: [4/275] testing candidate (substitution, pos 0)... MATCH
  Tango-ok7    (working passphrase - substitution, pos 0)
   exit status: 0
   image unchanged by the search

== Guess 'Tnago-ok7' (a and n swapped) ==
luks-doctor: generated 275 candidates (substitution + deletion + insertion + transposition + case flip)
luks-doctor: [262/275] testing candidate (transposition, pos 1)... MATCH
  Tango-ok7    (working passphrase - transposition, pos 1)
   exit status: 0
   image unchanged by the search

== Guess 'tango-ok7' (T typed as t) ==
luks-doctor: generated 275 candidates (substitution + deletion + insertion + transposition + case flip)
luks-doctor: [269/275] testing candidate (case flip, pos 0)... MATCH
  Tango-ok7    (working passphrase - case flip, pos 0)
   exit status: 0
   image unchanged by the search

== Guess 'Tango-o7' (letter missing, with --insert-letters) ==
luks-doctor: generated 475 candidates (substitution + deletion + insertion + transposition + case flip)
luks-doctor: [402/475] testing candidate (insertion, pos 7)... MATCH
  Tango-ok7    (working passphrase - insertion, pos 7)
   exit status: 0
   image unchanged by the search

== A file that is not a LUKS device ==
recover-passphrase: error: <tmpdir>/notluks.img is not a LUKS device (or cannot be read)

== Time for one --test-passphrase with default Argon2id ==
	Time cost:  4
	Memory:     645801
	Threads:    4
   wrong passphrase: exit status 2, 1919 ms
   wrong passphrase: exit status 2, 1860 ms
   wrong passphrase: exit status 2, 1939 ms
```
