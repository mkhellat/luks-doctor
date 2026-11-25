# Passphrase recovery

## Claims

`scripts/recover-passphrase`, run against a LUKS2 image whose
passphrase is `Tango-ok7`:

- recovers the passphrase from a guess with one extra character, one
  lowercase letter or digit typed as a neighbouring key, or a missing
  digit or symbol from its insertion set, or two adjacent characters
  swapped;
- does not recover it from a guess with a missing letter (it only
  inserts digits and `!@#$%^&*_-.`) or with an uppercase letter typed
  as a neighbouring key (its keyboard tables cover lowercase letters,
  digits and symbols only);
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
luks-doctor: generated 262 candidates (substitution + deletion + insertion + transposition)
luks-doctor: testing the base guess itself... MATCH
   exit status: 0
   image unchanged by the search

== Guess 'Tango-okk7' (one extra character) ==
luks-doctor: generated 288 candidates (substitution + deletion + insertion + transposition)
luks-doctor: [50/288] testing candidate (deletion, pos 7)... MATCH
  Tango-ok7    (working passphrase - deletion, pos 7)
   exit status: 0
   image unchanged by the search

== Guess 'Tango-ol7' (k typed as its neighbour l) ==
luks-doctor: generated 260 candidates (substitution + deletion + insertion + transposition)
luks-doctor: [28/260] testing candidate (substitution, pos 7)... MATCH
  Tango-ok7    (working passphrase - substitution, pos 7)
   exit status: 0
   image unchanged by the search

== Guess 'Tango-ok' (final digit missing) ==
luks-doctor: generated 235 candidates (substitution + deletion + insertion + transposition)
luks-doctor: [215/235] testing candidate (insertion, pos 8)... MATCH
  Tango-ok7    (working passphrase - insertion, pos 8)
   exit status: 0
   image unchanged by the search

== Guess 'Tango-o7' (letter missing) ==
luks-doctor: generated 234 candidates (substitution + deletion + insertion + transposition)
luks-doctor: no match found among 234 edit-distance-1 candidates.
   exit status: 1
   image unchanged by the search

== Guess 'Rango-ok7' (uppercase T typed as its neighbour R) ==
luks-doctor: generated 262 candidates (substitution + deletion + insertion + transposition)
luks-doctor: no match found among 262 edit-distance-1 candidates.
   exit status: 1
   image unchanged by the search

== Guess 'Tnago-ok7' (a and n swapped) ==
luks-doctor: generated 262 candidates (substitution + deletion + insertion + transposition)
luks-doctor: [256/262] testing candidate (transposition, pos 1)... MATCH
  Tango-ok7    (working passphrase - transposition, pos 1)
   exit status: 0
   image unchanged by the search

== A file that is not a LUKS device ==
recover-passphrase: error: <tmpdir>/notluks.img is not a LUKS device (or cannot be read)

== Time for one --test-passphrase with default Argon2id ==
	Time cost:  4
	Memory:     483660
	Threads:    4
   wrong passphrase: exit status 2, 1774 ms
   wrong passphrase: exit status 2, 1814 ms
   wrong passphrase: exit status 2, 1890 ms
```
