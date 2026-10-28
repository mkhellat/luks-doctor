# Passphrase recovery

## Claims

`scripts/recover-passphrase`, run against a LUKS2 image whose
passphrase is `Tango-ok7`:

- recovers the passphrase from a guess with one extra character, one
  lowercase letter or digit typed as a neighbouring key, or a missing
  digit or symbol from its insertion set;
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

## Result (2026-10-28)

```
cryptsetup 2.8.8 flags: UDEV BLKID KEYRING KERNEL_CAPI HW_OPAL 
Real passphrase: Tango-ok7

== Guess 'Tango-ok7' (the real passphrase) ==
luks-doctor: generated 254 candidates (substitution + deletion + insertion)
luks-doctor: testing the base guess itself... MATCH
   exit status: 0
   image unchanged by the search

== Guess 'Tango-okk7' (one extra character) ==
luks-doctor: generated 280 candidates (substitution + deletion + insertion)
luks-doctor: [50/280] testing candidate (deletion, pos 7)... MATCH
  Tango-ok7    (working passphrase - deletion, pos 7)
   exit status: 0
   image unchanged by the search

== Guess 'Tango-ol7' (k typed as its neighbour l) ==
luks-doctor: generated 252 candidates (substitution + deletion + insertion)
luks-doctor: [28/252] testing candidate (substitution, pos 7)... MATCH
  Tango-ok7    (working passphrase - substitution, pos 7)
   exit status: 0
   image unchanged by the search

== Guess 'Tango-ok' (final digit missing) ==
luks-doctor: generated 228 candidates (substitution + deletion + insertion)
luks-doctor: [215/228] testing candidate (insertion, pos 8)... MATCH
  Tango-ok7    (working passphrase - insertion, pos 8)
   exit status: 0
   image unchanged by the search

== Guess 'Tango-o7' (letter missing) ==
luks-doctor: generated 227 candidates (substitution + deletion + insertion)
luks-doctor: no match found among 227 edit-distance-1 candidates.
   exit status: 1
   image unchanged by the search

== Guess 'Rango-ok7' (uppercase T typed as its neighbour R) ==
luks-doctor: generated 254 candidates (substitution + deletion + insertion)
luks-doctor: no match found among 254 edit-distance-1 candidates.
   exit status: 1
   image unchanged by the search

== A file that is not a LUKS device ==
recover-passphrase: error: <tmpdir>/notluks.img is not a LUKS device (or cannot be read)

== Time for one --test-passphrase with default Argon2id ==
	Time cost:  4
	Memory:     1048576
	Threads:    4
   wrong passphrase: exit status 2, 1960 ms
   wrong passphrase: exit status 2, 1946 ms
   wrong passphrase: exit status 2, 1971 ms
```
