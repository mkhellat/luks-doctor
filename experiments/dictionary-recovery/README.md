# Dictionary recovery

## Claims

`scripts/recover-dictionary`, given a wordlist and a LUKS2 image,
recovers a passphrase built from a wordlist entry by each of its four
transformations:

- a capitalized word with an appended year (`Summer2024` from `summer`);
- a leetspeak form (`p@55w0rd` from `password`);
- a two-word entry joined with a separator (`correct-horse` from the
  entry `correct horse`);

and, as controls:

- reports no match when the passphrase's word is not in the wordlist;
- errors, rather than guessing, when no `--wordlist` is given and
  `/usr/share/dict/words` does not exist;
- errors when the target is not a LUKS device;
- does not change the image.

Used in [`docs/dictionary-recovery.md`](../../docs/dictionary-recovery.md).

## Requirements

`cryptsetup` and `truncate`. No root; the images use PBKDF2 with a low
iteration count, so each test is fast and needs little RAM. A run takes
under a minute.

## Run

```
experiments/dictionary-recovery/run
```

For each case the output shows the search summary lines from
`recover-dictionary` (the many "no match" lines and the size warning are
filtered out), its exit status, and whether the image's SHA-256 changed.

## Result (2026-11-26)

```
cryptsetup 2.8.9 flags: UDEV BLKID KEYRING KERNEL_CAPI HW_OPAL 

== Passphrase 'Summer2024' (Capitalized word + appended year) ==
luks-doctor: wordlist: <tmpdir>/wl (1 entries)
luks-doctor: generated 175 candidates (case + leetspeak + append + separators)
luks-doctor: [103/175] testing candidate (from 'summer')... MATCH
  Summer2024    (working passphrase - from 'summer')
   exit status: 0
   image unchanged by the search

== Passphrase 'p@55w0rd' (leetspeak) ==
luks-doctor: wordlist: <tmpdir>/wl (1 entries)
luks-doctor: generated 6 candidates (case + leetspeak + append + separators)
luks-doctor: [2/6] testing candidate (from 'password')... MATCH
  p@55w0rd    (working passphrase - from 'password')
   exit status: 0
   image unchanged by the search

== Passphrase 'correct-horse' (two words joined with '-') ==
luks-doctor: wordlist: <tmpdir>/wl (1 entries)
luks-doctor: generated 30 candidates (case + leetspeak + append + separators)
luks-doctor: [7/30] testing candidate (from 'correct horse')... MATCH
  correct-horse    (working passphrase - from 'correct horse')
   exit status: 0
   image unchanged by the search

== Passphrase 'Summer2024' (word not in the list (no match)) ==
luks-doctor: wordlist: <tmpdir>/wl (1 entries)
luks-doctor: generated 210 candidates (case + leetspeak + append + separators)
luks-doctor: no match found among 210 wordlist candidates.
   exit status: 1
   image unchanged by the search

== No --wordlist and no system dictionary ==
recover-dictionary: error: no --wordlist given and /usr/share/dict/words does not exist

== A file that is not a LUKS device ==
recover-dictionary: error: <tmpdir>/notluks.img is not a LUKS device (or cannot be read)
```

The candidate counts are small because each wordlist here has one entry.
The count scales with the wordlist: roughly 175 candidates per
single-word entry with the defaults, so a large dictionary is out of
reach against a default-Argon2id keyslot (each candidate is a full KDF).
