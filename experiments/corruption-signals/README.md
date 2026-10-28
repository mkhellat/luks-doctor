# Corruption signals

## Claims

On a LUKS2 image formatted with cryptsetup's defaults (cryptsetup 2.8.8):

- the pattern `^  [0-9]+: ` matches data segments and digests in
  `luksDump` output as well as keyslots; restricting it to the
  `Keyslots:` section lists only keyslots;
- `luksHeaderBackup` writes 16 MiB, the whole header region including
  the keyslots area;
- `cryptsetup repair` warns about a keyslot area with a zeroed block or
  a repeated fill pattern, naming the suspect offsets, but exits 0 and
  changes nothing; it does not notice one changed byte;
- every kind of keyslot damage tested makes `open --test-passphrase`
  print "No key available with this passphrase." (exit 2), the same as
  a wrong passphrase;
- with the primary header damaged, `luksDump`, `open` and `repair` all
  work, print nothing about the damage, and rewrite the primary header
  from the secondary;
- with both header copies damaged, all of them fail with "Device ... is
  not a valid LUKS device." (exit 1), and `luksHeaderRestore` from a
  backup brings the volume back.

Used in [`docs/checking-for-corruption.md`](../../docs/checking-for-corruption.md).

## Sources

- [`man/cryptsetup-repair.8.adoc`](https://gitlab.com/cryptsetup/cryptsetup/-/blob/bae21790d59897ac50e5471f953f76b3a58aeeb6/man/cryptsetup-repair.8.adoc)
  at cryptsetup commit `bae21790`, section "LUKS keyslots corruption
  detection": "Only certain corruptions, usually only a low-entropy
  area (like zeroed blocks), can be detected. The detection prints only
  warnings. It does not modify keyslots."
- [`man/cryptsetup-luksHeaderBackup.8.adoc`](https://gitlab.com/cryptsetup/cryptsetup/-/blob/bae21790d59897ac50e5471f953f76b3a58aeeb6/man/cryptsetup-luksHeaderBackup.8.adoc):
  "Stores a binary backup of the LUKS header and keyslot area."
- `LUKS2_disk_hdr_read()` in `lib/luks2/luks2_disk_metadata.c` (lines
  640–807), which rewrites a damaged header copy from the valid one; see
  [`../header-anatomy/`](../header-anatomy).

## Requirements

`cryptsetup`, `truncate`, `dd`, `xxd`, `cmp`. No root.

## Run

```
experiments/corruption-signals/run
```

The script formats a throwaway image (PBKDF2 with 1000 iterations, to
keep it fast), then damages copies of it:

| Case | Damage |
|---|---|
| 0 | none |
| 1 | 4096 bytes of keyslot 0's area zeroed, starting 8192 bytes into the area |
| 2 | the same 4096 bytes filled with `de ad be ef` repeated |
| 3 | one byte of the area changed, 8192 bytes in |
| 4 | one byte of the primary JSON area changed |
| 5 | one byte of each JSON area changed |

For each it runs `luksDump`, `open --test-passphrase` and `repair`,
and prints their messages and exit status; for case 4 it also reports
whether each command rewrote the primary header, and for case 5 it
restores the header backup taken at the start.

## Result (2026-10-28)

```
cryptsetup 2.8.8 flags: UDEV BLKID KEYRING KERNEL_CAPI HW_OPAL 

== Keyslot listing: what the pattern '^  [0-9]+: ' matches ==
  0: crypt
  0: luks2
  0: pbkdf2
== Keyslots section only ==
  0: luks2

== Header backup size ==
   16777216 bytes

== Case 0: intact image ==
   luksDump (stdout discarded):
      exit status: 0
   open --test-passphrase:
      exit status: 0
   repair:
      exit status: 0

== Case 1: 4096 bytes of keyslot area zeroed (area offset 8192) ==
00000000: 0e6a 5fac 387e bcfd 19e7 b0a5 57a4 80c5  .j_.8~......W...
00000010: 5be2 aed3 e945 f7fe 71fa 4775 0b63 342f  [....E..q.Gu.c4/
00000020: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000030: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000040: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000050: 0000 0000 0000 0000 0000 0000 0000 0000  ................
   luksDump (stdout discarded):
      exit status: 0
   open --test-passphrase:
      No key available with this passphrase.
      exit status: 2
   repair:
      Keyslot 0 binary data could be corrupted.
        Suspected offset: 0xa000
        Suspected offset: 0xa080
        Suspected offset: 0xa100
        Subsequent suspected offsets are suppressed.
      You can use hexdump -v -C -n 128 -s <offset_0xXXXX> "<tmpdir>/c1.img" to inspect the data.
      exit status: 0

== Case 2: 4096 bytes of keyslot area filled with de ad be ef ==
00000000: 0e6a 5fac 387e bcfd 19e7 b0a5 57a4 80c5  .j_.8~......W...
00000010: 5be2 aed3 e945 f7fe 71fa 4775 0b63 342f  [....E..q.Gu.c4/
00000020: dead beef dead beef dead beef dead beef  ................
00000030: dead beef dead beef dead beef dead beef  ................
00000040: dead beef dead beef dead beef dead beef  ................
00000050: dead beef dead beef dead beef dead beef  ................
   luksDump (stdout discarded):
      exit status: 0
   open --test-passphrase:
      No key available with this passphrase.
      exit status: 2
   repair:
      Keyslot 0 binary data could be corrupted.
        Suspected offset: 0xa000
        Suspected offset: 0xa080
        Suspected offset: 0xa100
        Subsequent suspected offsets are suppressed.
      You can use hexdump -v -C -n 128 -s <offset_0xXXXX> "<tmpdir>/c2.img" to inspect the data.
      exit status: 0

== Case 3: one byte of keyslot area flipped (area offset 8192) ==
   luksDump (stdout discarded):
      exit status: 0
   open --test-passphrase:
      No key available with this passphrase.
      exit status: 2
   repair:
      exit status: 0

== Case 4: one byte of the primary JSON area changed ==
   luksDump (stdout discarded):
      exit status: 0
      primary header: rewritten
   open --test-passphrase:
      exit status: 0
      primary header: rewritten
   repair:
      exit status: 0
      primary header: rewritten
   primary JSON area now identical to the original

== Case 5: both JSON areas changed (bytes 8192 and 16384+8192) ==
   luksDump (stdout discarded):
      Device <tmpdir>/c5.img is not a valid LUKS device.
      exit status: 1
   open --test-passphrase:
      Device <tmpdir>/c5.img is not a valid LUKS device.
      exit status: 1
   repair:
      Device <tmpdir>/c5.img is not a valid LUKS device.
      exit status: 1
   luksHeaderRestore from the backup taken earlier:
      exit status: 0
   open --test-passphrase after restore:
      exit status: 0
```

The bytes before each damaged block are random and differ between
runs; the temporary directory is shown as `<tmpdir>`. The suspected
offset `0xa000` is 40960: the keyslot area's offset (32768) plus 8192.
