# Checking a LUKS2 Volume for Corruption

This is a practical guide to inspecting a LUKS2 device directly:
extracting raw bytes with `dd`, reading them with `xxd`, and using
cryptsetup's own checks to tell a damaged header or keyslot from a
wrong passphrase. It builds on
[`luks2-header-anatomy.md`](luks2-header-anatomy.md), which explains
the structures involved. What cryptsetup prints in each situation
below was recorded by
[`experiments/corruption-signals/`](../experiments/corruption-signals)
with cryptsetup 2.8.8.

**Before anything else, back up the header:**

```
sudo cryptsetup luksHeaderBackup /dev/sdX --header-backup-file ./header-backup.img
```

The backup holds "the LUKS header and keyslot area"
([man page](https://gitlab.com/cryptsetup/cryptsetup/-/blob/bae21790d59897ac50e5471f953f76b3a58aeeb6/man/cryptsetup-luksHeaderBackup.8.adoc)):
16 MiB with cryptsetup's default layout. With it, whatever goes wrong
during the steps below, you can put the header back as it was. Keep
it safe: any passphrase that is valid when the backup is taken can
later open the volume with it, even after that passphrase is removed
from the device.

## Contents

- [Confirm you have the right device](#confirm-you-have-the-right-device)
- [Extracting a keyslot's raw bytes with `dd`](#extracting-a-keyslots-raw-bytes-with-dd)
- [What healthy key material looks like](#what-healthy-key-material-looks-like)
- [What corrupted key material looks like](#what-corrupted-key-material-looks-like)
- [What no inspection can detect](#what-no-inspection-can-detect)
- [Diffing primary vs. secondary headers](#diffing-primary-vs-secondary-headers)
- [When to run `cryptsetup repair`, and what it can't fix](#when-to-run-cryptsetup-repair-and-what-it-cant-fix)
- [Decision guide](#decision-guide)

## Confirm you have the right device

Everything below reads raw bytes at absolute offsets, so first make
sure `/dev/sdX` is the LUKS device you mean. A device path can change
when a USB enclosure is replugged, and reading the wrong device (or a
whole disk instead of its partition) gives bytes that are easy to
mistake for corruption:

```
sudo blkid /dev/sdX
```

Expect `TYPE="crypto_LUKS"`. If `blkid` shows another type or nothing,
or the device doesn't match what `lsblk` shows, stop and identify the
device again before going further.

## Extracting a keyslot's raw bytes with `dd`

First, get the keyslot's byte range from `luksDump`:

```
sudo cryptsetup luksDump /dev/sdX
```

Find the keyslot you want and note its `Area offset` and `Area length`,
both in bytes (see
[`luks2-header-anatomy.md#reading-area-offset--area-length`](luks2-header-anatomy.md#reading-area-offset--area-length)).

**Checking more than one keyslot.** Keyslot numbers need not be
contiguous: removing a keyslot does not renumber the others, so a
volume with two keyslots may have slots `0` and `2`. To list the
keyslots present, look only at the `Keyslots:` section of `luksDump`,
since data segments and digests are numbered the same way:

```
sudo cryptsetup luksDump /dev/sdX | sed -n '/^Keyslots:/,/^Tokens:/p' | grep -E '^  [0-9]+: '
```

Each keyslot has its own `Area offset` and `Area length`; repeat the
extraction below for each one. Every keyslot holds its own copy of the
master key, so an intact keyslot whose passphrase you know is a way
back in even if another keyslot is damaged (see the
[decision guide](#decision-guide)).

Then extract exactly that byte range:

```
sudo dd if=/dev/sdX bs=1 skip=<Area offset> count=<Area length> 2>/dev/null | xxd
```

What each part does:

- `if=/dev/sdX`: the input, the device, or an image file of it; working
  on an image is safer for repeated experiments.
- `bs=1`: a block size of 1 byte, so `skip=` and `count=` count bytes.
  (Without it, `dd` uses 512-byte blocks.)
- `skip=<Area offset>`: skip that many bytes before reading.
- `count=<Area length>`: read exactly that many bytes.
- `2>/dev/null`: hide `dd`'s summary of bytes copied, which it writes
  to stderr.
- `| xxd`: show the bytes as a hex and ASCII dump.

Reading one byte at a time is slow but simple; for a 258,048-byte area
on an image file it took about a third of a second. Area offsets and
lengths are multiples of 4096 bytes, so the same bytes can be read in
512-byte blocks by dividing both numbers by 512, for example
`bs=512 skip=64 count=504` for an area at 32768 of length 258048.

`scripts/inspect-keyslot` computes the range and runs the extraction
for you; see its `--help`. It currently requires root, even for an
image file.

## What healthy key material looks like

A keyslot's area holds the keyslot's AF-split copy of the master key,
encrypted with the area cipher (see
[`af-splitting-explained.md#what-is-written-to-disk`](af-splitting-explained.md#what-is-written-to-disk)).
Ciphertext looks like uniformly random bytes, with no structure and no
repeating pattern. The part of the area after the key material is
random too: cryptsetup fills the whole keyslots area with random data
when it formats the device (see
[`luks2-header-anatomy.md#reading-area-offset--area-length`](luks2-header-anatomy.md#reading-area-offset--area-length)).

The first 128 bytes of a keyslot area on a freshly formatted test
image:

```
00000000: 1e27 2e29 cc80 7b78 8358 6545 b79c 63a2  .'.)..{x.XeE..c.
00000010: 4162 802f d3b8 0465 50a2 fd7e 96ba 7823  Ab./...eP..~..x#
00000020: 2325 17ef d357 6d8d e841 ad46 d79c 90de  #%...Wm..A.F....
00000030: 5a67 cd7e 277a a4ce 43a0 c6f6 5521 481c  Zg.~'z..C...U!H.
00000040: a1dc 105a ea1e bf88 8fd0 78a0 8551 6c04  ...Z......x..Ql.
00000050: 7c5d 08e8 b002 e191 2261 eb63 fb4d c86a  |]......"a.c.M.j
00000060: be79 8b04 6753 b2db 81c4 74ee da83 5254  .y..gS....t...RT
00000070: 628a 9e94 9317 f5db 410d a2ec 520e 037e  b.......A...R..~
```

What to look for:

- No byte value dominates; no long runs of `00`, `ff` or any other
  single byte.
- No multi-byte pattern repeating at a fixed interval.
- The ASCII column shows scattered printable characters by chance, but
  never readable text.

These are the patterns `scripts/inspect-keyslot`'s two checks are
built around; see its `--help` for what it flags and at which
thresholds.

## What corrupted key material looks like

cryptsetup's man page says keyslot damage "can happen due to storage
media failure or overwriting the keyslot area with other data"
([`cryptsetup-repair(8)`](https://gitlab.com/cryptsetup/cryptsetup/-/blob/bae21790d59897ac50e5471f953f76b3a58aeeb6/man/cryptsetup-repair.8.adoc)).
Overwriting leaves a visible trace when what was written is not random.
The two dumps below come from the experiment, which damaged 4096 bytes
of a keyslot area starting 8192 bytes in; each shows the 32 bytes
before the damage and the first 64 damaged bytes.

**A zeroed block:**

```
00000000: 0e6a 5fac 387e bcfd 19e7 b0a5 57a4 80c5  .j_.8~......W...
00000010: 5be2 aed3 e945 f7fe 71fa 4775 0b63 342f  [....E..q.Gu.c4/
00000020: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000030: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000040: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000050: 0000 0000 0000 0000 0000 0000 0000 0000  ................
```

**A repeated fill pattern** (here `de ad be ef`):

```
00000000: 0e6a 5fac 387e bcfd 19e7 b0a5 57a4 80c5  .j_.8~......W...
00000010: 5be2 aed3 e945 f7fe 71fa 4775 0b63 342f  [....E..q.Gu.c4/
00000020: dead beef dead beef dead beef dead beef  ................
00000030: dead beef dead beef dead beef dead beef  ................
00000040: dead beef dead beef dead beef dead beef  ................
00000050: dead beef dead beef dead beef dead beef  ................
```

Random bytes do produce short runs and repeats by chance, more often
the larger the area, so a short run on its own proves nothing; what
matters is a run or pattern too long to be chance.
`scripts/inspect-keyslot`'s thresholds are rough; for a statistical
treatment, see [`entropy-analysis.md`](entropy-analysis.md).

cryptsetup also checks for this kind of damage itself: `cryptsetup
repair` looks for low-entropy regions in keyslot areas and prints a
warning with the suspect offsets. For both dumps above it printed:

```
Keyslot 0 binary data could be corrupted.
  Suspected offset: 0xa000
  Suspected offset: 0xa080
  Suspected offset: 0xa100
  Subsequent suspected offsets are suppressed.
You can use hexdump -v -C -n 128 -s <offset_0xXXXX> "<tmpdir>/c1.img" to inspect the data.
```

`0xa000` is the area's offset (32768) plus 8192. The check "prints only
warnings. It does not modify keyslots", it can give false positives,
and it detects "usually only a low-entropy area (like zeroed blocks)"
([`cryptsetup-repair(8)`](https://gitlab.com/cryptsetup/cryptsetup/-/blob/bae21790d59897ac50e5471f953f76b3a58aeeb6/man/cryptsetup-repair.8.adoc)).
In the experiment, `repair` still exited with status 0.

## What no inspection can detect

Damage that replaces ciphertext with other random-looking bytes leaves
no trace. A single changed byte, or a block overwritten with random
data or with other ciphertext, still looks like ciphertext: neither a
hex dump, `scripts/inspect-keyslot`, a statistical test nor `cryptsetup
repair` can tell it from intact data. In the experiment, one changed
byte in the area produced no warning from `repair`, while
`open --test-passphrase` failed. How much of the key such damage
destroys is worked out in
[`af-splitting-explained.md#what-damage-does-to-the-key`](af-splitting-explained.md#what-damage-does-to-the-key):
at least 128 bits, far too many to search.

What LUKS2 checks, region by region:

- **The binary header and JSON metadata** carry a checksum over each
  copy (see
  [`luks2-header-anatomy.md#the-binary-header-byte-by-byte`](luks2-header-anatomy.md#the-binary-header-byte-by-byte)),
  and there are two copies, so accidental damage to one is detected
  and repaired from the other. The checksum does not protect against
  deliberate changes.
- **The keyslot areas** have no checksum of their own. The only check
  is the master-key digest, which runs after a keyslot has been
  decrypted and merged
  ([`af-splitting-explained.md#how-a-wrong-key-is-detected`](af-splitting-explained.md#how-a-wrong-key-is-detected)).
  It tells you the result is not the right key, but not whether the
  passphrase was wrong or the keyslot is damaged: cryptsetup prints
  "No key available with this passphrase." in both cases.
- **The data segment** is not checked by default. `luksFormat
  --integrity` adds a per-sector authentication tag through an
  underlying dm-integrity device, so damaged or altered data sectors
  are detected when read. cryptsetup marks this "*EXPERIMENTAL*", it
  costs space and speed, and it has to be chosen when the volume is
  created (`--integrity` in
  [`man/common_options.adoc`](https://gitlab.com/cryptsetup/cryptsetup/-/blob/bae21790d59897ac50e5471f953f76b3a58aeeb6/man/common_options.adoc),
  lines 362–368, and "Authenticated disk encryption (EXPERIMENTAL)" in
  [`man/cryptsetup.8.adoc`](https://gitlab.com/cryptsetup/cryptsetup/-/blob/bae21790d59897ac50e5471f953f76b3a58aeeb6/man/cryptsetup.8.adoc),
  lines 566–573).

So if a keyslot that used to work stops accepting a passphrase you are
sure of and nothing looks wrong, inspection cannot settle whether the
keyslot is damaged. Another keyslot, or a header backup taken before
the problem, is the way back in.

## Diffing primary vs. secondary headers

With the default layout, the binary headers are at 0 and 16384 and
the JSON areas at 4096 and 20480, each 12288 bytes. If the primary
header's `hdr_size` (see
[`luks2-header-anatomy.md`](luks2-header-anatomy.md#the-binary-header-byte-by-byte))
is not 16384, use that value as the secondary's offset and
`hdr_size` − 4096 as the JSON size.

```
sudo dd if=/dev/sdX bs=1 skip=0     count=4096 2>/dev/null | xxd > primary-header.hex
sudo dd if=/dev/sdX bs=1 skip=16384 count=4096 2>/dev/null | xxd > secondary-header.hex
diff primary-header.hex secondary-header.hex
```

The binary headers always differ, in exactly four fields: `magic`,
`salt`, `hdr_offset` and `csum` (see
[`luks2-header-anatomy.md#primary-vs-secondary-header-legitimate-differences`](luks2-header-anatomy.md#primary-vs-secondary-header-legitimate-differences)).
Any other difference is worth a closer look.

The JSON areas should be identical:

```
sudo dd if=/dev/sdX bs=1 skip=4096  count=12288 2>/dev/null > primary.json
sudo dd if=/dev/sdX bs=1 skip=20480 count=12288 2>/dev/null > secondary.json
cmp primary.json secondary.json
```

Two things to keep in mind:

- **Running cryptsetup can change what you are comparing.** When one
  copy is damaged, `luksDump`, `open` and `repair` each rewrite it from
  the other valid copy, without printing anything (shown in the
  experiment, and by
  [`experiments/header-anatomy/`](../experiments/header-anatomy)). So
  `luksDump` succeeding does not mean both copies were valid, and if
  you want to see the damage itself, extract both copies before running
  any cryptsetup command on the device, or work on an image.
- **If both copies are damaged**, every command fails with "Device
  /dev/sdX is not a valid LUKS device." The fix is to restore a header
  backup.

## When to run `cryptsetup repair`, and what it can't fix

```
sudo cryptsetup repair /dev/sdX
```

`repair` "Tries to repair the device metadata if possible", for "some
known benign LUKS metadata header corruptions. Only basic corruptions
of unused keyslot are fixable. This command will only change the LUKS
header, not any keyslot data." It also upgrades or recovers LUKS2
re-encryption metadata, which needs a passphrase
([`cryptsetup-repair(8)`](https://gitlab.com/cryptsetup/cryptsetup/-/blob/bae21790d59897ac50e5471f953f76b3a58aeeb6/man/cryptsetup-repair.8.adoc)).
The man page recommends taking a header backup first.

What it printed in the experiment:

| Situation | Output | Exit status |
|---|---|---|
| Intact device | nothing | 0 |
| Primary header damaged | nothing (it rewrote the primary header) | 0 |
| Keyslot area zeroed or pattern-filled | the "binary data could be corrupted" warning above | 0 |
| One byte of a keyslot area changed | nothing | 0 |
| Both header copies damaged | `Device ... is not a valid LUKS device.` | 1 |

So exit status 0 does not mean the keyslots are intact; read any
warnings it prints.

**What it does not fix:**

- **Damaged keyslot data.** `repair` does not change keyslot data, and
  a damaged keyslot cannot be rebuilt from what is left of it (see
  [What no inspection can detect](#what-no-inspection-can-detect)). The
  man page: "if the keyslot is corrupted, no recovery is possible. You
  have to use the LUKS header backup." Another working keyslot also
  still opens the volume.
- **A wrong passphrase.** A wrong passphrase leaves the header and
  keyslots intact, so `repair` has nothing to find. If the header and
  keyslots check out and the volume still won't open, the passphrase is
  the leading suspect; see [`passphrase-recovery.md`](passphrase-recovery.md).

## Decision guide

Work through these in order, after taking a header backup (or working
on an image of the device).

1. **Does `cryptsetup luksDump /dev/sdX` work?**
   - No, it says the device "is not a valid LUKS device": first make
     sure it is the right device ([above](#confirm-you-have-the-right-device)).
     If it is, both header copies are damaged, and `repair` cannot fix
     that. Restore a header backup taken before the damage:
     ```
     sudo cryptsetup luksHeaderRestore /dev/sdX --header-backup-file ./header-backup.img
     ```
     "All keyslots will be replaced; only the passphrases from the
     backup will work afterward"
     ([`cryptsetup-luksHeaderRestore(8)`](https://gitlab.com/cryptsetup/cryptsetup/-/blob/bae21790d59897ac50e5471f953f76b3a58aeeb6/man/cryptsetup-luksHeaderRestore.8.adoc)),
     so use a backup you know belongs to this device. Without a backup,
     the volume cannot be opened.
   - Yes: go to step 2. (If one header copy was damaged, cryptsetup has
     already rewritten it from the other.)

2. **Does `cryptsetup repair` warn that a keyslot's binary data could
   be corrupted, or does a dump of the keyslot's area show long runs of
   one byte or a repeating pattern?**
   - Yes: that keyslot is probably damaged and cannot be repaired. Use
     another keyslot whose passphrase you know, or restore a header
     backup taken before the damage.
   - No: go to step 3.

3. **The header and keyslots look fine, but the volume won't open with
   your passphrase.** The most likely cause is the passphrase: a typo,
   a missing character, a different special character. See
   [`passphrase-recovery.md`](passphrase-recovery.md) for a bounded,
   safe search. Damage that inspection cannot see (see
   [What no inspection can detect](#what-no-inspection-can-detect))
   produces the same symptom, so if the search finds nothing, another
   keyslot or a header backup is the remaining option.
