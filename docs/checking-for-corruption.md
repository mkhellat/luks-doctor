# Checking a LUKS2 Volume for Corruption

This is a practical, step-by-step guide to inspecting a LUKS2 device
directly — extracting raw bytes with `dd`, reading them with `xxd`, and
telling the difference between "this looks fine" and "this is actually
damaged." It assumes you've read (or will read)
[`luks2-header-anatomy.md`](luks2-header-anatomy.md) for the underlying
concepts; this doc is the "how do I actually look" companion.

**Before anything else, back up the header:**

```
sudo cryptsetup luksHeaderBackup /dev/sdX --header-backup-file ./header-backup.img
```

This is cheap (the header region is small, typically a few MiB), fast,
and means nothing you do below — even a mistake — can make things worse
than they already are. Do this before any exploratory `repair` or
inspection work on a device you care about.

## Contents

- [Confirm you have the right device](#confirm-you-have-the-right-device)
- [Extracting a keyslot's raw bytes with `dd`](#extracting-a-keyslots-raw-bytes-with-dd)
- [What healthy key material looks like](#what-healthy-key-material-looks-like)
- [What corrupted key material looks like](#what-corrupted-key-material-looks-like)
- [Diffing primary vs. secondary headers](#diffing-primary-vs-secondary-headers)
- [When to run `cryptsetup repair`, and what it can't fix](#when-to-run-cryptsetup-repair-and-what-it-cant-fix)
- [Decision guide](#decision-guide)

## Confirm you have the right device

Before touching anything, confirm `/dev/sdX` is actually the LUKS device you
think it is — everything below reads and interprets raw bytes at absolute
offsets, and running it against the wrong device (a stale path after a USB
re-enumeration, a similarly-named device, a partition vs. the whole disk)
produces confusing garbage that looks exactly like corruption but isn't:

```
sudo blkid /dev/sdX
```

Expect `TYPE="crypto_LUKS"` in the output. If `blkid` shows a different type,
shows nothing, or the device node doesn't match what you expect from
`lsblk`/`dmesg` (e.g. after replugging a USB enclosure, which can reassign
`/dev/sdX` letters), stop and re-identify the device before proceeding — do
not extrapolate corruption findings from the wrong device.

## Extracting a keyslot's raw bytes with `dd`

First, get the keyslot's byte range from `luksDump`:

```
sudo cryptsetup luksDump /dev/sdX
```

Find the keyslot you care about and note its `Area offset` and
`Area length` (both in bytes) — see
[`luks2-header-anatomy.md#reading-area-offset--area-length`](luks2-header-anatomy.md#reading-area-offset--area-length)
for what these mean.

**Checking more than one keyslot**: a volume can have several independent
keyslots, and their numbers are not guaranteed to be contiguous starting at
`0` — a keyslot can be removed (`luksKillSlot`) without renumbering the
ones that remain, so a two-keyslot volume might show slots `0` and `2`,
not `0` and `1`. List every keyslot number actually present before deciding
which ones to inspect:

```
sudo cryptsetup luksDump /dev/sdX | grep -E '^  [0-9]+: '
```

Each listed slot has its own independent `Area offset`/`Area length` —
repeat the extraction below for each one you need to check. This matters
because damage is typically local to whichever slot was being written when
something went wrong; an intact slot elsewhere on the same device is a
legitimate way back in if the one you were using is damaged (see the
decision guide below).

Then extract exactly that byte range:

```
sudo dd if=/dev/sdX bs=1 skip=<Area offset> count=<Area length> 2>/dev/null | xxd
```

What each part does:

- `if=/dev/sdX` — input file: the raw device (or a disk image file —
  this works identically on an `.img` file, which is often safer for
  repeated experimentation).
- `bs=1` — block size of 1 byte. This is what makes `skip=`/`count=`
  operate in exact bytes rather than in whatever the default block size
  is (512 bytes, historically). It's slower than a larger block size,
  but for a region this small (a few hundred KB at most) the difference
  is imperceptible, and byte-exact addressing is worth the tradeoff —
  you do not want off-by-block-size errors when the whole point is
  precise inspection.
- `skip=<Area offset>` — skip this many blocks (= bytes, since `bs=1`)
  from the start of the input before reading anything. This seeks to
  the start of the keyslot area.
- `count=<Area length>` — read exactly this many blocks (= bytes) and
  stop. This reads exactly the keyslot area and nothing beyond it.
- `2>/dev/null` — suppress `dd`'s normal "N bytes copied" status message
  on stderr, so it doesn't interleave with or follow the piped output.
- `| xxd` — pipe the raw bytes into `xxd`, which renders them as a
  readable hex+ASCII dump instead of dumping raw binary to your
  terminal.

`scripts/inspect-keyslot.sh` does this computation and extraction for
you automatically, including handling the case of multiple keyslots —
see its `--help` output.

## What healthy key material looks like

A keyslot's `area` holds AF-striped, encrypted key material (see
[AF-splitting](luks2-header-anatomy.md#af-splitting-anti-forensic-splitting),
or [`af-splitting-explained.md`](af-splitting-explained.md) for a
byte-by-byte worked example of why this makes partial damage
unrecoverable).
Correctly written, this data is **cryptographically indistinguishable
from uniform random noise** — there is no structure, no repeating
pattern, no predictable byte at any position. That's expected and
correct, not a red flag.

A healthy dump looks like this (synthetic example, not a real keyslot):

```
00000000: 390c 8c7d 7247 342c d810 0f2f 6f77 0d65  9..}rG4,.../ow.e
00000010: d670 e58e 0351 d8ae 8e4f 6eac 342f c231  .p...Q...On.4/.1
00000020: b7b0 8716 eb3f c128 96b9 6223 1774 9428  .....?.(..b#.t.(
00000030: 7733 c28e e8ba 53bd b56b 8824 577d 53ec  w3....S..k.$W}S.
00000040: c28a 70a6 1c75 10a1 cd89 216c a16c ffca  ..p..u....!l.l..
00000050: ea49 8747 7e86 dbcc b970 46fc 2e18 384e  .I.G~....pF...8N
00000060: 51d8 20c5 c3ef 8005 3a88 ae39 96de 50e8  Q. .....:..9..P.
00000070: 0186 5b36 9865 4ebf 5200 a5fa 0939 b99d  ..[6.eN.R....9..
```

What makes this "look healthy" to the eye:

- No byte value dominates — you don't see long runs of `00`, `ff`, or
  any other single byte.
- No repeating multi-byte pattern (e.g. the same 4 or 8 bytes recurring
  every N bytes) — that would suggest something got overwritten with a
  fill pattern or a cyclic buffer artifact rather than real ciphertext.
- The ASCII column on the right is uniformly full of `.` (non-printable)
  with only sporadic, coincidental printable characters — real
  ciphertext will never spell out meaningful text, but occasional
  single printable bytes purely by chance are normal and expected in
  high-entropy data.

This is the pattern `scripts/inspect-keyslot.sh`'s heuristic check is
built around — see that script's `--help` for exactly what it flags.

## What corrupted key material looks like

By contrast, here's what actual damage tends to look like (again,
synthetic — generated to illustrate failure patterns, not a real dump).

**Truncation / zero-fill from an interrupted write** (e.g. a USB
enclosure disconnecting mid-write, a failed sector remap, or a
partial `dd` that didn't complete):

```
00000000: 390c 8c7d 7247 342c d810 0f2f 6f77 0d65  9..}rG4,.../ow.e
00000010: d670 e58e 0351 d8ae 8e4f 6eac 342f c231  .p...Q...On.4/.1
00000020: b7b0 8716 eb3f c128 96b9 6223 1774 9428  .....?.(..b#.t.(
00000030: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000040: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000050: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000060: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000070: 0000 0000 0000 0000 0000 0000 0000 0000  ................
```

The first 48 bytes look normal (high entropy), then it drops into a
long, unbroken run of `00` and never recovers. This is the signature of
a write that started correctly and then stopped — the drive (or
enclosure, or cable) dropped out partway through, and everything after
that point is unwritten/zeroed rather than real ciphertext.

**Repeating pattern from a fill/wipe tool or overwritten region**:

```
00000000: 390c 8c7d 7247 342c d810 0f2f 6f77 0d65  9..}rG4,.../ow.e
00000010: deadbeef deadbeef deadbeef deadbeef       ................
00000020: deadbeef deadbeef deadbeef deadbeef       ................
00000030: deadbeef deadbeef deadbeef deadbeef       ................
```

A short, exactly-repeating multi-byte pattern like this is not
something real ciphertext produces — it's the signature of a fill
pattern, whether from a diagnostic tool, a buggy driver zero/pattern-
filling unread sectors, or (rarely) deliberate overwriting.

**Important caveat**: a *single* short run of zeros, or one coincidental
repeated byte pair, is not automatically damning — real random data
does occasionally produce short coincidental runs by chance, especially
in a large keyslot area (hundreds of KB). What matters is runs and
patterns that are implausibly long to occur by chance, or that persist
across a large fraction of the area. This is why the heuristic in
`scripts/inspect-keyslot.sh` is explicitly a rough visual aid with a
threshold, not a rigorous statistical entropy test — for anything
approaching a real forensic determination, use a proper entropy/chi-
squared analysis tool, not this project.

## Diffing primary vs. secondary headers

Extract both headers the same way:

```
sudo dd if=/dev/sdX bs=1 skip=0     count=4096 2>/dev/null | xxd > primary-header.hex
sudo dd if=/dev/sdX bs=1 skip=16384 count=4096 2>/dev/null | xxd > secondary-header.hex
diff primary-header.hex secondary-header.hex
```

You will get a large diff — **this is expected**, not a symptom. As
covered in
[`luks2-header-anatomy.md#primary-vs-secondary-header-legitimate-differences`](luks2-header-anatomy.md#primary-vs-secondary-header-legitimate-differences),
the two headers legitimately differ in their magic bytes (`LUKS` vs.
`SKUL`, byte-reversed), their independent checksums, their independent
random salts, and the secondary header's self-referential offset field.

What you're actually checking for here is not "are these identical"
(they never are) but:

1. **Does `cryptsetup luksDump` succeed and show consistent JSON content
   from both?** Run `cryptsetup luksDump` normally — it reads and
   validates the primary header by default, falling back to the
   secondary automatically if the primary fails checksum validation.
   If it succeeds without warning, both headers are at least internally
   valid.
2. **Does the JSON payload (keyslots, digests, segments) match in
   substance between primary and secondary?** The binary header framing
   differs by design; the *meaning* of the metadata should not. A
   difference here — a different number of keyslots, a different
   segment offset, a keyslot present in one but not the other — is a
   genuine red flag suggesting the two copies have drifted (e.g. from a
   crash during a metadata-modifying operation like `luksAddKey`).

## When to run `cryptsetup repair`, and what it can't fix

```
sudo cryptsetup repair /dev/sdX
```

**What success looks like** — `repair` found nothing wrong, or fixed
something and reports it, then exits quietly with status 0:

```
$ sudo cryptsetup repair /dev/sdX
$ echo $?
0
```

Don't be alarmed by the lack of output on a clean header — silence means
"nothing to do," not "didn't run." If it actually resyncs a header copy,
it prints a line saying so before exiting 0.

**What failure looks like** — a non-zero exit and an explicit error
naming what it couldn't reconcile, e.g.:

```
$ sudo cryptsetup repair /dev/sdX
Device size is not aligned to requested sector size alignment (4096 bytes).
$ echo $?
1
```

or a message that both header copies are damaged beyond repair. If you get
an error here instead of quiet success, `repair` did not fix your header —
proceed to a header restore from backup (see the decision guide below), or
treat the structural damage as unrecovered.

**What it fixes**: structural damage to the JSON metadata area — e.g.
a JSON document that fails to parse, a checksum mismatch on one header
copy that can be repaired by resyncing from the other valid copy, or
certain known-inconsistent leftover states from an interrupted
`cryptsetup` operation (like a crashed re-encryption). It only touches
metadata structure — think of it as filesystem-check-for-the-header,
not a general data-recovery tool.

**What it does NOT fix**:

- **Corrupted keyslot key material.** If the AF-striped bytes in a
  keyslot's `area` are themselves damaged (zeroed, truncated,
  overwritten), `repair` cannot regenerate them — that data, if not
  recoverable from a header backup or the volume's other keyslots, is
  gone. This is the anti-forensic property working as intended (see
  [AF-splitting](luks2-header-anatomy.md#af-splitting-anti-forensic-splitting)) —
  it does not distinguish "attacker trying to partially erase a slot"
  from "innocent bit rot," so it protects against both equally
  effectively, for better and worse.
- **A wrong passphrase.** `repair` operates purely on structure — it has
  no way to know or guess your passphrase, and a passphrase being wrong
  produces a header/keyslot region that is completely well-formed from
  `repair`'s point of view. If your header inspects as clean and
  `repair` finds nothing to do, and the volume still won't unlock, the
  passphrase itself is the leading suspect. That's the scenario
  [`passphrase-recovery.md`](passphrase-recovery.md) covers.

## Decision guide

Work through these in order:

1. **Does `cryptsetup luksDump /dev/sdX` succeed cleanly?**
   - No, checksum/JSON error → try `sudo cryptsetup repair /dev/sdX`,
     then re-run `luksDump`. If it now succeeds, proceed to step 2. If
     it still fails and you have a `luksHeaderBackup` file taken before
     the damage occurred, restore it:
     ```
     sudo cryptsetup luksHeaderRestore /dev/sdX --header-backup-file ./header-backup.img
     ```
     This overwrites the device's current header region with the
     backup's — only run it against a backup you're confident predates
     the damage, since it discards whatever header state is currently
     on disk (including any keyslots added or changed since that
     backup was taken). Re-run `luksDump` afterward to confirm. Without
     a pre-damage backup, structural damage that `repair` can't fix is
     very likely unrecoverable.
   - Yes → proceed to step 2.

2. **Does the target keyslot's `area` show visible corruption when
   dumped with `dd`+`xxd`** (long zero-runs, repeating patterns,
   obvious truncation, per the examples above)?
   - Yes → the keyslot's key material is likely damaged. Check whether
     another keyslot on the same device is intact (a volume can have
     multiple independent keyslots), or whether you have a
     `luksHeaderBackup` file predating the damage. Without one of
     those, this keyslot is very likely unrecoverable — that's the
     nature of AF-splitting.
   - No, it looks like uniform high-entropy noise → proceed to step 3.

3. **Header structurally sound, keyslot data looks clean, but the
   volume still won't unlock with the passphrase you're using?**
   - This strongly suggests the passphrase itself is wrong — a typo, a
     dropped character, a wrong special-character variant — not disk
     damage. See [`passphrase-recovery.md`](passphrase-recovery.md) for
     a bounded, safe search technique for exactly this situation.
