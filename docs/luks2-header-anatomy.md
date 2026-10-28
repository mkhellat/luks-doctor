# LUKS2 Header and Keyslot Anatomy

This document explains how a LUKS2-encrypted volume is laid out on
disk, what each part is for, and how to read it with
`cryptsetup luksDump` and raw tools like `dd` and `xxd`. It assumes no
prior knowledge of LUKS internals. Layout claims are checked against a
real header by [`experiments/header-anatomy/`](../experiments/header-anatomy).

Sources used throughout: the LUKS2 On-Disk Format Specification
v1.1.4 ([PDF at commit `a81aa2fe`](https://gitlab.com/cryptsetup/LUKS2-docs/-/blob/a81aa2fef8d176debdbec297c1e0b74bb50cfee8/luks2_doc_wip.pdf),
cited as "spec"), and cryptsetup at commit
[`bae21790`](https://gitlab.com/cryptsetup/cryptsetup/-/tree/bae21790d59897ac50e5471f953f76b3a58aeeb6).

## Contents

- [What LUKS2 is, and why header/keyslot separation exists](#what-luks2-is-and-why-headerkeyslot-separation-exists)
- [On-disk layout](#on-disk-layout)
  - [The binary header, byte-by-byte](#the-binary-header-byte-by-byte)
- [The JSON metadata area](#the-json-metadata-area)
- [Reading Area offset / Area length](#reading-area-offset--area-length)
- [Argon2id](#argon2id)
- [AF-splitting (anti-forensic splitting)](#af-splitting-anti-forensic-splitting)
- [Primary vs. secondary header: legitimate differences](#primary-vs-secondary-header-legitimate-differences)
- [Command reference](#command-reference)

## What LUKS2 is, and why header/keyslot separation exists

LUKS (Linux Unified Key Setup) is the standard on-disk format for
block-device encryption on Linux. LUKS2 is the current version,
succeeding LUKS1. `cryptsetup` is the userspace tool that creates,
inspects and manages LUKS volumes on top of the kernel's `dm-crypt`.

The central design idea in LUKS is the separation between:

- **The master key**: a random key, 32 or 64 bytes with cryptsetup's
  defaults, that encrypts and decrypts the volume's data. `luksFormat`
  generates it once; it is never derived from a passphrase. See
  [`master-key-lifecycle.md`](master-key-lifecycle.md).
- **Keyslots**: separate copies of that same master key, each
  encrypted under a key derived from a different passphrase. A
  passphrase can also be produced by another unlock mechanism, such as
  a FIDO2 key, a PKCS#11 token or a TPM2 chip enrolled with
  [`systemd-cryptenroll`](https://www.freedesktop.org/software/systemd/man/latest/systemd-cryptenroll.html).

This indirection makes several everyday operations cheap:

- **Multiple passphrases** can unlock the same volume, each through its
  own keyslot, without re-encrypting the data.
- **Changing a passphrase** re-encrypts one keyslot's copy of the
  master key under the new passphrase; the data is not touched.
- **Removing a passphrase** deletes one keyslot. cryptsetup overwrites
  the keyslot's area when it does so (with the 39-pass Gutmann pattern
  on rotational disks and one pass of random data on other devices:
  `LUKS2_keyslot_wipe()` in `lib/luks2/luks2_keyslot.c`, lines 704–711,
  and `lib/utils_wipe.c`, lines 228–231). On SSDs and other flash
  storage the old copy can survive anyway; see
  [`af-splitting-explained.md`](af-splitting-explained.md#the-problem-af-splitting-solves-restated-concretely).
  Anyone who kept a header backup, or an image of the device, can still
  use the removed passphrase with that copy.

The **header** is the region at the start of the device that holds
everything needed to interpret the rest: the cipher, where the
keyslots are, where the encrypted data starts, and the metadata
describing all of that. The header is not secret, but it is essential:
if it is lost or damaged beyond repair, and no backup exists, the data
cannot be decrypted, whatever passphrase you have.

## On-disk layout

A LUKS2 header has three areas (spec §2, p.3): a binary header, a JSON
metadata area, and a keyslots area. The binary header and JSON area
are stored twice (primary and secondary); "There is no redundancy in
the binary keyslots area."

With cryptsetup 2.8.8's defaults, the layout is
([`experiments/header-anatomy/`](../experiments/header-anatomy)):

```
Offset (hex)  Offset (dec)  Size          Region
------------  ------------  ------------  ----------------------------------
0x00000000    0             4096 B        Primary binary header
                                           (magic "LUKS\xba\xbe")
0x00001000    4096          12288 B       Primary JSON area
------------  ------------  ------------  ----------------------------------
0x00004000    16384         4096 B        Secondary binary header
                                           (magic "SKUL\xba\xbe")
0x00005000    20480         12288 B       Secondary JSON area
------------  ------------  ------------  ----------------------------------
0x00008000    32768         16744448 B    Keyslots area
                                           (config.keyslots_size); each
                                           keyslot's area is a range in it
                                           given by its JSON "area" object
------------  ------------  ------------  ----------------------------------
0x01000000    16777216      rest of       Data segment
              (16 MiB)      device        (segments.0.offset)
------------  ------------  ------------  ----------------------------------
```

These offsets are defaults, not constants. The data segment starts
wherever `segments.0.offset` says; `luksDump` shows it as the data
segment's `offset`, and `--luks2-metadata-size` and
`--luks2-keyslots-size` change the metadata and keyslots area sizes at
format time.

The secondary header starts immediately after the primary JSON area,
so its offset depends on the JSON area size. The specification allows
only these combinations (spec §2.1, Table 1, p.4):

| Secondary header offset (bytes) | JSON area size |
|---|---|
| `0x004000` (16384)   | 12 KiB |
| `0x008000` (32768)   | 28 KiB |
| `0x010000` (65536)   | 60 KiB |
| `0x020000` (131072)  | 124 KiB |
| `0x040000` (262144)  | 252 KiB |
| `0x080000` (524288)  | 508 KiB |
| `0x100000` (1048576) | 1020 KiB |
| `0x200000` (2097152) | 2044 KiB |
| `0x400000` (4194304) | 4092 KiB |

Read the real secondary offset from the primary header's `hdr_size`
field rather than assuming `0x4000`. If the primary header is
unreadable, cryptsetup itself tries each of these offsets in turn to
find the secondary (`LUKS2_disk_hdr_read()`,
`lib/luks2/luks2_disk_metadata.c`, lines 682–693).

### The binary header, byte-by-byte

The binary header is `struct luks2_hdr_disk` (spec §2.1, Figure 2,
p.5): a packed C struct of exactly 4096 bytes in which "All integer
values are stored in the big-endian format" and all strings are
NUL-terminated. It is "intended for a quick scanning by blkid" (spec
§2.1, p.4).

```
Offset (hex/dec)   Field         Size (B)  Purpose
-----------------  ------------  --------  ----------------------------------
0x0000    (0)      magic                6  "LUKS\xba\xbe" (primary) or
                                            "SKUL\xba\xbe" (secondary)
0x0006    (6)      version              2  2 for LUKS2
0x0008    (8)      hdr_size             8  Header size including the JSON
                                            area, in bytes
0x0010    (16)     seqid                8  Increased on every header update
0x0018    (24)     label               48  Optional label, or empty
0x0048    (72)     csum_alg            32  Checksum algorithm, e.g. "sha256"
0x0068    (104)    salt                64  Random, different in every header
0x00a8    (168)    uuid                40  Device UUID, same format as LUKS1
0x00d0    (208)    subsystem           48  Optional secondary label
0x0100    (256)    hdr_offset           8  This header's own offset on the
                                            device, in bytes
0x0108    (264)    _padding           184  Must be zero
0x01c0    (448)    csum                64  Checksum of binary header + JSON
                                            area, computed with csum zeroed
0x0200    (512)    _padding4096      3584  Must be zero
-----------------  ------------  --------  ----------------------------------
                   TOTAL             4096
```

Only the first 512 bytes are used; the struct is 4096 bytes so that
"the binary header is always written to only one sector (atomic
write)" (spec §2, p.3). The fields that matter most for diagnosis:

- **`hdr_size`**: where the JSON area ends and, therefore, where the
  secondary header must start. The JSON area is `hdr_size` − 4096 bytes
  (spec §2.2, p.5).
- **`seqid`**: increased on every update. "The header with a higher
  seqid is more recent and is used for recovery" (spec §2.1, p.4).
  `luksDump` prints it as `Epoch`.
- **`hdr_offset`**: the header's own position on the device. Both
  headers have it (0 for the primary). If it does not match where the
  header was read from, "the header is misplaced and must not be used.
  It is a prevention to partition resize or manipulation with the
  device start offset" (spec §2.1, p.5). cryptsetup rejects such a
  header (`hdr_disk_sanity_check_pre()`, lines 178–220, the check at
  line 193).
- **`csum`**: cryptsetup hashes the 4096-byte binary header with `csum`
  zeroed, followed by the JSON area, using `csum_alg` (SHA-256 by
  default), and compares the result with the stored value using
  `memcmp()` (`hdr_checksum_calculate()` and `hdr_checksum_check()`,
  [`lib/luks2/luks2_disk_metadata.c`](https://gitlab.com/cryptsetup/cryptsetup/-/blob/bae21790d59897ac50e5471f953f76b3a58aeeb6/lib/luks2/luks2_disk_metadata.c),
  lines 61–83 and 88–114). The checksum detects accidental damage
  only. The specification says "Metadata checksum and redundancy can
  prevent random metadata corruption only. It does not cover
  intentional modification" (spec §1.2, p.3): anyone who can write to
  the device can change the metadata and recompute the checksum. It is
  separate from the master-key digest (see
  [`af-splitting-explained.md`](af-splitting-explained.md#how-a-wrong-key-is-detected)),
  which checks a candidate key, not the header.

When cryptsetup reads the header (`LUKS2_disk_hdr_read()`, lines
640–807), it reads and validates each copy separately, and a copy with
a bad checksum or invalid JSON is not used. If both copies are valid
but their `seqid` differs, the one with the higher `seqid` wins (lines
698–703). If only one copy is valid and the command allows recovery,
cryptsetup rewrites the bad copy from the good one with a new salt
(lines 722–768); if the device also carries other signatures that make
it ambiguous, it refuses and asks you to run `cryptsetup repair`. In
the experiment, with the primary JSON area damaged, `luksDump` and
`cryptsetup repair` each rewrote the primary header from the secondary,
with a new salt, and neither printed anything about it; see
[`checking-for-corruption.md`](checking-for-corruption.md#when-to-run-cryptsetup-repair-and-what-it-cant-fix).

**Keyslot areas have no fixed offsets.** In LUKS1, the header has a
fixed array of 8 keyslots (`LUKS_NUMKEYS`; LUKS1 spec v1.2.3, p.12).
In LUKS2, each keyslot's location and size are given by its own
`area` object in the JSON metadata (see
[Reading Area offset / Area length](#reading-area-offset--area-length)),
and keyslot areas are "allocated on-demand" (spec §2, p.3).

## The JSON metadata area

After each binary header comes a JSON document describing the volume,
stored as a NUL-terminated string with the rest of the area zeroed
(spec §2.2, p.5). To see it in readable form:

```
sudo cryptsetup luksDump /dev/sdX
```

or as raw JSON:

```
sudo cryptsetup luksDump --dump-json-metadata /dev/sdX
```

(Neither needs root on an image file you own.) The top-level objects
(spec §3, pp.6–13):

- **`config`**: `json_size` and `keyslots_size` (which must match the
  binary header and be 4096-byte aligned, respectively), and optional
  `flags` and `requirements` (spec §3.5, p.12).
- **`keyslots`**: one entry per keyslot, keyed by number (`"0"`,
  `"1"`, …). Each has:
  - `type`: `"luks2"` for an ordinary keyslot; `"reencrypt"` is an
    optional type used during re-encryption (spec §3.2.2, p.9).
  - `key_size`: the size in bytes of the key stored in the keyslot,
    the master key.
  - `af`: the anti-forensic splitter: `type` (`"luks1"`, the only type
    used), `stripes` (only 4000 is supported) and `hash` (the hash
    used in the AF diffusion, e.g. `sha256`).
  - `area`: where the keyslot's encrypted, AF-split copy of the key is
    stored: `offset` and `size` in bytes, `encryption` (the cipher that
    encrypts the area) and `key_size` (that cipher's key size).
    cryptsetup uses the volume's own cipher for the area whenever it
    can (see
    [`af-splitting-explained.md`](af-splitting-explained.md#what-is-written-to-disk)).
  - `kdf`: the function that turns a passphrase into the area key:
    `type` (`argon2id`, `argon2i` or `pbkdf2`) and its parameters (see
    [Argon2id](#argon2id)).
  - `priority` (optional): 0 = ignore unless named, 1 = normal,
    2 = high.
- **`digests`**: each digest is "used to verify that a key decrypted
  from a keyslot is correct" (spec §3.4, p.12), and lists the keyslots
  and segments it belongs to. This lets cryptsetup tell whether a
  passphrase was right without touching the data.
- **`segments`**: the encrypted data area(s): `type`, `offset`, `size`
  (or `"dynamic"` for the rest of the device), and for `crypt`
  segments `iv_tweak`, `encryption` (e.g. `aes-xts-plain64`) and
  `sector_size` (spec §3.3, pp.10–11).
- **`tokens`** (optional): each token "can describe how to get a
  passphrase to unlock a particular keyslot" and lists the keyslots it
  belongs to (spec §3.6, p.13); `systemd-cryptenroll` stores its FIDO2,
  PKCS#11 and TPM2 enrollments here.

The keyslot part of `luksDump` for a volume formatted with
cryptsetup 2.8.8's defaults (from the experiment, salt elided):

```
Keyslots:
  0: luks2
	Key:        512 bits
	Priority:   normal
	Cipher:     aes-xts-plain64
	Cipher key: 512 bits
	PBKDF:      argon2id
	Time cost:  5
	Memory:     1048576
	Threads:    4
	Salt:       <random>
	            <random>
	AF stripes: 4000
	AF hash:    sha256
	Area offset:32768 [bytes]
	Area length:258048 [bytes]
	Digest ID:  0
```

`Time cost` and `Memory` depend on the machine that formatted the
volume (see [Argon2id](#argon2id)).
[`checking-for-corruption.md`](checking-for-corruption.md) shows how
to use `Area offset` and `Area length`.

## Reading Area offset / Area length

`Area offset` and `Area length` (`offset` and `size` in the keyslot's
`area` object) give the byte range on the device where the keyslot's
encrypted key material is stored, counted from byte 0 of the device
(spec §3.2.3, p.9: "the offset from the device start").

Given:

```
Area offset: 32768   [bytes]
Area length: 258048  [bytes]
```

the area occupies bytes `[32768, 32768 + 258048)` = `[32768, 290816)`.
[`checking-for-corruption.md`](checking-for-corruption.md) gives the
`dd` command to extract it, and `scripts/inspect-keyslot` computes the
range for you.

The area is much larger than the key because of AF-splitting (below):
a 64-byte key is split into 4000 stripes, 256,000 bytes, rounded up to
whole 512-byte sectors. The area is larger still: 258,048 bytes
(63 × 4096) in the experiment. The remaining 2,048 bytes are not
zeros: when formatting, cryptsetup fills the whole keyslots area with
random data (`LUKS2_wipe_header_areas()`,
`lib/luks2/luks2_json_format.c`, lines 325–379), and nothing
overwrites that tail afterwards.

## Argon2id

LUKS2's default key derivation function (KDF), the function that turns
a passphrase into the key that decrypts a keyslot, is **Argon2id**
(`configure.ac`, line 806). LUKS1 uses PBKDF2.

**Why Argon2id and not PBKDF2.** PBKDF2's cost is repeated hashing,
which needs almost no memory, so an attacker can run very many guesses
in parallel on GPUs or dedicated hardware. Argon2 also makes each
guess fill and read a configurable amount of memory, so parallel
guessing needs that much memory per guess. Argon2id "works as Argon2i
for the first half of the first pass over the memory and as Argon2d
for the rest, thus providing both side-channel attack protection and
brute-force cost savings due to time-memory trade-offs"
([RFC 9106](https://www.rfc-editor.org/rfc/rfc9106) §1), and RFC 9106
recommends it as the default variant (§7.4).
[`kdf-comparison.md`](kdf-comparison.md) compares the two in detail.

**The three cost parameters**, as `luksDump` shows them:

- **Time cost**: the number of passes over the memory (RFC 9106
  §3.1, "Number of passes t").
- **Memory**: the memory per guess, in kilobytes. `Memory: 1048576` is
  1 GiB, cryptsetup's default maximum (`configure.ac`, line 809). An
  attacker needs this much memory for each guess running at the same
  time.
- **Threads**: the degree of parallelism, how many lanes compute one
  guess in parallel (RFC 9106 §3.1); cryptsetup's default maximum is 4
  (`configure.ac`, line 810).

`luksFormat` chooses the time cost and memory by benchmarking the
machine, aiming for the configured iteration time, 2000 ms by default
(`configure.ac`, line 808; `--iter-time` changes it). That is why the
values differ between volumes formatted on different machines.
`--pbkdf-force-iterations`, `--pbkdf-memory` and `--pbkdf-parallel`
set them directly, at format time or when adding or changing a key.

**What this means for recovery.** Every passphrase guess against a
real keyslot costs that time and memory, so testing candidates with
`cryptsetup open --test-passphrase` only works for a small number of
them. This shapes the recovery tool in this project; see
[`passphrase-recovery.md`](passphrase-recovery.md).

## AF-splitting (anti-forensic splitting)

Before a keyslot's copy of the master key is encrypted and written to
its `area` on disk, LUKS2 expands it with **AF-splitting**
(anti-forensic splitting), the same algorithm LUKS1 uses: "only the
luks1 type is currently used", and that type is "compatible with
LUKS1" (spec §3.2, p.9, and §3.2.4, p.10). The key is split first and
the result is encrypted (§4.2, p.14). Splitting is not encryption; its
purpose is to make the keyslot erasable.

AF-splitting expands an *N*-byte key (64 bytes with the default
`aes-xts-plain64`) into 4000 stripes of *N* bytes each. LUKS2 supports
no other stripe count ("for historical reasons only the 4000 value is
supported", §3.2.4, p.10), recorded in the keyslot's `af.stripes`
field. In cryptsetup's implementation
([`lib/luks1/af.c`](https://gitlab.com/cryptsetup/cryptsetup/-/blob/fb6b9480fa519c70366d6743ec84cb0f3afcc8c7/lib/luks1/af.c#L91-139)):

- **Every stripe is needed to reconstruct the key.** Stripes 1 to 3999
  are random. Each is XORed into a running accumulator, which is then
  passed through a hash-based diffusion function (the `af.hash` field,
  typically SHA-256). That function hashes the accumulator in separate
  digest-sized chunks (32 bytes for SHA-256), so damage to part of a
  stripe scrambles only the key chunk it lines up with: one half of a
  64-byte key. The
  [LUKS1 specification](https://gitlab.com/cryptsetup/cryptsetup/-/blob/bae21790d59897ac50e5471f953f76b3a58aeeb6/docs/on-disk-format.pdf)
  records this chunk-by-chunk design as an implementation error
  (§2.4.1, footnote 4, p.4).
- **The last stripe is not diffused.** It is the key XORed with the
  final accumulator, so damage to part of it changes only the matching
  bytes of the reconstructed key.

**Why this exists.** Removing a passphrase means destroying its
keyslot's encrypted copy of the master key; otherwise anyone who knows
the old passphrase can still decrypt it (spec §4.4 "Keyslot
Revocation", p.14). An overwrite can miss a sector that disk firmware
has remapped to a reserved area, and a 32- or 64-byte key fits in one
such sector whole. AF-splitting makes the stored copy 4000 times
larger, so that an overwrite destroys at least one necessary piece
with high probability (Fruhwirth,
[*New Methods in Hard Disk Encryption*, 2005](https://clemens.endorphin.org/nmihde/nmihde-A4-ds.pdf)
§5.2, pdf p.87–89). It does not work on flash storage, where spare
pools far larger than any keyslot can keep old copies; the LUKS2
specification calls the splitter "no longer much effective on modern
storage devices" (§3.2.4, p.10). See
[`af-splitting-explained.md`](af-splitting-explained.md#the-problem-af-splitting-solves-restated-concretely)
for the full argument and sources.

**What this means when inspecting a keyslot.** The area holds
ciphertext, which looks like uniformly random bytes whether or not it
decrypts to the right key, so a hex dump cannot show that a keyslot is
intact. It can show some kinds of damage that ciphertext does not
produce, such as long runs of one byte value or repeating patterns;
[`checking-for-corruption.md`](checking-for-corruption.md) covers what
to look for. [`af-splitting-explained.md`](af-splitting-explained.md#what-damage-does-to-the-key)
works through exactly how much of the key one damaged byte destroys.

## Primary vs. secondary header: legitimate differences

LUKS2 stores two copies of the binary header and JSON area: the
primary at offset 0 and the secondary right after the primary JSON
area (offset `0x4000` by default). The copies "under normal
circumstances contain same functional metadata" (spec §2, p.3), so
damage to one, for example from overwriting the start of the device,
can be repaired from the other (see the end of
[The binary header, byte-by-byte](#the-binary-header-byte-by-byte)).

Compared byte by byte, the two copies are **not** identical, and that
is expected. In the experiment, the binary headers differed in exactly
four fields, as the specification requires:

- **`magic`**: `LUKS\xba\xbe` in the primary, `SKUL\xba\xbe` in the
  secondary (spec §2.1, Figure 2, p.5). cryptsetup checks that each
  copy has the right one (`hdr_disk_sanity_check_pre()`, line 185).
- **`salt`**: random, and "different for every header (it differs on
  the primary and secondary header)". It "is not used after the binary
  header is read, the main intention is to avoid deduplication of the
  header sector", and it "must be regenerated on every header repair"
  (spec §2.1, p.4).
- **`hdr_offset`**: each header records its own offset, so the primary
  has 0 and the secondary has 16384 by default.
- **`csum`**: each copy's checksum covers its own binary header and
  JSON area. Since the binary headers differ, so do the checksums. A
  checksum that does not match its own copy means damage; two copies
  with different checksums is normal.

Everything else, including `seqid`, `uuid`, `label` and the JSON
content, should be the same. A real difference in the JSON content
(different keyslots or segments, for example) or in `seqid` means the
copies are out of step, which cryptsetup resolves in favour of the
valid copy with the higher `seqid`.

## Command reference

| Command | Purpose |
|---|---|
| `cryptsetup luksDump /dev/sdX` | Readable dump of the header and JSON metadata: cipher, keyslots, KDF parameters, digests, tokens, segments. |
| `cryptsetup luksDump --dump-json-metadata /dev/sdX` | The raw JSON metadata only, for scripts or archiving. |
| `dd if=/dev/sdX bs=1 skip=<offset> count=<length> \| xxd` | Extract and hex-dump a byte range, such as a keyslot area or a header. See [`checking-for-corruption.md`](checking-for-corruption.md). |
| `cryptsetup repair /dev/sdX` | "Tries to repair the device metadata if possible", for "some known benign LUKS metadata header corruptions"; it "will only change the LUKS header, not any keyslot data", and can warn about some damaged keyslots ([man page](https://gitlab.com/cryptsetup/cryptsetup/-/blob/bae21790d59897ac50e5471f953f76b3a58aeeb6/man/cryptsetup-repair.8.adoc)). It cannot repair a damaged keyslot or help with a wrong passphrase. |
| `cryptsetup luksHeaderBackup /dev/sdX --header-backup-file <file>` | "Stores a binary backup of the LUKS header and keyslot area" ([man page](https://gitlab.com/cryptsetup/cryptsetup/-/blob/bae21790d59897ac50e5471f953f76b3a58aeeb6/man/cryptsetup-luksHeaderBackup.8.adoc)). Take one before any exploratory work on a real device. With it, any passphrase valid when it was taken can still open the volume. |
| `cryptsetup luksHeaderRestore /dev/sdX --header-backup-file <file>` | Writes a header backup back to the device. "All keyslots will be replaced; only the passphrases from the backup will work afterward" ([man page](https://gitlab.com/cryptsetup/cryptsetup/-/blob/bae21790d59897ac50e5471f953f76b3a58aeeb6/man/cryptsetup-luksHeaderRestore.8.adoc)). Only use a backup you know is from this device and good. |

---

Next: [`checking-for-corruption.md`](checking-for-corruption.md):
using this to tell a damaged header or keyslot from a wrong
passphrase.
