# LUKS2 Header and Keyslot Anatomy

This document explains how a LUKS2-encrypted volume is structured on disk,
what each part is for, and how to read that structure directly using
`cryptsetup luksDump` and raw tools like `dd`/`xxd`. It assumes no prior
knowledge of LUKS internals.

## Contents

- [What LUKS2 is, and why header/keyslot separation exists](#what-luks2-is-and-why-headerkeyslot-separation-exists)
- [On-disk layout](#on-disk-layout)
- [The JSON metadata area](#the-json-metadata-area)
- [Reading Area offset / Area length](#reading-area-offset--area-length)
- [Argon2id](#argon2id)
- [AF-splitting (anti-forensic splitting)](#af-splitting-anti-forensic-splitting)
- [Primary vs. secondary header: legitimate differences](#primary-vs-secondary-header-legitimate-differences)
- [Command reference](#command-reference)

## What LUKS2 is, and why header/keyslot separation exists

LUKS (Linux Unified Key Setup) is the standard on-disk format for
block-device encryption on Linux. LUKS2 is the current major version,
superseding LUKS1. `cryptsetup` is the userspace tool that creates,
inspects, and manages LUKS volumes on top of the kernel's `dm-crypt`.

The central design idea in LUKS — the reason it isn't "just" a password
that derives an encryption key directly — is the separation between:

- **The master key**: a large random value that is the *actual* key used
  to encrypt and decrypt every block of data on the volume. It is
  generated once, at volume creation, and never derived from a
  passphrase.
- **Keyslots**: independent, separately-encrypted copies of that same
  master key, each protected by a different passphrase (or other
  credential, such as a FIDO2 token or TPM-sealed secret via `systemd-cryptenroll`).

This indirection is what makes several everyday operations possible:

- **Multiple passphrases** can unlock the same volume, each in its own
  keyslot, without needing to re-encrypt the entire disk.
- **Changing a passphrase** just re-wraps the master key in a keyslot
  under a new passphrase — the (potentially huge) bulk data on disk is
  never touched or re-encrypted.
- **Revoking a passphrase** (e.g. a lost laptop, an offboarded employee)
  is a matter of wiping one keyslot, not re-encrypting the volume.

The **header** is the small, fixed-format region at the start (and,
redundantly, mirrored elsewhere) of the device that holds everything
needed to *interpret* the rest of the device: which cipher is in use,
where the keyslots live, where the encrypted data segment begins, and
the metadata describing all of that. The header is not secret — an
attacker with the device already has it — but it is essential: lose or
corrupt it beyond repair, and every byte of "random-looking" data after
it is unrecoverable, no matter how correct your passphrase is.

## On-disk layout

A LUKS2 device, from byte 0, looks roughly like this:

```
offset 0x0000  ┌────────────────────────────────────┐
               │ Primary binary header (4 KiB)       │  fixed-size, "LUKS" magic
               ├────────────────────────────────────┤
               │ Primary JSON metadata area           │  size given in binary header
               │ (typically ~12 KiB of the total      │
               │  16 KiB primary metadata region)     │
0x4000         ├────────────────────────────────────┤
               │ Secondary (backup) binary header     │  fixed-size, "SKUL" magic
               │ (4 KiB)                               │  (byte-reversed magic — see below)
               ├────────────────────────────────────┤
               │ Secondary JSON metadata area          │  mirror of primary JSON
               │ (same size as primary)                │
   ...         ├────────────────────────────────────┤
               │ Keyslot areas                         │  one binary region per keyslot,
               │ (binary, AF-striped, high-entropy)    │  offset/size defined in JSON
   ...         ├────────────────────────────────────┤
               │ (optional) LUKS2 token/other areas    │
   ...         ├────────────────────────────────────┤
               │ Data segment                          │  the actual encrypted payload
               │ (everything the mapped /dev/mapper/*  │  (filesystem, LVM PV, etc.)
               │  device exposes)                      │
               └────────────────────────────────────┘
```

Key points:

- The **default total metadata size** reserved at the front of a LUKS2
  device is 16 MiB (primary header + JSON, secondary header + JSON, and
  keyslot areas all live inside this region by default), though this is
  configurable at format time (`cryptsetup luksFormat --luks2-metadata-size`
  / `--luks2-keyslots-size`).
- The **primary header** starts at offset 0. The **secondary (backup)
  header** starts at a fixed offset of `0x4000` (16384 bytes) into the
  device by default.
- Each binary header is followed immediately by its own JSON metadata
  area. The primary and secondary JSON areas are supposed to be mirror
  images of each other — same content, describing the same volume.
- **Keyslot areas** are binary regions elsewhere in the metadata region
  (not fixed offsets — their exact location is *described by* the JSON
  metadata, not implied by a fixed layout). This is a key difference
  from LUKS1, where keyslot geometry was rigidly fixed by the format.
  LUKS2's JSON-described layout is what allows variable numbers of
  keyslots, variable KDF parameters per keyslot, and other flexibility.
- The **data segment** — the actual encrypted filesystem or payload —
  begins after the metadata region and continues to the end of the
  device (or to wherever the JSON `segments` object says it does).

## The JSON metadata area

Everything after each 4 KiB binary header is a JSON document describing
the volume. Run:

```
sudo cryptsetup luksDump /dev/sdX
```

to see this rendered in human-readable form, or:

```
sudo cryptsetup luksDump --dump-json-metadata /dev/sdX
```

to get the raw JSON directly (useful for scripting or archiving a copy
of your header's metadata for backup purposes).

The JSON document has several top-level sections. The ones you'll deal
with most often:

- **`config`**: overall metadata region sizing (`json_size`,
  `keyslots_size`) and a few volume-wide flags.
- **`keyslots`**: one entry per keyslot, keyed by keyslot number
  (`"0"`, `"1"`, ...). Each entry describes:
  - `type` — usually `"luks2"` for a passphrase-protected keyslot
    (there are other types, e.g. `"reencrypt"` for in-progress
    re-encryption bookkeeping).
  - `key_size` — size in bytes of the key material this slot protects
    (matches the master key size for the volume's cipher).
  - `af` — the anti-forensic (AF) splitting parameters: `type` (almost
    always `"luks1"`, the AF algorithm carried over from LUKS1),
    `stripes` (default 4000), and `hash` (the hash used in the AF
    diffusion, e.g. `sha256`).
  - `area` — where on disk this keyslot's *encrypted, AF-striped* key
    material actually lives: `offset`, `size` (bytes), `encryption`
    (the cipher used to encrypt this keyslot's data, independent of the
    volume's data cipher, though usually matching), and `key_size`.
  - `kdf` — the key-derivation function used to turn a passphrase into
    the key that unwraps this slot: `type` (`argon2id`, `argon2i`, or
    legacy `pbkdf2`), plus the tunable cost parameters (see
    [Argon2id](#argon2id) below).
- **`digests`**: one entry per digest, used to verify that a candidate
  master key (recovered by successfully unwrapping *any* keyslot) is
  actually correct, without needing to touch the encrypted data segment.
  Each digest independently binds to a set of keyslots via `keyslots`,
  so LUKS2 can tell you whether an unwrapped key is right before you
  ever try to mount anything.
- **`segments`**: describes the encrypted data area(s) — starting
  `offset`, `size` (or `"dynamic"` for "rest of device"), `iv_tweak`,
  `encryption` (the cipher spec, e.g. `aes-xts-plain64`), and
  `sector_size`.
- **`tokens`** (optional): metadata for auxiliary unlock mechanisms —
  e.g. `systemd-cryptenroll`'s TPM2 or FIDO2 tokens, or just a stored
  hint/label. Tokens reference one or more keyslots they can unlock.

A trimmed example (`luksDump` human-readable form) for one keyslot:

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
        Salt:       XX XX XX XX XX XX XX XX ... (32 bytes)
        AF stripes: 4000
        AF hash:    sha256
        Area offset:32768 [bytes]
        Area length:258048 [bytes]
        Digest ID:  0
```

Every field here is discoverable and meaningful — nothing is opaque
binary magic once you know where to look. `checking-for-corruption.md`
walks through using `Area offset` / `Area length` in practice.

## Reading Area offset / Area length

`Area offset` and `Area length` (or `offset`/`size` in the raw JSON's
`keyslots.<N>.area` object) tell you the *exact byte range on the
physical device* where this keyslot's encrypted key material lives.
These are absolute byte offsets from the start of the device (byte 0),
not offsets from the start of the metadata region.

Given:

```
Area offset: 32768   [bytes]
Area length: 258048  [bytes]
```

the keyslot's raw data occupies bytes `[32768, 32768 + 258048)` =
`[32768, 290816)` on the device. You can extract exactly that range with
`dd` — see `docs/checking-for-corruption.md` for the precise command and
what to look for in the output. `scripts/inspect-keyslot.sh` automates
this computation so you never have to do the arithmetic by hand.

Note that `Area length` is deliberately larger than the master key
itself — this is because of AF-splitting (below), which expands the key
material by a configurable factor (default 4000 stripes) before it's
written to disk.

## Argon2id

LUKS2's default key-derivation function (KDF) — the function that turns
a human passphrase into a cryptographic key capable of unwrapping a
keyslot — is **Argon2id**. This is a deliberate improvement over LUKS1,
which used PBKDF2.

**Why Argon2id and not PBKDF2:** PBKDF2 is a *compute-hard* KDF — its
cost comes purely from doing many rounds of hashing, which is cheap to
parallelize on GPUs and near-free on purpose-built ASICs. That makes
brute-forcing a weak passphrase against a stolen PBKDF2-protected header
far more tractable for a well-resourced attacker than the same attack
against a *memory-hard* KDF. Argon2id (the balanced hybrid variant of
the Argon2 family, resistant to both side-channel and GPU/ASIC-style
time-memory tradeoff attacks) forces each guess to also consume a
significant, configurable amount of RAM, which GPUs and ASICs have far
less of per compute unit than a general-purpose CPU. This closes most of
the brute-force cost advantage that specialized hardware would otherwise
have.

**The three tunable cost parameters**, as shown in `luksDump` output:

- **Time cost** (iterations): how many passes Argon2id makes over the
  memory buffer. Higher = slower to compute, for both legitimate unlocks
  and attackers.
- **Memory** (KiB): the size of the memory buffer each single guess must
  allocate and touch. `Memory: 1048576` means 1 GiB per attempt. This is
  the parameter that most directly hurts parallel brute-force — an
  attacker trying many guesses at once needs that much RAM *per
  concurrent guess*, not just once total.
- **Threads**: how many threads compute a single guess in parallel
  (affects wall-clock time, not the fundamental memory/time cost per
  guess).

`cryptsetup luksFormat` picks Time cost and Memory automatically at
volume-creation time, calibrated so that unlocking the volume on the
machine it was created on takes roughly a target duration (by default,
around 2 seconds) — this is why parameters vary between volumes created
on different hardware. You can override this with `--pbkdf-force-iterations`,
`--pbkdf-memory`, and `--pbkdf-parallel` at format or `luksChangeKey` time.

**The practical consequence for recovery tooling**: because each
passphrase guess against a real keyslot costs a deliberately significant
amount of time and memory (by design — that's the whole point of using
Argon2id), any recovery approach that relies on `--test-passphrase`
against the actual header is only tractable for a small number of
candidates. This directly shapes the scope of the recovery tool in this
project — see `docs/passphrase-recovery.md`.

## AF-splitting (anti-forensic splitting)

Before a keyslot's key material is encrypted and written to its `area`
on disk, LUKS applies **AF-splitting** (anti-forensic splitting, an
algorithm inherited unchanged from LUKS1). This is a *diffusion* step,
not encryption — the goal is different from confidentiality:

AF-splitting takes the (typically 512-bit) unwrapped key and expands it
into many "stripes" (4000 by default — see the `af.stripes` field in
the JSON) such that:

- **All stripes are needed to reconstruct the original key.** Losing or
  corrupting even a single stripe makes the entire keyslot
  unrecoverable — there is no partial reconstruction.
- **Each stripe, individually, reveals nothing about the key.** The
  diffusion uses repeated hashing (the `af.hash` field, typically
  SHA-256) to mix each stripe with the ones before it, so that only the
  complete, ordered set of stripes lets you invert the process.

**Why this exists as a security feature** (not a bug, and not something
this project's tooling tries to work around): magnetic and flash media
do not reliably guarantee that an overwritten sector is truly gone —
wear-leveling, bad-block remapping, and filesystem journaling can all
leave forensic remnants of old data behind. If a keyslot were written to
disk as a single contiguous copy of the (wrapped) key, an attacker who
recovered even a fragment of an old, "deleted" keyslot region might
reconstruct a meaningful chunk of key material. AF-splitting means a
partially-erased or partially-recovered keyslot is cryptographically
useless — you need every stripe, in order, or you have nothing.

**Why this matters when inspecting a keyslot for corruption**: because
AF-striped, encrypted key material is expected to look like uniform
high-entropy random noise (that's what "encrypted with no exploitable
structure" looks like), you *cannot* visually distinguish "encrypted
correctly" from "gibberish" just by looking at a hex dump — but you
*can* spot structural corruption, because real random noise doesn't
produce long runs of a single repeated byte, obvious repeating patterns,
or premature all-zero padding. `docs/checking-for-corruption.md` covers
exactly what to look for.

## Primary vs. secondary header: legitimate differences

LUKS2 stores **two independent copies** of the binary header + JSON
metadata: the primary at offset 0, and a secondary (backup) copy at a
fixed offset (`0x4000` = 16384 bytes, by default). This redundancy
exists so that damage to the very front of the device (a common failure
mode — partition table corruption, accidental `dd` of a few sectors,
firmware bugs on some external enclosures) doesn't necessarily destroy
your ability to unlock the volume; `cryptsetup luksHeaderRestore` and
`cryptsetup repair` can fall back to the secondary copy.

When you compare the two headers directly (e.g. with `dd`+`xxd`, see
`docs/checking-for-corruption.md`), you will find they are **not**
byte-identical, and that is by design, not evidence of corruption:

- **Magic bytes are byte-reversed.** The primary header begins with the
  ASCII magic `LUKS\xba\xbe` (the traditional LUKS signature). The
  secondary header begins with `SKUL\xba\xbe` — literally "LUKS"
  spelled backward. This is intentional: it lets tooling (and a human
  looking at a hex dump) immediately distinguish "this is a primary
  header" from "this is a backup header" without needing to know its
  offset in advance, which matters for recovery scenarios where the
  device may have been imaged or partially reconstructed.
- **Independent checksums.** Each header carries its own checksum
  (SHA-256 by default) over its own binary header fields. Because the
  headers differ (at minimum, in their magic bytes and their own
  self-description), their checksums necessarily differ too. A checksum
  mismatch *within* a single header (i.e., the header's own checksum
  field doesn't match its own computed contents) indicates corruption;
  the primary and secondary simply having *different* checksum values
  from each other is expected and normal.
- **Independent salts.** Each binary header stores its own random salt,
  used in header integrity verification. Two independently-generated
  random salts will always differ — this is not a discrepancy to
  investigate.
- **A self-referential offset pointer.** The secondary header's binary
  structure includes a field recording its own offset on the device
  (so that tools reading a raw image, without external knowledge of
  where the backup header lives, can confirm they've found a genuine
  backup header at the offset they expect). The primary header, always
  living at offset 0 by convention, has no equivalent need for this
  field.

The JSON metadata *content* between primary and secondary (keyslots,
digests, segments, tokens) is expected to be **semantically identical**
even though the surrounding binary header differs — both describe the
same volume. If the JSON content itself differs meaningfully between
primary and secondary (e.g. a different number of keyslots, different
segment offsets), that is a genuine red flag, unlike the expected binary
header differences above.

## Command reference

| Command | Purpose |
|---|---|
| `cryptsetup luksDump /dev/sdX` | Human-readable dump of header + JSON metadata: cipher, keyslots, KDF parameters, digests, tokens, segments. |
| `cryptsetup luksDump --dump-json-metadata /dev/sdX` | Raw JSON metadata only, suitable for scripting or archiving. |
| `dd if=/dev/sdX bs=1 skip=<offset> count=<length> \| xxd` | Extract and hex-dump an arbitrary byte range — used to inspect keyslot areas or compare headers directly. See `docs/checking-for-corruption.md`. |
| `cryptsetup repair /dev/sdX` | Attempts to fix *structural* JSON metadata damage (e.g. a corrupted or unparseable JSON area, recoverable from the redundant copy or internal consistency checks). Cannot repair corrupted keyslot key material, and cannot help with a wrong passphrase. |
| `cryptsetup luksHeaderBackup /dev/sdX --header-backup-file <file>` | Back up the entire header region (primary + secondary + keyslot areas) to a file — do this *before* any exploratory work on a real device. |
| `cryptsetup luksHeaderRestore /dev/sdX --header-backup-file <file>` | Restore a previously backed-up header region. Destructive to the current header — only use on a deliberately restored/known-good backup. |

---

Next: [`docs/checking-for-corruption.md`](checking-for-corruption.md) —
using this knowledge to distinguish a corrupted header/keyslot from a
simply-wrong passphrase.
