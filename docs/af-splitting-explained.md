# AF-Splitting, Explained From First Principles

This is a slow, beginner-friendly walkthrough of anti-forensic (AF)
splitting — the algorithm covered at a higher level in
[`luks2-header-anatomy.md#af-splitting-anti-forensic-splitting`](luks2-header-anatomy.md#af-splitting-anti-forensic-splitting).
That section explains *what* AF-splitting is for. This document exists to
explain *how it actually works*, byte by byte, so that when you're staring
at a hex dump wondering whether a keyslot is corrupted, you understand
mechanically why the answer is "yes, unrecoverably" rather than taking it
on faith.

If you haven't read the anatomy doc's AF-splitting section yet, read that
first — this document assumes you know *why* AF-splitting exists (the
anti-forensic property: a partially-recovered keyslot must be
cryptographically useless) and focuses entirely on *how*.

## Contents

- [The problem AF-splitting solves, restated concretely](#the-problem-af-splitting-solves-restated-concretely)
  - [Aside: where does that key-length number actually come from?](#aside-where-does-that-key-length-number-actually-come-from)
    - [Where key length actually comes from, per code](#where-key-length-actually-comes-from-per-code)
    - [The keyslot JSON object, sketched](#the-keyslot-json-object-sketched)
    - [A real example, from the spec itself](#a-real-example-from-the-spec-itself)
- [The real algorithm, in plain English](#the-real-algorithm-in-plain-english)
- [A worked example you can trace by hand](#a-worked-example-you-can-trace-by-hand)
  - [Splitting the key](#splitting-the-key)
  - [Merging the stripes back](#merging-the-stripes-back)
- [Why this makes corruption unrecoverable: three demonstrations](#why-this-makes-corruption-unrecoverable-three-demonstrations)
- [Mapping the toy example back to real LUKS2](#mapping-the-toy-example-back-to-real-luks2)
- [What this means when you're inspecting a keyslot](#what-this-means-when-youre-inspecting-a-keyslot)

## The problem AF-splitting solves, restated concretely

Say your LUKS2 volume's master key is *N* bytes. If that key were
written to disk as-is — even encrypted under your passphrase-derived
key — an attacker who recovers even a small *fragment* of that region
(from wear-leveling remnants on an SSD, a bad-block remap, filesystem
journal residue, whatever) has a fragment of the actual key. Not the
whole key, but a real, meaningful piece of it, which measurably narrows
a brute-force search.

AF-splitting's job is to take that *N*-byte key and expand it into many
"stripes" (4000, by default) such that:

- All 4000 stripes, in order, are needed to reconstruct the original key.
- Any subset smaller than all 4000 — even 3999 of them — reveals
  **nothing** about the key. Not "a little less secure," not "narrows the
  search space slightly." Nothing, in the same sense that XORing a secret
  with one unknown random byte reveals nothing about the secret.

That second property is the interesting part, and it's not automatic —
you get it from a specific construction, not from "spread the data out
and hope." The rest of this document is that construction, worked
through with a concrete *N* so you can trace real numbers rather than
reason about an abstract key. Before picking that *N*, though, it's
worth being precise about what it actually is — because "the master
key" is not a fixed-size thing LUKS2 defines once; it's determined by
choices made at `luksFormat` time, and getting that wrong is exactly
the kind of imprecision this project's docs are supposed to avoid.

### Aside: where does that key-length number actually come from?

Before getting into *why* the number is what it is, three things worth
being concrete about, since none of them are stated anywhere above:

- **What this key actually is.** It's the one secret dm-crypt uses to
  encrypt and decrypt your actual filesystem data, sector by sector,
  every time you read or write to the unlocked volume. It is *not*
  derived from your passphrase — it's generated once, from random
  bytes, at `luksFormat` time, and never changes for the life of the
  volume (unless you re-encrypt). Your passphrase's only job is to
  unwrap (decrypt) a *copy* of this key stored in a keyslot — see
  [`luks2-header-anatomy.md`](luks2-header-anatomy.md) for the full
  unlock flow.
- **Where it lives.** Never in cleartext on disk, anywhere. What's on
  disk, per keyslot, is this key encrypted under your passphrase-derived
  key and then AF-split (the whole subject of this document) — that's
  the `area` region [`checking-for-corruption.md`](checking-for-corruption.md)
  walks through inspecting. In cleartext, it exists in two different
  places at two different points, each verified against the real
  source rather than described in general terms:
  - **Briefly, in `cryptsetup`'s own (userspace) heap memory**, only
    during the unlock process itself. The unwrapped key is allocated
    via `crypt_safe_alloc()`
    ([`lib/utils_safe_memory.c`](https://gitlab.com/cryptsetup/cryptsetup/-/blob/main/lib/utils_safe_memory.c),
    verified 2026-08-17), which `mlock()`s the allocation (so it can't
    be swapped to disk) and, on `crypt_safe_free()`, explicitly zeroes
    it before calling `free()` — not a `memset` that a compiler could
    optimize away, but `crypt_backend_memzero()`, meant to survive
    that. This is heap memory, not stack, and not a CPU register — a
    process with `ptrace` rights on the running `cryptsetup` process
    (in practice, root, since `luksOpen` itself requires root) could
    read it while it's live, the same as for any other process's
    memory; nothing LUKS-specific defends against a *hostile root* on
    the same machine, only against the key ending up on persistent
    storage (swap) or lingering after use.
  - **For as long as the volume stays mapped, inside the Linux
    kernel's `dm-crypt` target** — a completely separate copy from
    cryptsetup's, in kernel space rather than userspace. The kernel's
    `struct crypt_config` (`drivers/md/dm-crypt.c`, confirmed against
    the current Linux source, commit `8d3ae59288f1e7d58d76558a6ee96d533bc5019f`)
    ends with `u8 key[] __counted_by(key_size);` — the raw key bytes
    are allocated as part of this struct itself (`kzalloc_flex(*cc,
    key, key_size)`), on the kernel heap, not the stack. It stays
    there for the mapping's entire lifetime — this is *why* a mounted
    LUKS volume keeps working without re-prompting for a passphrase on
    every read/write: the kernel already has the key and uses it
    directly, it doesn't ask userspace again. Reading kernel memory
    from userspace isn't possible through ordinary means (no
    `ptrace`-equivalent for kernel memory); it requires either a kernel
    exploit, physical access with a hardware/DMA-based memory-dump
    attack (a real, known LUKS/dm-crypt threat class, sometimes called
    a "cold boot" or DMA attack — a fundamentally different threat
    model from anything else in this project, since it requires an
    already-unlocked, running machine rather than a disconnected drive;
    see [`cold-boot-and-dma-attacks.md`](cold-boot-and-dma-attacks.md)
    for the full treatment), or root abusing something like `/dev/kmem` where that's
    even enabled (it's disabled by default on modern kernels). On
    `cryptsetup luksClose` (which tears down the device-mapper
    target), the kernel's own destructor, `crypt_dtr()`, explicitly
    zeroes `struct crypt_config` before freeing it — the source
    literally comments this step `/* Must zero key material before
    freeing */` before calling `kfree_sensitive(cc)`, which zeroes
    memory before the underlying `kfree()`. Until `luksClose` (or a
    reboot/crash) happens, the key is genuinely still resident in
    kernel memory — it does not get wiped just because you stop
    actively reading/writing the volume.
- **What it's used for, mechanically.** This is the same plaintext
  master key from the first bullet above — already unwrapped from a
  keyslot and confirmed correct by the digest check below — being put
  to its actual use: encrypting and decrypting sectors, via a concrete
  kernel object. Getting there, and then using it, breaks into three
  distinct steps — object creation, one-time keying, and repeated use
  — and keeping them separate is exactly what avoids the confusion
  below about what happens "once" versus "constantly":
  1. **The cipher object gets created, empty, at unlock time — before
     the key is involved at all.** When a LUKS device is set up
     (`luksOpen`), dm-crypt calls `crypt_alloc_tfms_skcipher()`, which
     calls the kernel crypto API's `crypto_alloc_skcipher("aes-xts-plain64", ...)`
     (or whatever cipher the volume was formatted with). This asks the
     kernel to instantiate a real, working implementation of that
     algorithm — a `struct crypto_skcipher` object, referred to in the
     code as a `tfm` ("transform") — and the kernel picks a concrete
     backend for it (a plain C implementation, or a
     CPU-instruction-accelerated one like AES-NI, depending on what's
     available; dm-crypt logs which one it picked via
     `cra_driver_name`). At this point the `tfm` exists and knows *how*
     to do AES-XTS, but has no key yet.
  2. **The raw key bytes are consumed exactly once, immediately after
     that empty `tfm` is created — turning them into a *key schedule*
     stored inside it.** A
     key schedule is AES's own internal expansion of your key into a
     separate round key for each of its encryption rounds (14 rounds
     for AES-256, so 15 round keys) — this is `KeyExpansion()`, [FIPS
     197](https://doi.org/10.6028/NIST.FIPS.197-upd1) §5.2, p. 17
     (Algorithm 2). In the current kernel this is `aes_expandkey()`
     (declared in
     [`include/crypto/aes.h`](https://github.com/torvalds/linux/blob/d4e273a5065f81ca86eca48cb3fed55867cc0115/include/crypto/aes.h#L146-L160),
     pinned commit `d4e273a5`, verified 2026-08-20; its own doc comment
     says outright: *"Expands the AES key as described in FIPS-197"*),
     which the `tfm`'s `setkey` operation calls internally. dm-crypt
     triggers this by calling
     `crypt_setkey()`, which calls
     `crypto_skcipher_setkey(tfm, key, size)`. This is the only point
     in the entire volume-mount lifetime where the raw plaintext key
     bytes are handed to a *new* function call for ordinary I/O — but
     that doesn't mean the raw bytes disappear afterward. The schedule
     produced isn't some separate, derived secret that replaces the
     key; per FIPS 197 Algorithm 2 (quoted above), the schedule's first
     `Nk` words *are* the raw key, verbatim (`w[0..Nk-1] = key`), with
     the remaining round keys computed from there. Concretely, the
     kernel's `struct crypto_aes_ctx`
     ([`include/crypto/aes.h`](https://github.com/torvalds/linux/blob/d4e273a5065f81ca86eca48cb3fed55867cc0115/include/crypto/aes.h#L122-L126),
     lines 122–126, same pinned commit) is just two fixed 240-byte
     arrays, `key_enc[]` and `key_dec[]`, plus a length field — no
     pointer back to a separately-stored "original key" to erase,
     because there isn't one; the raw key bytes are already baked into
     slot zero of the array that gets read on every sector. So this
     step doesn't make the key harder to find in memory — if anything,
     the schedule's later slots are additional derived material sitting
     right next to the raw key, all inside the same `tfm`. What
     changes is *access pattern*, not secrecy: encrypt/decrypt calls
     read from this schedule array instead of re-running key expansion,
     which is a performance property, not a security boundary. Whoever
     could already read the raw key in kernel memory (see "Where it
     lives," above — a kernel exploit, a physical DMA/cold-boot attack,
     or root access to `/dev/kmem` where enabled) can read this
     schedule too, for exactly the same reasons and through exactly the
     same channels; expanding the key into a schedule adds no new
     protection and removes none.
  3. **Every sector read or write afterward runs the cipher against
     that already-keyed `tfm`, not against the raw key.** For each
     sector, dm-crypt allocates a fresh per-request object
     (`crypt_alloc_req_skcipher()`), binds it to the same, already-keyed
     `tfm` via `skcipher_request_set_tfm()`, and then calls
     `crypto_skcipher_encrypt()` or `crypto_skcipher_decrypt()`, which
     walks the round-key schedule built in step 2 — the same schedule,
     reused, sector after sector. So step 2 (turning the key into a
     schedule) happens exactly once per unlock, while step 3 (using
     that schedule) happens continuously, once per sector, for as long
     as the volume stays mounted. Those are different claims about
     different things — the *setup work* is one-time; the *object it
     produced* is in constant use — and collapsing them into a single
     "used once" or "used constantly" statement would misdescribe one
     half of it.

  Confirmed directly in
  [`drivers/md/dm-crypt.c`, pinned commit `43fd83c0`](https://github.com/torvalds/linux/blob/43fd83c0b1dc127cf13b4c05303665924e63ef94/drivers/md/dm-crypt.c)
  (verified 2026-08-20): step 1's
  [`crypt_alloc_tfms_skcipher()`](https://github.com/torvalds/linux/blob/43fd83c0b1dc127cf13b4c05303665924e63ef94/drivers/md/dm-crypt.c#L2297)
  (line 2297) populates `cc->cipher_tfm.tfms[i]` via
  `crypto_alloc_skcipher()`. Step 2's
  [`crypt_setkey()`](https://github.com/torvalds/linux/blob/43fd83c0b1dc127cf13b4c05303665924e63ef94/drivers/md/dm-crypt.c#L2388-L2414)
  (lines 2388–2414) loops over those same `tfms[i]` objects, calling
  `crypto_skcipher_setkey(cc->cipher_tfm.tfms[i], cc->key + (i *
  subkey_size), subkey_size)` (line 2414) for each one — and this exact
  call is the *only* call to `crypto_skcipher_setkey()` in the entire
  file, confirming it's genuinely a one-time step per unlock, not
  something the per-sector path also does. Step 3 is a completely
  separate code path:
  [`crypt_alloc_req_skcipher()`](https://github.com/torvalds/linux/blob/43fd83c0b1dc127cf13b4c05303665924e63ef94/drivers/md/dm-crypt.c#L1431-L1442)
  (lines 1431–1442) calls
  `skcipher_request_set_tfm(ctx->r.req, cc->cipher_tfm.tfms[key_index])`
  (line 1442), and
  [`crypt_convert_block_skcipher()`](https://github.com/torvalds/linux/blob/43fd83c0b1dc127cf13b4c05303665924e63ef94/drivers/md/dm-crypt.c#L1352-L1418)
  (lines 1352–1418) then calls
  `crypto_skcipher_encrypt()`/`crypto_skcipher_decrypt()` (lines
  1416/1418) — both run fresh for every sector, and neither one calls
  `crypto_skcipher_setkey()`. (`crypto_skcipher_encrypt()` also appears
  once more, at line 754, inside a self-test helper used to validate a
  cipher choice before committing to it — unrelated to the per-sector
  I/O path.)
  `crypt_setkey()` does run again later, but only if the key is
  explicitly replaced: `crypt_wipe_key()` (covered in
  [`cold-boot-and-dma-attacks.md`](cold-boot-and-dma-attacks.md)) calls
  it to load fresh random bytes into the same, already-existing `tfm`
  objects in place of the real key, destroying the old schedule.

  `aes-xts-plain64` is cryptsetup's default cipher for this step; that's
  it, there's no other role for this key anywhere in LUKS2.
- **How LUKS2 knows the unwrap actually worked.** Decrypting a keyslot
  with the *wrong* passphrase doesn't fail loudly — symmetric
  decryption with the wrong key just produces wrong-looking bytes, not
  an error. So unwrapping alone can't tell you whether you got the real
  key back. LUKS2 solves this with a separate check: at `luksFormat`
  time, the real master key is run through PBKDF2 once (independently
  of the passphrase KDF) with a stored salt, and the result is saved in
  cleartext as a `digest` in the header's JSON metadata. After
  unwrapping a candidate key from any keyslot, cryptsetup repeats that
  same PBKDF2 computation on the candidate and compares it, byte for
  byte, against the stored digest — confirmed directly in
  `PBKDF2_digest_verify()`
  ([`lib/luks2/luks2_digest_pbkdf2.c`](https://gitlab.com/cryptsetup/cryptsetup/-/blob/main/lib/luks2/luks2_digest_pbkdf2.c),
  verified 2026-08-17). Match means the passphrase was right; mismatch
  means it wasn't — and this check happens *before* cryptsetup ever
  touches your actual encrypted data, which is exactly what
  `cryptsetup open --test-passphrase` relies on to verify a guess
  safely without mounting anything (see
  [`passphrase-recovery.md`](passphrase-recovery.md)).

With that grounded, the actual question this aside answers: **why is
this key 512 bits by default**, when "AES-256" (256 bits) is the number
most people would guess? Short answer: `aes-xts-plain64`'s "XTS" part
needs two separate 256-bit AES keys, not one — one key encrypts your
actual data, the other encrypts a small per-sector value (a "tweak")
that keeps two sectors holding identical plaintext from producing
identical ciphertext. Both keys are required and independent; there is
no single, smaller "real" key underneath that gets padded or doubled
after the fact — the 512-bit value *is* the two keys, concatenated.

That two-key requirement is confirmed directly in the Linux kernel code
dm-crypt actually calls at unlock time (`crypto/xts.c`,
`xts_setkey()`), which splits an incoming key exactly in half and
explicitly rejects it if the two halves are equal:

```c
static int xts_setkey(struct crypto_skcipher *parent, const u8 *key,
		      unsigned int keylen)
{
	...
	err = xts_verify_key(parent, key, keylen);
	if (err)
		return err;

	keylen /= 2;

	/* we need two cipher instances: one to compute the initial 'tweak'
	 * by encrypting the IV (usually the 'plain' iv) and the other
	 * to encrypt the data */
	...
```
([`crypto/xts.c` on kernel.org's git mirror](https://github.com/torvalds/linux/blob/master/crypto/xts.c),
verified 2026-08-16.) That rejection isn't defensive paranoia — using
the same key for both halves is a real, documented, exploitable
weakness (a chosen-ciphertext attack letting an adversary tamper with
plaintext without knowing the key), specified in [FIPS 140-2
Implementation Guidance, §A.9 "XTS-AES Key Generation
Requirements"](https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Module-Validation-Program/documents/fips140-2/FIPS1402IG.pdf)
(p. 213; §C.I in the newer [FIPS 140-3
IG](https://csrc.nist.gov/csrc/media/Projects/cryptographic-module-validation-program/documents/fips%20140-3/FIPS%20140-3%20IG.pdf),
p. 141), citing Rogaway's *Efficient Instantiations of Tweakable
Blockciphers and Refinements to Modes OCB and PMAC* (2004), §6.
(NIST SP 800-38E, sometimes cited for this, actually has no
security-rationale section on it — just a bibliography — so the FIPS IG
is the real source, not that spec.)

**Why cryptsetup's own code describes this as "doubling."** cryptsetup
has exactly one compiled-in default key size, 256 bits, meant for
ordinary single-key ciphers like `aes-cbc-essiv:sha256`. Rather than
maintaining a second default for XTS, it reuses that same 256-bit
number and multiplies it by two specifically when the chosen cipher
mode is XTS — arriving at 512 bits before any key material is
generated. cryptsetup's build configuration names this literally:
`configure.ac`'s `--disable-luks-adjust-xts-keysize` option and its
`ENABLE_LUKS_ADJUST_XTS_KEYSIZE` macro are both documented in the
source as *"XTS mode requires two keys, double default LUKS keysize if
needed."* The exact code doing this arithmetic is in the next section
([Where key length actually comes from, per code](#where-key-length-actually-comes-from-per-code)) —
flagging the word "doubling" here so it's read correctly: it's
cryptsetup's default-selection *code* doubling a shared constant, not a
smaller 256-bit key getting padded out into 512 bits after generation.

None of this is a fixed rule, though — it's just cryptsetup's default
when you don't pass `--key-size`. 32 bytes (256-bit, a single key, no
doubling) is also a real, common value — it's the exact figure the
LUKS2 spec's own worked example uses, for a cipher mode that only needs
one key. This document uses 32 bytes for its worked example purely
because it's a familiar round number; nothing below depends on that
specific length.

#### Where key length actually comes from, per code

There are three separate layers here, and conflating them produces
exactly the kind of "32 bytes is standard" overstatement this section
just corrected. Each layer's actual behavior, cited directly:

1. **LUKS2 on-disk format**: imposes no fixed key length. Each keyslot's
   JSON metadata carries its own `key_size` (bytes) field, and different
   keyslots on the same volume are explicitly allowed to hold
   different-sized keys (LUKS2 On-Disk Format Specification v1.1.4,
   [`docs/on-disk-format-luks2.pdf`](https://gitlab.com/cryptsetup/cryptsetup/-/raw/main/docs/on-disk-format-luks2.pdf),
   §3.2/§4.2). The format's only real constraint is an upper storage
   bound (`LUKS_MAX_KEYSLOT_SIZE` in `lib/luks1/luks.h`), not a specific
   length.
2. **Kernel / dm-crypt**: cryptsetup does not hardcode a table of
   "cipher X accepts key sizes Y" — the man page says so outright
   (`man/cryptsetup.8.adoc`, "Supported ciphers, modes, hashes and key
   sizes" section): *"The available combinations of ciphers, modes,
   hashes and key sizes depend on kernel support. See /proc/crypto for a
   list of available options."* Concretely, `crypt_check_cipher()`
   (`lib/utils.c`) doesn't consult a lookup table at all — it generates
   a random key of the requested length and actually attempts the
   cipher via `crypt_storage_init()`/`crypt_storage_decrypt()`, and
   rejects `luksFormat` only if that live attempt fails. The kernel
   crypto API is the real source of truth, not cryptsetup.
3. **cryptsetup's CLI convenience default**: the *only* place a
   specific number gets chosen automatically is when you run
   `luksFormat` without `--key-size`. That path is
   `get_adjusted_key_size()` in `src/utils_luks.c`:

   ```c
   int get_adjusted_key_size(const char *cipher, const char *cipher_mode, uint32_t keysize_bits,
                 uint32_t default_size_bits, int integrity_keysize)
   {
   #if ENABLE_LUKS_ADJUST_XTS_KEYSIZE
       if (!keysize_bits && (!strncmp(cipher_mode, "xts-", 4) || !strncmp(cipher, "capi:xts(", 9))) {
           if (default_size_bits == 128)
               keysize_bits = 256;
           else if (default_size_bits == 256)
               keysize_bits = 512;
       }
   #endif
       return (keysize_bits ?: default_size_bits) / 8 + integrity_keysize;
   }
   ```

   In words: only fires if you didn't pass `--key-size` (`!keysize_bits`)
   *and* the mode string literally starts with `"xts-"` (or is a
   `capi:xts(...)` spec) — then it doubles the compiled-in
   `default_size_bits` (256 → 512 bits). Any other mode (`cbc-essiv:...`,
   `adiantum-plain64`, etc.) skips this branch entirely and just uses
   `default_size_bits` (256 bits / 32 bytes) as-is. Source:
   [`src/utils_luks.c`](https://gitlab.com/cryptsetup/cryptsetup/-/blob/9b560a0d4948cde06a1a961813ee3c01264a185f/src/utils_luks.c#L141-150)
   (pinned commit `9b560a0d`, verified 2026-08-16).

Concretely, for common `--cipher` choices with no explicit
`--key-size`:

| `--cipher` value | Mode matches `xts-`? | Doubling applies? | Resulting key |
|---|---|---|---|
| `aes-xts-plain64` (the default) | yes | yes | 512 bit / 64 bytes |
| `serpent-xts-plain64` | yes | yes | 512 bit / 64 bytes |
| `twofish-xts-plain64` | yes | yes | 512 bit / 64 bytes |
| `aes-cbc-essiv:sha256` | no | no | 256 bit / 32 bytes |
| `aes-adiantum-plain64` | no (mode is `adiantum`, not `xts-...`) | no | 256 bit / 32 bytes |

All five rows assume the compiled-in `default_size_bits` of 256 was left
untouched at build time — this table describes the *default-selection*
logic, not a hard limit; `--key-size` overrides it for any cipher, and
whatever value results still has to pass the live
`crypt_check_cipher()` test against the running kernel.

#### The keyslot JSON object, sketched

`key_size` doesn't float free in the JSON — it's one field inside a
specific nested structure. Every field below is mandatory unless marked
`optional`; this is the `luks2`-type keyslot object shape (source: LUKS2
On-Disk Format Specification v1.1.4, §3.2–3.2.5, same PDF as above):

```
keyslots["<N>"]                         <- keyslot, keyed by slot number as a string
├── type            "luks2"
├── key_size        <int, bytes>        <- the field this document keeps citing
├── priority        <int, optional>     <- 0=ignore, 1=normal, 2=high
├── af { }                              <- anti-forensic splitting parameters
│   ├── type        "luks1"             <- only luks1-style AF is currently used
│   ├── stripes     <int>               <- only 4000 is supported ("historical reasons")
│   └── hash        <string>            <- diffuse()'s hash, e.g. "sha256"
├── area { }                            <- where the AF-striped data physically lives
│   ├── type        "raw"               <- only "raw" is valid for luks2 keyslots
│   ├── offset      <string-uint64>     <- byte offset from device start
│   ├── size        <string-uint64>     <- this is what inspect-keyslot's "Area length" is
│   ├── encryption  <string>            <- dm-crypt cipher spec, e.g. "aes-xts-plain64"
│   └── key_size    <int, bytes>        <- area-encryption key size (normally == keyslot key_size)
└── kdf { }                             <- how your passphrase becomes the area-encryption key
    ├── type        "argon2i" | "argon2id" | "pbkdf2"
    ├── salt        <base64>
    ├── time        <int>               <- argon2 only
    ├── memory      <int, KB>           <- argon2 only
    ├── cpus        <int>               <- argon2 only
    ├── hash        <string>            <- pbkdf2 only
    └── iterations  <int>               <- pbkdf2 only
```

Two `key_size` fields exist at different nesting depths (top-level
`keyslots["N"].key_size` and `keyslots["N"].area.key_size`) — the spec
describes them as normally equal, but they're formally separate fields:
one is "the key size stored in keyslot," the other is "the area
encryption key size." Cross-checked against actual field validation in
cryptsetup source, `LUKS2_keyslot_validate()` in
[`lib/luks2/luks2_json_metadata.c`](https://gitlab.com/cryptsetup/cryptsetup/-/blob/main/lib/luks2/luks2_json_metadata.c)
requires `key_size` (as `json_type_int`) directly on every keyslot
object, and separately requires the nested `area` object to exist —
matching the spec's mandatory-fields list above, not just documented
prose.

#### A real example, from the spec itself

This isn't a hand-built illustration — it's the LUKS2 On-Disk Format
Specification's own worked example (§3.1, full header for an
AES-XTS-encrypted device with two keyslots), quoted verbatim except for
re-indentation:

```json
{
  "keyslots": {
    "0": {
      "type": "luks2",
      "key_size": 32,
      "af": {
        "type": "luks1",
        "stripes": 4000,
        "hash": "sha256"
      },
      "area": {
        "type": "raw",
        "encryption": "aes-xts-plain64",
        "key_size": 32,
        "offset": "32768",
        "size": "131072"
      },
      "kdf": {
        "type": "argon2i",
        "time": 4,
        "memory": 235980,
        "cpus": 2,
        "salt": "z6vz4xK7cjan92rDA5JF8O6Jk2HouV0O8DMB6GlztVk="
      }
    },
    "1": {
      "type": "luks2",
      "key_size": 32,
      "af": {
        "type": "luks1",
        "stripes": 4000,
        "hash": "sha256"
      },
      "area": {
        "type": "raw",
        "encryption": "aes-xts-plain64",
        "key_size": 32,
        "offset": "163840",
        "size": "131072"
      },
      "kdf": {
        "type": "pbkdf2",
        "hash": "sha256",
        "iterations": 1774240,
        "salt": "vWcwY3rx2fKpXW2Q6oSCNf8j5bvdJyEzB6BNXECGDsI="
      }
    }
  }
}
```

(The full spec example also includes `tokens`, `segments`, `digests`,
and `config` top-level objects — trimmed here to just `keyslots` since
that's this document's subject. See
[`luks2-header-anatomy.md#the-json-metadata-area`](luks2-header-anatomy.md#the-json-metadata-area)
for the other top-level objects.)

Notice this example's two keyslots use **different KDF types** (slot 0:
`argon2i`; slot 1: `pbkdf2`) but the **same `key_size`: 32** — this is
exactly the "different keyslots can use different parameters, but
happen to share a key length here" case, not evidence that 32 is fixed.
Change `--cipher` to something in the "doubling applies" rows of the
table above and both `key_size` fields (top-level and `area.key_size`)
would read `64` instead, with no other structural change.

That's the full answer to "what is *N*": it's `key_size` from a real
keyslot, and it's commonly 32 or 64 bytes depending on cipher choice —
32 being both the spec's own example value and a familiar round number.
The rest of this document picks **N = 32 bytes** wherever a concrete
key size is needed (the algorithm walkthrough next, then the fully
worked toy example further down); nothing about AF-splitting's
structure or the corruption arguments later in this document depends on
which of those two common values you have on a real device — only the
*number* of stripes and the *size* of each stripe scale with it, not the
underlying logic.

## The real algorithm, in plain English

This describes the actual algorithm implemented in `cryptsetup`'s
`lib/luks1/af.c` (function names `AF_split`, `AF_merge`, and their
`diffuse`/`hash_buf` helpers; unchanged in LUKS2, which reuses the LUKS1
AF-splitter as-is) — unaltered, just narrated in words before you see it
in bytes. Source, so you can check this yourself rather than take the
narration on faith:
[`lib/luks1/af.c` at commit `fb6b9480`](https://gitlab.com/cryptsetup/cryptsetup/-/blob/fb6b9480fa519c70366d6743ec84cb0f3afcc8c7/lib/luks1/af.c)
(pinned to a specific commit so this link doesn't rot if upstream later
refactors the file; verified 2026-08-15 that `AF_split`/`AF_merge`/
`diffuse`/`hash_buf` at that commit are byte-for-byte what's described
below).

Before the code: what's `diffuse`, structurally, before you see how it
hashes? It's a function that takes the accumulator buffer (same size as
the key — for real LUKS2, 32+ bytes) and scrambles it, using a hash
function, in a way that's easy to redo (merge needs to reproduce the
exact same scramble) but impossible to invert without the accumulator's
prior value. One detail matters for the worked example below: **a hash
function only processes one digest-sized block at a time** (SHA-256's
digest is 32 bytes), so if the accumulator is *larger* than one digest,
`diffuse` chops it into digest-sized blocks and hashes each block
separately — mixing in that block's own position (`0`, `1`, `2`, ...) as
part of the hash input, so block 0 and block 1 of the same buffer hash
differently even if their raw bytes happened to match. That per-block
hash step is `hash_buf`, shown below. (The toy example further down uses
a 2-byte accumulator — smaller than one SHA-256 digest — so it only ever
has *one* block and never exercises this chopping step. Flagged again
where it matters, in
[Mapping the toy example back to real LUKS2](#mapping-the-toy-example-back-to-real-luks2).)

```c
static int hash_buf(const char *src, char *dst, uint32_t iv,
		    size_t len, const char *hash_name)
{
	struct crypt_hash *hd = NULL;
	char *iv_char = (char *)&iv;
	int r;

	iv = be32_to_cpu(iv);
	if (crypt_hash_init(&hd, hash_name))
		return -EINVAL;
	if ((r = crypt_hash_write(hd, iv_char, sizeof(uint32_t))))
		goto out;
	if ((r = crypt_hash_write(hd, src, len)))
		goto out;
	r = crypt_hash_final(hd, dst, len);
out:
	crypt_hash_destroy(hd);
	return r;
}
```

— i.e. each block's hash input is the block's own index (`iv`, as a
big-endian 32-bit integer) followed by the block's bytes. That index
mix-in is the concrete mechanism behind "the block's position is part
of what gets hashed," mentioned above. `hash_buf` itself doesn't decide
how many blocks there are — that's `diffuse`, which calls it once per
digest-sized block:

```c
static int diffuse(char *src, char *dst, size_t size, const char *hash_name)
{
	int r, hash_size = crypt_hash_size(hash_name);
	unsigned int digest_size;
	unsigned int i, blocks, padding;

	if (hash_size <= 0)
		return -EINVAL;
	digest_size = hash_size;

	blocks = size / digest_size;
	padding = size % digest_size;

	for (i = 0; i < blocks; i++) {
		r = hash_buf(src + digest_size * i,
			    dst + digest_size * i,
			    i, (size_t)digest_size, hash_name);
		if (r < 0)
			return r;
	}

	if (padding) {
		r = hash_buf(src + digest_size * i,
			    dst + digest_size * i,
			    i, (size_t)padding, hash_name);
		if (r < 0)
			return r;
	}

	return 0;
}
```

This confirms the claim above precisely: `blocks = size / digest_size`
whole blocks, each hashed with index `i` via `hash_buf`, plus one final
short call for any remainder (`padding`). For a 32-byte accumulator with
SHA-256 (32-byte digest), `blocks = 1` and `padding = 0` — exactly one
`hash_buf` call, index `0`. That's the case the toy example (and real
256-bit LUKS2 keys) land in; a larger accumulator would mean `blocks > 1`
and multiple indexed calls, as described above. `struct crypt_hash` and
`crypt_hash_init`/`_write`/`_final`/`_destroy` are not part of
AF-splitting itself — they're cryptsetup's internal wrapper around
whichever real crypto library it's built against (OpenSSL, gcrypt, NSS,
or the kernel crypto API), so this code can call a generic "hash
something" API without caring which backend is compiled in. The opaque
type is declared in
[`lib/crypto_backend/crypto_backend.h`](https://gitlab.com/cryptsetup/cryptsetup/-/blob/fb6b9480fa519c70366d6743ec84cb0f3afcc8c7/lib/crypto_backend/crypto_backend.h#L28-49);
the OpenSSL backend's concrete definition (a thin wrapper around
`EVP_MD_CTX`) is in
[`lib/crypto_backend/crypto_openssl.c`](https://gitlab.com/cryptsetup/cryptsetup/-/blob/fb6b9480fa519c70366d6743ec84cb0f3afcc8c7/lib/crypto_backend/crypto_openssl.c#L55-57).
Nothing about that indirection changes the algorithm — skip it if you
just want the data flow.

**Splitting** a key into N stripes, pictured first, then as steps. Read
top to bottom — `buf` is the one accumulator, updated in place at each
row:

```
buf = 00...00                        (all-zero, key-sized)

stripe[0] (random)  --XOR-->  buf
                     buf = diffuse(buf)

stripe[1] (random)  --XOR-->  buf
                     buf = diffuse(buf)

        ...                         (repeat for every stripe except the last)

stripe[N-2] (random) --XOR-->  buf
                     buf = diffuse(buf)

stripe[N-1] = original_key XOR buf   (NOT random -- the real key enters
                                       only here, XORed with the final buf)
```

1. Start with an all-zero "accumulator" buffer, the same size as the key.
2. For each stripe *except the last* (stripes `0` through `N-2`):
   a. Generate a stripe's worth of **cryptographically random bytes** —
      call this the random stripe. Write it to the output.
   b. XOR the random stripe into the accumulator.
   c. Run the accumulator through a **diffusion function** (`diffuse`,
      built from repeated hashing — SHA-256 by default) and replace the
      accumulator with the result.
3. The **final stripe** (stripe `N-1`) is not random at all: it's the
   original key XORed with whatever the accumulator holds after all
   those rounds.

**Merging** stripes back into the key reverses this exactly — same
pipeline, read the diagram above top-to-bottom again, except the last
step is an XOR *out* instead of *in*:

1. Start with the same all-zero accumulator.
2. For each stripe *except the last*, in the same order: XOR it into the
   accumulator, then diffuse the accumulator — identical to the split
   process, because the merge side needs to reconstruct the exact same
   accumulator value the split side had.
3. XOR the final stripe with the (now fully reconstructed) accumulator.
   The result is the original key.

The mixing-in-of-position inside `diffuse` (the `iv`/block-index in
`hash_buf`, above) is what a cryptsetup source comment calls
"anti-forensic" — combined with the XOR chain above, it's specifically
what guarantees a partial stripe set carries no information (see
[Why this makes corruption unrecoverable](#why-this-makes-corruption-unrecoverable-three-demonstrations)
for what "no information" means concretely, not just asserted).

Notice what's *not* here: there's no encryption key involved in
AF-splitting itself, and no secret parameter beyond the original key
being split. `diffuse`'s hash function is public, the stripe count is
public, the algorithm is public — none of that matters, because the
security property doesn't come from hiding the mechanism. It comes from
the accumulator being **built incrementally from stripes you don't have
all of**, so reconstructing it requires the full ordered set.

## A worked example you can trace by hand

Real LUKS2 uses SHA-256 as the diffusion hash and 4000 stripes over a
key whose length depends on the cipher chosen at `luksFormat` time
(commonly 256-bit/32-byte or 512-bit/64-byte — see the previous section)
— utterly infeasible to trace by hand either way, and that's the point
(see
[Mapping the toy example back to real LUKS2](#mapping-the-toy-example-back-to-real-luks2)).
To actually *see* the algorithm's structure work, this section uses a toy
version: a 2-byte "key," 3 stripes, and a fake, non-cryptographic stand-in
for the diffusion hash that you can compute with addition instead of
SHA-256:

```
toy_diffuse(block, index) = each byte of block, plus (index + 1), mod 256
```

**This toy hash has zero cryptographic value** — it's linear, invertible,
and has none of SHA-256's avalanche or one-way properties. It exists
purely so the arithmetic in this section is checkable with a calculator.
Every structural step (the XOR chain, the accumulator, the loop order)
is otherwise identical to the real algorithm.

Toy setup:

- **Key to split** (`src`): `a5 3c` (2 bytes)
- **Stripe count** (`N`): 3
- **"Random" stripes**: normally a CSPRNG; for a reproducible worked
  example, fixed here to `11 22` and `77 88`

### Splitting the key

Start: accumulator (`buf`) = `00 00` (all zero, same size as the key).

**Stripe 0** (not the last stripe, so: random + XOR + diffuse):

```
random stripe[0]     = 11 22        <- written to disk as-is
buf = stripe[0] XOR buf_prev
    = 11 22  XOR  00 00
    = 11 22
buf = toy_diffuse(buf, index=0)
    = (0x11 + 1) mod 256, (0x22 + 1) mod 256
    = 12 23
```

**Stripe 1** (also not the last):

```
random stripe[1]     = 77 88        <- written to disk as-is
buf = stripe[1] XOR buf_prev
    = 77 88  XOR  12 23
    = 65 ab
buf = toy_diffuse(buf, index=0)      (diffuse restarts its own internal
                                       block index at 0 each call - this
                                       is a fresh diffuse() call, not a
                                       continuation)
    = (0x65 + 1) mod 256, (0xab + 1) mod 256
    = 66 ac
```

**Stripe 2** (the *last* stripe — no randomness, this is where the real
key gets folded in):

```
stripe[2] = src XOR buf
          = a5 3c  XOR  66 ac
          = c3 90
```

**What actually gets written to the keyslot's `area` on disk:**

```
stripe[0]  stripe[1]  stripe[2]
┌───────┐ ┌───────┐  ┌───────┐
│ 11 22 │ │ 77 88 │  │ c3 90 │      6 bytes total, laid out
└───────┘ └───────┘  └───────┘      end-to-end in `area`
 random     random    key XOR buf
```

Notice: none of these three stripes, read individually, look like `a5 3c`
or reveal anything about it. `stripe[0]` and `stripe[1]` are pure
randomness by construction. `stripe[2]` is the key XORed with an
accumulator value that itself depends on both prior random stripes —
without them, `stripe[2]` alone is indistinguishable from random noise
too.

### Merging the stripes back

Given all three stripes, reconstruction replays the identical
accumulation:

```
buf = 00 00                                    (start over, same as split)

buf = stripe[0] XOR buf  = 11 22 XOR 00 00 = 11 22
buf = toy_diffuse(buf, 0) = 12 23

buf = stripe[1] XOR buf  = 77 88 XOR 12 23 = 65 ab
buf = toy_diffuse(buf, 0) = 66 ac

recovered = stripe[2] XOR buf
          = c3 90  XOR  66 ac
          = a5 3c                               <- back to the original key
```

`a5 3c` — the merge exactly reverses the split. This isn't a coincidence
of the toy numbers; it's guaranteed by construction, because merge
replays the exact same accumulator-building steps split used, then
undoes the final XOR.

## Why this makes corruption unrecoverable: three demonstrations

These three cases are what actually happens (traced through the same toy
algorithm above) when a keyslot area is damaged — not just asserted, but
shown:

**1. Flip one bit in the *first* stripe, then merge:**

```
stripe[0]: 11 22  ->  10 22   (low bit flipped)
```

Redoing the merge with this corrupted `stripe[0]`:

```
buf = 10 22 XOR 00 00 = 10 22
buf = toy_diffuse(buf, 0) = 11 23

buf = 77 88 XOR 11 23 = 66 ab
buf = toy_diffuse(buf, 0) = 67 ac

recovered = c3 90 XOR 67 ac = a4 3c
```

`a4 3c`, not `a5 3c` — wrong, and not *close* to right in any meaningful
sense (with a real cryptographic hash instead of the toy addition, one
flipped input bit flips roughly half the output bits at each diffusion
step, so the error doesn't stay localized to one byte — it's total
garbage, not a small offset you could search around).

**2. Flip one bit in the *last* stripe instead:**

```
stripe[2]: c3 90 -> c2 90
recovered = c2 90 XOR 66 ac = a4 3c
```

Also wrong. It doesn't matter which stripe gets damaged — first, last, or
anywhere between — because every stripe participates in either building
the accumulator or the final XOR. There is no "less important" stripe.

**3. Lose a whole stripe (simulating a truncated write or zeroed
region):**

Merging with only `stripe[0]` and `stripe[1]` present (as if `stripe[2]`
were missing, or the reader assumed the wrong stripe count) doesn't
produce a "close but short" answer — it doesn't even correspond to a
coherent operation. `AF_merge` needs to know `N` (the stripe count) up
front to know which stripe is "last" and treated as the XOR target rather
than an accumulator input; get that count wrong — which happens
automatically if the `area` region is truncated — and you're not
recovering a damaged key, you're computing an unrelated value from
mismatched inputs. In real `cryptsetup`, the expected stripe count comes
from the keyslot's own JSON metadata (`af.stripes`, see
[`luks2-header-anatomy.md#the-json-metadata-area`](luks2-header-anatomy.md#the-json-metadata-area)),
so a truncated `area` region is generally caught as a structural
mismatch before merge is even attempted — but the underlying reason it
*can't* work is the same: partial stripe data is not partial key data,
it's not key data at all.

## Mapping the toy example back to real LUKS2

Real LUKS2 differs from the toy example in four ways, all of which make
the anti-forensic property *stronger*, not different in kind:

- **SHA-256 instead of toy addition.** SHA-256 is a real one-way hash
  with strong avalanche behavior — changing a single input bit changes
  roughly half the output bits, unpredictably. The toy hash's `+1 mod
  256` is trivially invertible (subtract 1) and was chosen purely so the
  worked example above is checkable by hand; it is not standing in for
  SHA-256's actual security properties, only its role in the algorithm's
  data flow.
- **4000 stripes instead of 3.** More rounds of the same accumulator
  chain — the structure is identical, just repeated thousands of times.
  This is `af.stripes` in the keyslot's JSON metadata (see
  [`luks2-header-anatomy.md#the-json-metadata-area`](luks2-header-anatomy.md#the-json-metadata-area)).
- **A 256-bit (or larger) key instead of 2 bytes**, and correspondingly
  larger stripes — this is why a keyslot's `Area length` is so much
  bigger than the master key itself (see
  [`luks2-header-anatomy.md#reading-area-offset--area-length`](luks2-header-anatomy.md#reading-area-offset--area-length)):
  4000 stripes of a 32-byte key is 128,000 bytes, not 32.
- **`diffuse` chops the accumulator into digest-sized blocks — the toy
  example never does this.** The toy accumulator is 2 bytes, smaller
  than a single SHA-256 digest (32 bytes), so every `toy_diffuse` call
  above hashed (added-to, really) exactly one block. Real LUKS2's
  accumulator is also key-sized (32+ bytes) but SHA-256's digest is also
  32 bytes, so for a 256-bit key the accumulator still happens to fit in
  one block; for a *larger* key (e.g. a 512-bit key from a different
  cipher configuration) `diffuse` would chop the accumulator into
  multiple 32-byte blocks and hash each one separately with its own
  block index, mixing them back together. The toy example's single-XOR,
  single-hash-call structure per stripe is accurate for a 256-bit key;
  it undersells what `diffuse` does for anything larger. See
  [The real algorithm, in plain English](#the-real-algorithm-in-plain-english)
  for where this chopping step lives in the real code (`hash_buf`,
  called once per block by `diffuse`).

None of these differences change the *shape* of the argument in the
[three demonstrations](#why-this-makes-corruption-unrecoverable-three-demonstrations)
above — they only make the real thing more thoroughly unrecoverable when
damaged, since SHA-256's avalanche effect means a single flipped bit
corrupts the *entire* subsequent accumulator chain, not just nearby
bytes.

## What this means when you're inspecting a keyslot

Tying this back to the practical side
([`checking-for-corruption.md`](checking-for-corruption.md)):

- **A healthy keyslot `area` looks like uniform random noise** — because,
  per stripe, it either *is* literally random (every stripe except the
  last) or is XORed against something that's cryptographically
  indistinguishable from random (the last stripe). You cannot eyeball
  "correct" vs. "gibberish" by looking at entropy alone — both look
  identical. What you *can* spot is structural damage: long zero-runs,
  repeating patterns, truncation — things real random data doesn't
  produce (see
  [`checking-for-corruption.md#what-corrupted-key-material-looks-like`](checking-for-corruption.md#what-corrupted-key-material-looks-like)).
- **There is no partial recovery.** Not "harder," not "needs more
  compute" — the three demonstrations above show mechanically why even a
  single flipped bit, anywhere in any stripe, produces an unrelated
  result, not a close one. `cryptsetup repair` cannot help here (see
  [`checking-for-corruption.md#when-to-run-cryptsetup-repair-and-what-it-cant-fix`](checking-for-corruption.md#when-to-run-cryptsetup-repair-and-what-it-cant-fix))
  because there's no structural inconsistency to resolve — the stripe
  data is either bit-for-bit intact or the key is gone, and `repair`
  operates one level up, on the JSON metadata that *describes* the
  keyslot, not on the keyslot's key material itself.
- **This is why `luksHeaderBackup` matters before any exploratory work.**
  A backup taken before damage occurred has the intact stripes; nothing
  computed from the damaged region afterward can substitute for them.
