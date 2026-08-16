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

LUKS2 doesn't mandate a single master-key length — it's whatever the
cipher and key size chosen at `luksFormat` time require, recorded per
keyslot as `key_size` (in bytes) in the keyslot's own JSON metadata (see
[`luks2-header-anatomy.md#the-json-metadata-area`](luks2-header-anatomy.md#the-json-metadata-area)).
`cryptsetup`'s own compiled-in default cipher is `aes-xts-plain64`,
which needs a 512-bit (64-byte) volume key by construction — not
because cryptsetup pads or doubles a smaller key, but because an
XTS-mode key *is* two independent, equal-length AES keys concatenated
end to end (`key1 || key2`; each half is a full, separate AES-256 key
here, not half an AES-256 key). One half encrypts the actual data
block; the other half encrypts a per-sector "tweak" value that gets
mixed in before and after the main encryption (the XEX construction —
XOR-Encrypt-XOR). Confirmed directly in the Linux kernel's XTS
implementation, which is what dm-crypt (and therefore LUKS2) actually
calls at unlock time:

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
(`crypto/xts.c`, `xts_setkey()`, Linux kernel source —
[`crypto/xts.c` on kernel.org's git mirror](https://github.com/torvalds/linux/blob/master/crypto/xts.c),
verified 2026-08-16; `xts_verify_key()`, called just above, actively
*rejects* a key whose two halves are equal — using the same key twice
is a real, documented weakness in XTS, not just wasteful. NIST SP
800-38E itself doesn't discuss this (it only has a bibliography
appendix, no security-rationale annex); the actual requirement and its
justification live in
[FIPS 140-2 Implementation Guidance, §A.9 "XTS-AES Key Generation
Requirements"](https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Module-Validation-Program/documents/fips140-2/FIPS1402IG.pdf)
(p. 213; renumbered to §C.I under the newer [FIPS 140-3
IG](https://csrc.nist.gov/csrc/media/Projects/cryptographic-module-validation-program/documents/fips%20140-3/FIPS%20140-3%20IG.pdf),
p. 141) — verbatim: *"An implementation of XTS-AES that improperly
generates Key so that Key_1 = Key_2 is vulnerable to a chosen
ciphertext attack... by obtaining the decryption of only one chosen
ciphertext block in a given data sector, an adversary who does not
know the key may be able to manipulate the ciphertext in that sector so
that one or more plaintext blocks change to any desired value... The
module shall check explicitly that Key_1 ≠ Key_2."* That IG cites the
underlying attack to Rogaway, *Efficient Instantiations of Tweakable
Blockciphers and Refinements to Modes OCB and PMAC* (2004), §6, and to
IEEE Std 1619-2007 Annex D §D.4.3 (pp. 31–32) for why XTS-AES departs
from the generic XEX construction on this point. So `--cipher aes-xts-plain64`
with no `--key-size` needs 512 bits total specifically because a
256-bit *tweak* key and a 256-bit *data* key both have to exist and be
independent — there's no smaller "real" master key underneath that gets
inflated; the 512-bit value *is* the pair.

cryptsetup encodes this as a doubling rule relative to a *different*
cipher's expectation, because its internal default-size constant
(`default_size_bits`) is shared across cipher families and represents
"AES-256, single key" — the natural default for non-XTS modes like
`aes-cbc-essiv:sha256`, which only ever need one key. For XTS
specifically, that shared 256-bit constant is doubled to 512 bits so
the result is still "AES-256, but XTS's two-key shape" rather than
silently downgrading XTS to two AES-128 keys. See
[Where key length actually comes from, per code](#where-key-length-actually-comes-from-per-code)
for the exact code path. 32 bytes (256-bit) is a real, common value too
— it's the exact figure used in the LUKS2 on-disk format spec's own
worked example, for a *single*-key mode — just not a fixed universal
constant. This document uses 32 bytes purely because it's a familiar
round number; nothing below depends on that specific length.

### Where key length actually comes from, per code

There are three separate layers here, and conflating them produces
exactly the kind of "32 bytes is standard" overstatement this section
just corrected. (Layer 3 below talks about cryptsetup "doubling" a
256-bit default to 512 bits for XTS — that's describing the code's own
arithmetic, not implying a smaller 256-bit key gets padded; per the
explanation above, the 512-bit result is two full, independent 256-bit
keys from the start.) Each layer's actual behavior, cited directly:

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

### The keyslot JSON object, sketched

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

### A real example, from the spec itself

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

Whatever the actual length, the problem AF-splitting solves is the same:
if that key were written to disk as-is (even encrypted under your
passphrase-derived key), an attacker who recovers even a small
*fragment* of that region — from wear-leveling remnants on an SSD, a
bad-block remap, filesystem journal residue, whatever — has a fragment
of the actual key. Not the whole key, but a real, meaningful piece of
it, which measurably narrows a brute-force search.

AF-splitting's job is to take that 32-byte key and expand it into many
"stripes" (4000, by default) such that:

- All 4000 stripes, in order, are needed to reconstruct the original key.
- Any subset smaller than all 4000 — even 3999 of them — reveals
  **nothing** about the key. Not "a little less secure," not "narrows the
  search space slightly." Nothing, in the same sense that XORing a secret
  with one unknown random byte reveals nothing about the secret.

That second property is the interesting part, and it's not automatic —
you get it from a specific construction, not from "spread the data out
and hope." The rest of this document is that construction.

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
