# AF-Splitting, Explained From First Principles

This is a slow, beginner-friendly walkthrough of anti-forensic (AF)
splitting — the algorithm covered at a higher level in
[`luks2-header-anatomy.md#af-splitting-anti-forensic-splitting`](luks2-header-anatomy.md#af-splitting-anti-forensic-splitting).
That section explains *what* AF-splitting is for. This document exists to
explain *how it actually works*, byte by byte, so that when you're staring
at a hex dump wondering whether a keyslot is corrupted, you understand
mechanically why the answer is "yes, unrecoverably" rather than taking it
on faith.

The anatomy doc's AF-splitting section summarizes what AF-splitting is
for: making a deleted keyslot unrecoverable even if part of it survives
the overwrite. The next section states that purpose in detail, with
sources, including where it falls short; the rest of this document
covers how the algorithm works.

## Contents

- [The problem AF-splitting solves, restated concretely](#the-problem-af-splitting-solves-restated-concretely)
- [The key being split](#the-key-being-split)
  - [Why the default key is 512 bits](#why-the-default-key-is-512-bits)
  - [Where the key length comes from, per code](#where-the-key-length-comes-from-per-code)
  - [The keyslot JSON object, sketched](#the-keyslot-json-object-sketched)
  - [A real example, from the spec itself](#a-real-example-from-the-spec-itself)
- [The real algorithm, in plain English](#the-real-algorithm-in-plain-english)
- [A worked example you can trace by hand](#a-worked-example-you-can-trace-by-hand)
  - [Splitting the key](#splitting-the-key)
  - [Merging the stripes back](#merging-the-stripes-back)
- [What is written to disk](#what-is-written-to-disk)
  - [How a wrong key is detected](#how-a-wrong-key-is-detected)
- [What damage does to the key](#what-damage-does-to-the-key)
  - [From damaged stripes to the key](#from-damaged-stripes-to-the-key)
  - [From damaged ciphertext to stripes](#from-damaged-ciphertext-to-stripes)
  - [What this means for recovery](#what-this-means-for-recovery)
- [Mapping the toy example back to real LUKS2](#mapping-the-toy-example-back-to-real-luks2)
- [What this means when you're inspecting a keyslot](#what-this-means-when-youre-inspecting-a-keyslot)

## The problem AF-splitting solves, restated concretely

Each keyslot stores a copy of the volume's master key, encrypted under
a key derived from that keyslot's passphrase. Removing or changing a
passphrase therefore means destroying that encrypted copy. If it
survives anywhere on the device, anyone who knows the old passphrase
can still decrypt it and recover the master key, and a leaked
passphrase is often exactly why it is being removed. The LUKS2
specification requires the keyslot's binary area to be "physically
overwritten (to discard the stored data)" before its metadata is
removed
([LUKS2 spec v1.1.4](https://gitlab.com/cryptsetup/LUKS2-docs/-/blob/a81aa2fef8d176debdbec297c1e0b74bb50cfee8/luks2_doc_wip.pdf)
§4.4 "Keyslot Revocation", p.14).

Overwriting a sector does not guarantee the old data is gone. When a
sector starts to fail, disk firmware remaps it to a reserved area, and
the old copy stays there, where no overwrite of the original address
can reach it. A master key is only 32 or 64 bytes with cryptsetup's
default key sizes (see [The key being split](#the-key-being-split)), so its encrypted copy
fits in a single sector and can survive such a remap whole. Fruhwirth,
who designed AF-splitting and LUKS, describes this as the problem the
splitter solves: encrypted key material "is typically very short and
can be accommodated by a single sector in a reserved remapping zone"
([*New Methods in Hard Disk Encryption*, 2005](https://clemens.endorphin.org/nmihde/nmihde-A4-ds.pdf)
§5.2.1, pdf p.87–88). The
[LUKS1 specification](https://gitlab.com/cryptsetup/cryptsetup/-/blob/bae21790d59897ac50e5471f953f76b3a58aeeb6/docs/on-disk-format.pdf)
makes the same argument (§1, p.3): the key "can easily be remapped as
a whole to a reserved area".

AF-splitting addresses this by making the stored copy large. It
expands an *N*-byte key into 4000 stripes of *N* bytes each, 4000 × *N*
bytes in total (LUKS1 spec §2.4, p.4; LUKS2 supports no other stripe
count: "for historical reasons only the 4000 value is supported",
LUKS2 spec §3.2.4, p.10), and the key can only be reconstructed from
all of them. Fruhwirth's argument is probabilistic (§5.2.2, pdf p.88):
if each block of data is destroyed by an overwrite with probability
*p*, independently of the others, all *n* blocks survive with
probability (1 − *p*)ⁿ, which shrinks
exponentially as *n* grows. Overwriting a large split keyslot
therefore destroys at least one necessary piece with high probability,
even when some sectors escape the overwrite.

Exactly what reconstruction needs follows from cryptsetup's
`AF_split()` and `AF_merge()`
([`lib/luks1/af.c`](https://gitlab.com/cryptsetup/cryptsetup/-/blob/fb6b9480fa519c70366d6743ec84cb0f3afcc8c7/lib/luks1/af.c#L91-139),
lines 91–139), traced step by step later in this document:

- Every stripe is needed. If any whole stripe is missing, no byte of
  the key can be computed.
- Damage to part of a stripe stays within the hash-sized chunk of the
  key it lines up with. Each of stripes 1 to 3999 is XORed into a
  running accumulator, and the accumulator is then passed through
  `diffuse()` (`af.c` lines 108–109 when splitting, 133–134 when
  merging). `diffuse()` (lines 54–84) cuts the accumulator into chunks
  the size of the hash digest (32 bytes for SHA-256) and replaces each
  chunk with the hash of its index and that chunk alone, so a changed
  byte scrambles its own chunk and leaves every other chunk unchanged. With a 64-byte key and SHA-256, damage to one byte of stripes
  1 to 3999 changes one half of the key and leaves the other half
  intact.
- The last stripe is not diffused at all. It is XORed with the
  accumulated result directly (`af.c` line 114 when splitting, line
  138 when merging), so damage to part of it changes only the matching
  bytes of the key. Fruhwirth notes this trade-off: "The diffusion of
  s*n* has to be omitted, as the hash function is not invertible. This
  degrades security marginally" (§5.2.2, pdf p.89).

The chunk-by-chunk diffusion is not what Fruhwirth designed. His thesis
builds the diffusion function so that every output chunk hashes the
whole input, H(q) = h(0 ‖ q) ‖ h(1 ‖ q) ‖ … (§5.2.2, footnote 1,
pdf p.89). The LUKS1 specification defines that version as "H2" and
the chunk-by-chunk version LUKS actually uses as "H1", with the note
"H's function definition stems from an implementation error that I'm
responsible for … H2 is the correct hash extension as originally
envisioned" (§2.4.1–2.4.2, pp.4–5).

AF-splitting does not make keyslots erasable on flash storage. SSDs,
USB sticks, and hybrid or SMR drives redirect writes internally and
keep old data in spare pools far larger than any keyslot; the
cryptsetup FAQ gives about 16 GB of spare area for a 240 GB SSD and
concludes that "fast erase by overwriting the header and key-slot area
is insecure"
([FAQ §5.19](https://gitlab.com/cryptsetup/cryptsetup/-/blob/bae21790d59897ac50e5471f953f76b3a58aeeb6/FAQ.md#L1788-1835)).
The LUKS2 specification says the same of the splitter itself: "The
LUKS1 AF splitter is no longer much effective on modern storage
devices. The functionality is here mainly for compatibility reasons"
(§3.2.4, p.10).

The rest of this document works through the construction with a
concrete *N*, so you can trace real numbers rather than reason about
an abstract key. *N* is not a fixed size that LUKS2 defines once; it
is determined by choices made at `luksFormat` time, which the next
section traces through cryptsetup's code.

## The key being split

The key AF-splitting splits is the volume's master key: the random key
dm-crypt uses to encrypt the volume's data, generated once at
`luksFormat`. Each keyslot stores its own copy of it, split and then
encrypted under a key derived from that keyslot's passphrase. Where the
plaintext key exists in memory, and how the kernel uses it, is covered
in [`master-key-lifecycle.md`](master-key-lifecycle.md).

Its length, *N* in this document, is the keyslot's `key_size` field.
LUKS2 does not fix it: each keyslot records its own `key_size`, and
"LUKS2 keyslots can store different keys with different key sizes"
([LUKS2 spec v1.1.4](https://gitlab.com/cryptsetup/LUKS2-docs/-/blob/a81aa2fef8d176debdbec297c1e0b74bb50cfee8/luks2_doc_wip.pdf)
§3.2, p.8, and §4.2, p.14). In practice it is set by the cipher chosen
at `luksFormat` and by `--key-size`.

### Why the default key is 512 bits

With cryptsetup's default cipher, `aes-xts-plain64`, the key is 512
bits, not the 256 bits "AES-256" suggests, because XTS takes two AES
keys. One encrypts the data. The other encrypts each sector's IV to
produce the *tweak*, a value that makes each 16-byte block's encryption
depend on its position on the disk. The kernel's XTS template splits
the key it is given exactly in half:
[`crypto/xts.c`](https://github.com/torvalds/linux/blob/cae575fc09fa824900939960e33bc49b8e964d80/crypto/xts.c#L42-L75)'s
`xts_setkey()` (lines 42–75) halves the key length and keys "two cipher
instances: one to compute the initial 'tweak' by encrypting the IV
(usually the 'plain' iv) and the other one to encrypt and decrypt the
data" (comment, lines 56–58), with the tweak key taken from the second half (line 65).
So a 512-bit XTS key is two independent 256-bit AES keys side by side,
not one AES-256 key extended to 512 bits.

The two halves must differ. The FIPS 140 implementation guidance
explains why: if Key_1 = Key_2, "an adversary who does not know the
key may be able to manipulate the ciphertext in that sector so that one
or more plaintext blocks change to any desired value"
([FIPS 140-2 IG](https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Module-Validation-Program/documents/fips140-2/FIPS1402IG.pdf)
§A.9 "XTS-AES Key Generation Requirements", p.213; the same text is
§C.I "XTS-AES (SP 800-38E) Requirements on the Key" of the
[FIPS 140-3 IG](https://csrc.nist.gov/csrc/media/Projects/cryptographic-module-validation-program/documents/fips%20140-3/FIPS%20140-3%20IG.pdf),
p.156, version dated 08/19/2026). Both cite §6 of Rogaway's
[*Efficient Instantiations of Tweakable Blockciphers and Refinements
to Modes OCB and PMAC*](https://www.cs.ucdavis.edu/~rogaway/papers/offsets.pdf)
(2004), which gives the attack for the single-key construction. NIST
SP 800-38E, which approves XTS-AES, does so by reference to IEEE
1619-2007 and does not discuss this itself.

The kernel only enforces it in some configurations.
`xts_verify_key()` rejects equal halves only "when in FIPS mode or the
FORBID_WEAK_KEYS flag is set"
([`include/crypto/xts.h`](https://github.com/torvalds/linux/blob/cae575fc09fa824900939960e33bc49b8e964d80/include/crypto/xts.h#L28-L35),
lines 28–35), and dm-crypt does not set that flag (it does not appear
in [`drivers/md/dm-crypt.c`](https://github.com/torvalds/linux/blob/43fd83c0b1dc127cf13b4c05303665924e63ef94/drivers/md/dm-crypt.c)).
cryptsetup generates the key from random bytes, so equal halves are
not a practical concern for keys it creates.

### Where the key length comes from, per code

Three layers decide the key length:

1. **The LUKS2 format** records it per keyslot and fixes no value (see
   above).
2. **Cipher support** decides which lengths work. cryptsetup keeps no
   table of valid key sizes; its man page says "The available
   combinations of ciphers, modes, hashes and key sizes depend on
   kernel support" and "the configured cryptographic library must also
   support selected algorithms"
   ([`man/cryptsetup.8.adoc`](https://gitlab.com/cryptsetup/cryptsetup/-/blob/bae21790d59897ac50e5471f953f76b3a58aeeb6/man/cryptsetup.8.adoc),
   lines 538–542). When formatting, `crypt_check_cipher()`
   ([`lib/utils.c`](https://gitlab.com/cryptsetup/cryptsetup/-/blob/bae21790d59897ac50e5471f953f76b3a58aeeb6/lib/utils.c#L388-453),
   lines 388–453) tests the cipher with a random key of the requested
   length: first through cryptsetup's own crypto backend
   (`crypt_storage_init()` and `crypt_storage_decrypt()`), and, if that
   fails and cryptsetup runs as root, through the kernel's dm-crypt
   (`crypt_storage_wrapper_init()` with `CSW_DMCRYPT_ONLY`). The format
   fails only if the cipher works neither way.
3. **cryptsetup's default** picks a length when `luksFormat` runs
   without `--key-size`, in `get_adjusted_key_size()`
   ([`src/utils_luks.c`](https://gitlab.com/cryptsetup/cryptsetup/-/blob/bae21790d59897ac50e5471f953f76b3a58aeeb6/src/utils_luks.c#L142-154),
   lines 142–154):

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

   If no `--key-size` was given and the mode starts with `xts-` (or the
   cipher is a `capi:xts(...)` spec), it doubles the compiled-in
   default of 256 bits to 512; otherwise it uses 256 bits. The doubling
   is a build option: `configure.ac` describes
   `--disable-luks-adjust-xts-keysize` as "XTS mode requires two keys,
   double default LUKS keysize if needed", and enables it by default
   ([`configure.ac`](https://gitlab.com/cryptsetup/cryptsetup/-/blob/bae21790d59897ac50e5471f953f76b3a58aeeb6/configure.ac#L794-803),
   lines 794–803, which also set the default cipher `aes`, mode
   `xts-plain64` and key size 256).

The resulting key sizes, measured with cryptsetup 2.8.8 by formatting
a throwaway image with each cipher and no `--key-size`
([`experiments/default-key-sizes/`](../experiments/default-key-sizes)):

| `--cipher` | Mode starts with `xts-`? | Key size |
|---|---|---|
| `aes-xts-plain64` (the default) | yes | 512 bits / 64 bytes |
| `serpent-xts-plain64` | yes | 512 bits / 64 bytes |
| `twofish-xts-plain64` | yes | 512 bits / 64 bytes |
| `aes-cbc-essiv:sha256` | no | 256 bits / 32 bytes |
| `xchacha20,aes-adiantum-plain64` | no | 256 bits / 32 bytes |

In every case the keyslot area used the same cipher and key size as
the volume. `--key-size` overrides the default for any cipher, as long
as the result passes `crypt_check_cipher()`.

### The keyslot JSON object, sketched

`key_size` is one field of a keyslot object in the header's JSON
metadata. The shape of a keyslot of type `luks2`, from the LUKS2
specification (§3.2–3.2.5, pp.8–10); every field is mandatory unless
marked optional:

```
keyslots["<N>"]                         <- keyslot, keyed by slot number as a string
├── type            "luks2"
├── key_size        <int, bytes>        <- the size of the key stored in the keyslot
├── priority        <int, optional>     <- 0 = ignore, 1 = normal, 2 = high
├── af { }                              <- anti-forensic splitter
│   ├── type        "luks1"             <- the only AF type currently used
│   ├── stripes     <int>               <- only 4000 is supported
│   └── hash        <string>            <- diffuse()'s hash, e.g. "sha256"
├── area { }                            <- where the encrypted split key is stored
│   ├── type        "raw"               <- the only area type for luks2 keyslots
│   ├── offset      <string-uint64>     <- byte offset from the device start
│   ├── size        <string-uint64>     <- area size; inspect-keyslot's "Area length"
│   ├── encryption  <string>            <- area cipher, e.g. "aes-xts-plain64"
│   └── key_size    <int, bytes>        <- area cipher's key size
└── kdf { }                             <- turns the passphrase into the area key
    ├── type        "argon2i" | "argon2id" | "pbkdf2"
    ├── salt        <base64>
    ├── time        <int>               <- argon2 only
    ├── memory      <int, kilobytes>    <- argon2 only
    ├── cpus        <int>               <- argon2 only
    ├── hash        <string>            <- pbkdf2 only
    └── iterations  <int>               <- pbkdf2 only
```

The two `key_size` fields are separate: `keyslots["N"].key_size` is
"the key size (in bytes) stored in keyslot" (§3.2, p.8), the master
key's size, and `area.key_size` is "the area encryption key size"
(§3.2.3, p.9), the size of the passphrase-derived key that encrypts the
area. They are equal when the area uses the volume's cipher, which
cryptsetup does whenever it can (see
[What is written to disk](#what-is-written-to-disk)).

cryptsetup checks this shape in two places. `LUKS2_keyslot_validate()`
requires every keyslot to have a string `type` and an integer
`key_size` that fits in 32 bits
([`lib/luks2/luks2_json_metadata.c`](https://gitlab.com/cryptsetup/cryptsetup/-/blob/bae21790d59897ac50e5471f953f76b3a58aeeb6/lib/luks2/luks2_json_metadata.c#L418-435),
lines 418–435). The `luks2` keyslot type's own validator,
`luks2_keyslot_validate()`, requires the `kdf`, `af` and `area` objects
and the fields of each
([`lib/luks2/luks2_keyslot_luks2.c`](https://gitlab.com/cryptsetup/cryptsetup/-/blob/bae21790d59897ac50e5471f953f76b3a58aeeb6/lib/luks2/luks2_keyslot_luks2.c#L668-732),
lines 668–732); it checks that `af.stripes` is an integer, not that it
is 4000.

### A real example, from the spec itself

The LUKS2 specification's own example (§3.1, p.7), the full metadata of
an AES-XTS device with two keyslots, quoted here except for spacing and
with only the `keyslots` object:

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

The full example also has `tokens`, `segments`, `digests` and `config`
objects; see
[`luks2-header-anatomy.md#the-json-metadata-area`](luks2-header-anatomy.md#the-json-metadata-area).

The two keyslots use different KDFs (`argon2i` and `pbkdf2`) and the
same `key_size`, 32. With `aes-xts-plain64`, 32 bytes means two 16-byte
AES-128 keys; cryptsetup's current default for this cipher is 64 bytes
(see the table above). Each area
is 131,072 bytes, enough for the 4000 × 32 = 128,000 bytes of split
material.

The algorithm is the same for both sizes. What the size changes is how
damage spreads: `diffuse()` hashes the key-sized accumulator in 32-byte
chunks (with SHA-256), so a 32-byte key is one chunk and a 64-byte key
is two, which decides how much of the key one damaged stripe takes with
it (see [What damage does to the key](#what-damage-does-to-the-key)).

## The real algorithm, in plain English

This section narrates cryptsetup's AF splitter, `AF_split()` and
`AF_merge()` with their helpers `diffuse()` and `hash_buf()`, from
[`lib/luks1/af.c` at commit `fb6b9480`](https://gitlab.com/cryptsetup/cryptsetup/-/blob/fb6b9480fa519c70366d6743ec84cb0f3afcc8c7/lib/luks1/af.c).
The four functions are unchanged at the later commit
[`bae21790`](https://gitlab.com/cryptsetup/cryptsetup/-/blob/bae21790d59897ac50e5471f953f76b3a58aeeb6/lib/luks1/af.c)
apart from moving down one line. LUKS2 uses this same LUKS1 code: its
keyslot handler calls `AF_split()` when writing a keyslot and
`AF_merge()` when unlocking one
([`lib/luks2/luks2_keyslot_luks2.c`](https://gitlab.com/cryptsetup/cryptsetup/-/blob/bae21790d59897ac50e5471f953f76b3a58aeeb6/lib/luks2/luks2_keyslot_luks2.c),
lines 235 and 360).

The algorithm keeps one working buffer, the *accumulator*, the same
size as the key: 32 or 64 bytes with cryptsetup's default key sizes.
`diffuse()` replaces the accumulator with a hash of itself, but not a
hash of the buffer as a whole. It cuts the buffer into chunks the size
of the hash's digest (32 bytes for SHA-256) and hashes each chunk
separately, prefixed with the chunk's index (0, 1, …); a last chunk
shorter than a digest is hashed and the result cut to its length. A
change to one chunk therefore changes that chunk's output and no other
chunk's. Hash functions do not require this; SHA-256 accepts input of
any length. The LUKS1 specification records it as an implementation
error, as covered in
[the problem section above](#the-problem-af-splitting-solves-restated-concretely).

The per-chunk hash is `hash_buf()`:

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

Its hash input is the chunk's index as a big-endian 32-bit integer,
followed by the chunk's bytes; `crypt_hash_final()` writes `len` bytes
of the digest. `diffuse()` decides how many chunks there are and calls
`hash_buf()` once for each:

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

With SHA-256, a 32-byte accumulator is one chunk (`blocks = 1`,
`padding = 0`) and a 64-byte accumulator is two (`blocks = 2`): bytes
0–31 hashed with index 0, bytes 32–63 hashed with index 1.

`struct crypt_hash` and `crypt_hash_init()`/`_write()`/`_final()`/
`_destroy()` belong to cryptsetup's crypto backend layer, which wraps
whichever library cryptsetup is built against; at commit `fb6b9480`,
`lib/crypto_backend/` has backends for gcrypt, the kernel crypto API,
Mbed TLS, Nettle, NSS and OpenSSL. The type is declared opaquely in
[`lib/crypto_backend/crypto_backend.h`](https://gitlab.com/cryptsetup/cryptsetup/-/blob/fb6b9480fa519c70366d6743ec84cb0f3afcc8c7/lib/crypto_backend/crypto_backend.h#L28-49)
(line 28; the hash functions are declared on lines 45–49), and the
OpenSSL backend defines it as a wrapper around `EVP_MD_CTX`
([`lib/crypto_backend/crypto_openssl.c`](https://gitlab.com/cryptsetup/cryptsetup/-/blob/fb6b9480fa519c70366d6743ec84cb0f3afcc8c7/lib/crypto_backend/crypto_openssl.c#L55-57),
lines 55–57). None of this affects the algorithm.

**Splitting** a key into *n* stripes (`AF_split()`, lines 91–119).
`buf` is the accumulator, updated in place row by row:

```
buf = 00...00                        (all zero, key-sized)

stripe[0] (random)  --XOR-->  buf
                     buf = diffuse(buf)

stripe[1] (random)  --XOR-->  buf
                     buf = diffuse(buf)

        ...                         (every stripe except the last)

stripe[n-2] (random) --XOR-->  buf
                     buf = diffuse(buf)

stripe[n-1] = key XOR buf            (not random: the key enters only
                                      here, XORed with the final buf)
```

1. Start with an all-zero accumulator, the same size as the key.
2. For each stripe except the last (stripes `0` to `n-2`):
   1. fill the stripe with random bytes from `crypt_random_get()`
      (line 104) and write it to the output;
   2. XOR the stripe into the accumulator (line 108);
   3. replace the accumulator with `diffuse(accumulator)` (line 109),
      using the keyslot's `af.hash` (SHA-256 with cryptsetup's
      defaults).
3. Write the last stripe, `n-1`, as the key XORed with the accumulator
   (line 114).

**Merging** the stripes back into the key (`AF_merge()`, lines
121–143) repeats the same accumulator steps over the stored stripes:

1. Start with an all-zero accumulator.
2. For each stripe except the last, in order, XOR it into the
   accumulator and diffuse the accumulator (lines 132–134). This
   rebuilds exactly the accumulator value the split ended with.
3. XOR the last stripe with that accumulator (line 138). The result is
   the key.

No secret is involved apart from the key itself. The hash, the stripe
count and the algorithm are all public. Recovering the key needs the
final accumulator, and the final accumulator can only be rebuilt from
every one of stripes `0` to `n-2`.

Because `diffuse()` never mixes chunks, the split works chunk by chunk:
chunk *j* of the final accumulator depends only on chunk *j* of each
stripe, so chunk *j* of the key depends only on chunk *j* of every
stripe. With SHA-256, a 64-byte key is in effect split as two
independent 32-byte keys.

## A worked example you can trace by hand

Real LUKS2 uses SHA-256 and 4000 stripes on a 32- or 64-byte key, far
too much to follow by hand. This example uses a 2-byte key, 3 stripes,
and an addition in place of the hash:

```
toy_diffuse(block, index) = each byte of block, plus (index + 1), mod 256
```

The toy uses a single 2-byte chunk, so `toy_diffuse` is always called
with index 0 and adds 1 to each byte. **This stand-in has no
cryptographic properties at all.** It is linear and trivially
invertible, and, unlike SHA-256, a change to one byte of its input
changes only that byte of its output; it exists only so the arithmetic
can be checked by hand. The XOR chain, the accumulator and the order
of steps are the real algorithm's.

Toy setup:

- **Key to split**: `a5 3c` (2 bytes)
- **Stripe count** (*n*): 3
- **"Random" stripes**: normally from a random number generator; fixed
  here to `11 22` and `77 88` so the example is reproducible

### Splitting the key

Start: accumulator (`buf`) = `00 00`.

**Stripe 0** (not the last stripe: random, XOR, diffuse):

```
stripe[0]  = 11 22                 <- random
buf = stripe[0] XOR buf
    = 11 22  XOR  00 00
    = 11 22
buf = toy_diffuse(buf, index=0)
    = (0x11 + 1) mod 256, (0x22 + 1) mod 256
    = 12 23
```

**Stripe 1** (not the last stripe either):

```
stripe[1]  = 77 88                 <- random
buf = stripe[1] XOR buf
    = 77 88  XOR  12 23
    = 65 ab
buf = toy_diffuse(buf, index=0)    (each diffuse() call numbers its
                                    chunks from 0 again)
    = (0x65 + 1) mod 256, (0xab + 1) mod 256
    = 66 ac
```

**Stripe 2** (the last stripe: no randomness; the key enters here):

```
stripe[2] = key XOR buf
          = a5 3c  XOR  66 ac
          = c3 90
```

**The split material:**

```
stripe[0]  stripe[1]  stripe[2]
┌───────┐ ┌───────┐  ┌───────┐
│ 11 22 │ │ 77 88 │  │ c3 90 │      6 bytes, end to end
└───────┘ └───────┘  └───────┘
 random     random    key XOR buf
```

None of the three stripes on its own reveals anything about `a5 3c`:
`stripe[0]` and `stripe[1]` are random, and `stripe[2]` is the key
XORed with an accumulator that depends on both of them. A real keyslot
does not store this material as it is; it encrypts it first, as
described in
[What is written to disk](#what-is-written-to-disk).

### Merging the stripes back

Given all three stripes, the merge rebuilds the same accumulator:

```
buf = 00 00

buf = stripe[0] XOR buf  = 11 22 XOR 00 00 = 11 22
buf = toy_diffuse(buf, 0) = 12 23

buf = stripe[1] XOR buf  = 77 88 XOR 12 23 = 65 ab
buf = toy_diffuse(buf, 0) = 66 ac

key = stripe[2] XOR buf
    = c3 90  XOR  66 ac
    = a5 3c                         <- the original key
```

The merge reproduces the key because it repeats exactly the
accumulator steps the split took and then undoes the final XOR.

## What is written to disk

A keyslot's area holds the split material **encrypted**, not as it is.
When cryptsetup writes a keyslot
([`luks2_keyslot_luks2.c`](https://gitlab.com/cryptsetup/cryptsetup/-/blob/bae21790d59897ac50e5471f953f76b3a58aeeb6/lib/luks2/luks2_keyslot_luks2.c),
`luks2_keyslot_set_key()`, from line 149), it:

1. derives a key from the passphrase with the keyslot's KDF (line 208);
2. splits the master key into 4000 stripes with `AF_split()` (line
   235), into a buffer of `AF_split_sectors(key_size, 4000) × 512`
   bytes: the split material, rounded up to whole 512-byte sectors
   (line 224);
3. encrypts that buffer with the passphrase-derived key and the
   keyslot's area cipher (`area.encryption`), in 512-byte sectors whose
   IVs count from 0 at the start of the area, and writes it at
   `area.offset` (`luks2_encrypt_to_storage()`, lines 23–53, which
   passes `SECTOR_SIZE` and an IV offset of 0 to
   `crypt_storage_wrapper_init()`, line 38).

`SECTOR_SIZE` is 512
([`lib/libcryptsetup_macros.h`](https://gitlab.com/cryptsetup/cryptsetup/-/blob/bae21790d59897ac50e5471f953f76b3a58aeeb6/lib/libcryptsetup_macros.h#L38-39),
lines 38–39). The area cipher is the volume's own data cipher when it
can be used for keyslots, and otherwise, or when the volume uses
hardware OPAL encryption, `aes-xts-plain64` with a 512-bit key (`crypt_keyslot_get_encryption()` in
[`lib/setup.c`](https://gitlab.com/cryptsetup/cryptsetup/-/blob/bae21790d59897ac50e5471f953f76b3a58aeeb6/lib/setup.c#L6679-6720),
lines 6679–6720; the fallback is set in
[`configure.ac`](https://gitlab.com/cryptsetup/cryptsetup/-/blob/bae21790d59897ac50e5471f953f76b3a58aeeb6/configure.ac#L812-813),
lines 812–813). With cryptsetup's defaults, both are `aes-xts-plain64`
with a 64-byte key, so the area holds 4000 × 64 = 256,000 bytes of
encrypted split material, 500 sectors.

Unlocking reverses this: derive the key from the passphrase, read and
decrypt the same number of bytes from `area.offset`, `AF_merge()` them
(lines 315–360), then check the result against the stored digest (see
[How a wrong key is detected](#how-a-wrong-key-is-detected)).
Unlocking does not read `af.stripes` from the header: it always uses
`LUKS_STRIPES`, defined as 4000
([`libcryptsetup_macros.h`](https://gitlab.com/cryptsetup/cryptsetup/-/blob/bae21790d59897ac50e5471f953f76b3a58aeeb6/lib/libcryptsetup_macros.h#L62),
line 62), and header validation only checks that `af.stripes` is an
integer (`luks2_keyslot_validate()`, lines 709–714).

The experiment
[`experiments/keyslot-damage-e2e/`](../experiments/keyslot-damage-e2e)
confirms this layout on a real volume: it formats a throwaway LUKS2
image with cryptsetup, unlocks keyslot 0 with its own implementation
of the steps above, and gets the same key that cryptsetup reports.

### How a wrong key is detected

Decrypting a keyslot with the wrong passphrase does not fail by
itself: it produces the wrong bytes, and merging them produces a wrong
key. LUKS2 catches this with a *digest* of the master key, kept in the
header's `digests` object, which "is used to verify that a key
decrypted from a keyslot is correct"
([LUKS2 spec v1.1.4](https://gitlab.com/cryptsetup/LUKS2-docs/-/blob/a81aa2fef8d176debdbec297c1e0b74bb50cfee8/luks2_doc_wip.pdf)
§3.4, p.12). When the digest is created, cryptsetup runs PBKDF2 over
the master key with a random salt, the hash of the PBKDF setting, and
an iteration count benchmarked to take about 125 ms
(`LUKS_MKD_ITERATIONS_MS`,
[`lib/luks1/luks.h`](https://gitlab.com/cryptsetup/cryptsetup/-/blob/bae21790d59897ac50e5471f953f76b3a58aeeb6/lib/luks1/luks.h#L31),
line 31), and stores the salt, hash, iteration count and result
(`PBKDF2_digest_store()`,
[`lib/luks2/luks2_digest_pbkdf2.c`](https://gitlab.com/cryptsetup/cryptsetup/-/blob/bae21790d59897ac50e5471f953f76b3a58aeeb6/lib/luks2/luks2_digest_pbkdf2.c),
lines 77–172). To check a merged key, `PBKDF2_digest_verify()` (lines
15–75) repeats the computation on it and compares the result with the
stored digest (line 68); a mismatch is reported the same way as a
wrong passphrase. `cryptsetup open --test-passphrase` stops after this
check: it does "not activate the device, just verify the passphrase"
([`man/common_options.adoc`](https://gitlab.com/cryptsetup/cryptsetup/-/blob/bae21790d59897ac50e5471f953f76b3a58aeeb6/man/common_options.adoc),
lines 1040–1041), which is what
[`passphrase-recovery.md`](passphrase-recovery.md) relies on.

## What damage does to the key

Damage on disk reaches the key in two steps: decryption turns damaged
ciphertext into damaged stripes, and the merge turns damaged stripes
into a damaged key.

### From damaged stripes to the key

The toy example shows the structure, with one caveat: because the toy
diffusion is an addition, damage in it stays in the byte it hit, while
SHA-256 scrambles the whole chunk.

**1. Flip one bit in the first stripe:**

```
stripe[0]: 11 22  ->  10 22

buf = 10 22 XOR 00 00 = 10 22
buf = toy_diffuse(buf, 0) = 11 23
buf = 77 88 XOR 11 23 = 66 ab
buf = toy_diffuse(buf, 0) = 67 ac
key = c3 90 XOR 67 ac = a4 3c       (should be a5 3c)
```

The toy gets one bit wrong. In real LUKS2, the flipped bit goes through
SHA-256 at the next `diffuse()`, which scrambles every byte of that
32-byte chunk, and every later round keeps it scrambled; the other
chunk is untouched. With a 64-byte key, one half of the key is wrong;
with a 32-byte key, all of it is.

**2. Flip one bit in the last stripe:**

```
stripe[2]: c3 90  ->  c2 90
key = c2 90 XOR 66 ac = a4 3c       (should be a5 3c)
```

The last stripe is never diffused, so the key is wrong in exactly the
flipped bit, in the toy and in real LUKS2 alike.

**3. Lose a whole stripe:** without `stripe[0]`, the accumulator cannot
be rebuilt, and no byte of the key can be computed. In real LUKS2 the
same holds for any one of the 4000 stripes.

The experiment
[`experiments/af-damage-locality/`](../experiments/af-damage-locality)
runs cases 1 and 2 on the real algorithm with 4000 stripes and
SHA-256: one flipped bit in any of stripes 1 to 3999 changes only the
32-byte chunk of the key it lines up with, and one flipped bit in the
last stripe changes one key byte.

### From damaged ciphertext to stripes

Damage on disk changes ciphertext, so what matters first is how much
plaintext one damaged ciphertext byte affects. With the default
`aes-xts-plain64`, that is one 16-byte block. XTS encrypts a sector as
a series of 16-byte blocks, each XORed with a per-block tweak value,
encrypted with the block cipher on its own, and XORed with the tweak
again; the Linux kernel's implementation does exactly these three
passes
([`crypto/xts.c`](https://github.com/torvalds/linux/blob/cae575fc09fa824900939960e33bc49b8e964d80/crypto/xts.c#L77-L132),
`xts_xor_tweak()`, lines 83–132, and `xts_encrypt()`, lines 262–277).
So decrypting a damaged 16-byte block scrambles that block's 16 bytes
of plaintext and nothing else.

This section and its experiment cover `aes-xts-plain64` only. The
keyslot area uses the volume's own cipher whenever it can
([`experiments/default-key-sizes/`](../experiments/default-key-sizes)
shows this for XTS, CBC and Adiantum volumes), and other modes do not
encrypt in independent 16-byte blocks, so on a volume formatted with
a non-XTS cipher one damaged byte reaches a different amount of the
split material.

No XTS block crosses a stripe boundary: blocks start every 16 bytes
from the start of each 512-byte sector, sectors start every 512 bytes
from the start of the area, and stripes start every 64 bytes (or 32,
for a 32-byte key), all multiples of 16. Each 64-byte stripe therefore
holds exactly four XTS blocks. One damaged byte on disk therefore scrambles
16 bytes of exactly one stripe, which means:

| Damaged byte is in | Key bytes lost (64-byte key, SHA-256) |
|---|---|
| Stripes 1 to 3999 | the whole 32-byte chunk the block lines up with: half the key |
| The last stripe | the 16 key bytes the block lines up with |

Damage that spans several blocks loses the union of these.
[`experiments/keyslot-damage-e2e/`](../experiments/keyslot-damage-e2e)
measures exactly this on a real cryptsetup-formatted image: one flipped
ciphertext byte in stripe 1 or stripe 2000 changed 32 key bytes, and
one in the last stripe changed 16.

### What this means for recovery

The smallest possible loss, one 16-byte block in the last stripe,
leaves 128 bits of the key unknown; anywhere else, at least 256 bits.
Neither can be searched, so a keyslot with any damage to its encrypted
split material (the first 256,000 bytes of the area, for a 64-byte key)
cannot be repaired from its own data.

cryptsetup cannot tell this apart from a wrong passphrase. The merged
key fails the digest check, and `cryptsetup open --test-passphrase`
prints the same message as for a wrong passphrase, "No key available
with this passphrase.", with exit status 2 (measured in the same
experiment). A device or image that ends before the end of the area
fails differently: the read comes back short and cryptsetup reports
"IO error while decrypting keyslot." (`luks2_decrypt_from_storage()`,
lines 83–85).

## Mapping the toy example back to real LUKS2

The toy differs from real LUKS2 in five ways:

- **SHA-256 instead of addition.** Damage to a chunk changes the
  whole SHA-256 output for that chunk: in
  [`experiments/af-damage-locality/`](../experiments/af-damage-locality),
  one flipped bit changed all 32 bytes of the chunk (31 in one run,
  where a byte came out the same by chance). The toy's addition changes
  only the damaged byte.
- **32-byte chunks instead of one 2-byte chunk.** `diffuse()` hashes
  each 32-byte chunk of the accumulator separately, so damage stays
  within its chunk.
- **4000 stripes instead of 3.** The accumulator chain is the same,
  repeated 3999 times. Unlocking always uses 4000, whatever
  `af.stripes` in the header says.
- **A 32- or 64-byte key instead of 2 bytes.** The split material is
  4000 × the key size: 128,000 bytes for a 32-byte key, 256,000 bytes
  for a 64-byte key. The keyslot area recorded in the header
  (`area.size`, shown by `inspect-keyslot` as "Area length") is at
  least that; on the image the experiment formats, it is 258,048 bytes
  for a 64-byte key.
- **Encryption.** The toy stores its stripes as they are; a real
  keyslot encrypts them with the area cipher before writing them, and
  damage on disk reaches the stripes through that encryption.

## What this means when you're inspecting a keyslot

Tying this back to [`checking-for-corruption.md`](checking-for-corruption.md):

- **A healthy keyslot area looks like uniform random bytes**, because
  it is ciphertext. Looking at it cannot tell you whether it decrypts
  to the right key. What you can spot is damage that real ciphertext
  does not produce: long runs of zeros, repeated patterns, an area cut
  short (see
  [`checking-for-corruption.md#what-corrupted-key-material-looks-like`](checking-for-corruption.md#what-corrupted-key-material-looks-like)).
- **A damaged keyslot cannot be recovered from its own data.** As
  shown above, any damage leaves at least 128 bits of the key unknown.
  `cryptsetup repair` does not help: its man page says it "will only
  change the LUKS header, not any keyslot data", and that "if the
  keyslot is corrupted, no recovery is possible. You have to use the
  LUKS header backup"
  ([`man/cryptsetup-repair.8.adoc`](https://gitlab.com/cryptsetup/cryptsetup/-/blob/bae21790d59897ac50e5471f953f76b3a58aeeb6/man/cryptsetup-repair.8.adoc)).
  It can print warnings for some damage, "usually only a low-entropy
  area (like zeroed blocks)", but does not modify keyslots.
- **Other keyslots hold their own copies.** Each keyslot stores the
  master key separately, so if the volume has another keyslot whose
  passphrase you know, that keyslot still opens the volume.
- **A header backup taken before the damage restores the keyslot.**
  `cryptsetup luksHeaderBackup` "stores a binary backup of the LUKS
  header and keyslot area"
  ([`man/cryptsetup-luksHeaderBackup.8.adoc`](https://gitlab.com/cryptsetup/cryptsetup/-/blob/bae21790d59897ac50e5471f953f76b3a58aeeb6/man/cryptsetup-luksHeaderBackup.8.adoc)).
  The same man page warns that such a backup, with any passphrase that
  was valid when it was taken, opens the volume even after that
  passphrase is removed from the device.
