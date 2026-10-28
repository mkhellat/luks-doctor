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
  - [Aside: where does that key-length number actually come from?](#aside-where-does-that-key-length-number-actually-come-from)
    - [Where key length actually comes from, per code](#where-key-length-actually-comes-from-per-code)
    - [The keyslot JSON object, sketched](#the-keyslot-json-object-sketched)
    - [A real example, from the spec itself](#a-real-example-from-the-spec-itself)
- [The real algorithm, in plain English](#the-real-algorithm-in-plain-english)
- [A worked example you can trace by hand](#a-worked-example-you-can-trace-by-hand)
  - [Splitting the key](#splitting-the-key)
  - [Merging the stripes back](#merging-the-stripes-back)
- [What is written to disk](#what-is-written-to-disk)
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
default key sizes (see the aside below), so its encrypted copy
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
is determined by choices made at `luksFormat` time, which the aside
below traces through cryptsetup's code.

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
  disk, per keyslot, is this key AF-split (the whole subject of this
  document) and then encrypted under your passphrase-derived key (see
  [What is written to disk](#what-is-written-to-disk)) — that's
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
  2. **Immediately after that empty `tfm` is created, dm-crypt calls
     `crypt_setkey()`, which calls `crypto_skcipher_setkey(tfm, key,
     size)` — the one function call, for the whole volume-mount
     lifetime, that takes the raw plaintext key as an argument.** This
     call expands the key into a *key schedule*: AES's own precomputed
     set of per-round keys (14 rounds for AES-256, so 15 round keys),
     specified as `KeyExpansion()` in [FIPS
     197](https://doi.org/10.6028/NIST.FIPS.197-upd1) §5.2, p. 17
     (Algorithm 2, quoted above). Per that algorithm, the schedule's
     first `Nk` words are the raw key copied verbatim (`w[0..Nk-1] =
     key`); every later round key is computed from there. The schedule
     is stored inside the `tfm`, and every sector encrypt/decrypt in
     step 3 reads it directly.

     Which concrete function performs this expansion depends on which
     backend the kernel picked for `xts(aes)` (`cra_driver_name`, step
     1 above):
     - **AES-NI** (the common case on x86): `xts_setkey_aesni()`
       ([`arch/x86/crypto/aesni-intel_glue.c`](https://github.com/torvalds/linux/blob/ea0c746ffa1e6e701d39a564f6286a3f5740826b/arch/x86/crypto/aesni-intel_glue.c#L358-L376),
       lines 358–376, pinned commit `ea0c746f`, verified 2026-08-20)
       splits the 512-bit key in half and stores each half in its own
       `struct crypto_aes_ctx`, inside `struct aesni_xts_ctx {
       crypto_aes_ctx tweak_ctx; crypto_aes_ctx crypt_ctx; }` (same
       file, lines 49–52). It does this via `aes_set_key_common()`
       (lines 98–113), which normally runs the AES-NI assembly routine
       `aesni_set_key()`, falling back to `aes_expandkey()` (declared
       in
       [`include/crypto/aes.h`](https://github.com/torvalds/linux/blob/d4e273a5065f81ca86eca48cb3fed55867cc0115/include/crypto/aes.h#L146-L160),
       pinned commit `d4e273a5`, verified 2026-08-20; its own doc
       comment: *"Expands the AES key as described in FIPS-197"*) when
       SIMD isn't usable.
     - **No hardware acceleration**: the generic `crypto/xts.c`
       ([pinned commit `cae575fc`](https://github.com/torvalds/linux/blob/cae575fc09fa824900939960e33bc49b8e964d80/crypto/xts.c#L42-L74),
       lines 42–74, verified 2026-08-20) template splits the key and
       delegates to a child `ecb(aes)` transform, landing in
       `crypto/aes.c`'s `crypto_aes_setkey()` → `aes_preparekey()` — a
       different struct (`struct aes_key`, not `crypto_aes_ctx`), same
       FIPS-197 expansion.

     Freeing the `tfm` at `luksClose` zeroes this schedule.
     `crypto_free_skcipher()`
     ([`include/crypto/skcipher.h`](https://github.com/torvalds/linux/blob/f9bbd547cfb98b1c5e535aab9b0671a2ff22453a/include/crypto/skcipher.h#L328-L331),
     lines 328–331, pinned commit `f9bbd547`, verified 2026-08-20) is
     documented in its own comment as "zeroize and free cipher handle";
     it calls `crypto_destroy_tfm()`
     ([`crypto/api.c`](https://github.com/torvalds/linux/blob/cae575fc09fa824900939960e33bc49b8e964d80/crypto/api.c#L617-L631),
     lines 617–631, same pinned commit as the generic xts.c above),
     which calls `kfree_sensitive(mem)` — the same zero-before-free
     primitive `crypt_dtr()` uses on `struct crypt_config` itself
     (documented above). dm-crypt's teardown path calls
     `crypto_free_skcipher()` on every `tfms[i]`, so on `luksClose` the
     key material is zeroed twice: once when the `tfm` is freed, once
     when `struct crypt_config` is freed. Before teardown, reading this
     schedule requires the same access as reading the raw key
     elsewhere in kernel memory (see "Where it lives," above): a
     kernel exploit, a physical DMA/cold-boot attack, or root access
     to `/dev/kmem` where enabled.
  3. **Every sector read or write runs the cipher against that
     schedule.** For each sector, dm-crypt allocates a fresh
     per-request object (`crypt_alloc_req_skcipher()`), binds it to
     the same, already-keyed `tfm` via `skcipher_request_set_tfm()`,
     and calls `crypto_skcipher_encrypt()` or
     `crypto_skcipher_decrypt()`. Neither function touches the
     schedule directly: each pulls the `tfm` back off the request
     (`crypto_skcipher_reqtfm(req)`) and dispatches to that backend's
     registered encrypt/decrypt routine — on AES-NI,
     `xts_encrypt_aesni()`/`xts_decrypt_aesni()`
     (`arch/x86/crypto/aesni-intel_glue.c`, lines 592–593, same pinned
     commit as above), which call down through `xts_crypt()` to
     `aesni_xts_enc()`/`aesni_xts_dec()` (lines 490–501), the
     assembly-implemented routines that actually take the
     `crypto_aes_ctx` built in step 2 as an argument and read the
     round keys out of it. That chain runs fresh for every sector,
     over and over, for as long as the volume stays mounted, reading
     the same schedule array — raw key at slot zero, derived round
     keys after it — every time. Step 2's `setkey` call runs once per
     unlock; step 3's use of what it produced runs continuously.

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

  #### Key-lifecycle call graph

  The three-step summary above collapses real branching: which exact
  functions run depends on which of three competing kernel
  implementations of `xts(aes)` wins priority-based selection, and the
  per-sector encrypt/decrypt path is driven by a bio-submission chain
  never shown above. The diagram below traces every edge from
  `luksOpen` through per-sector I/O to `luksClose`, each one verified
  against real kernel source at a pinned commit (see the citation
  table beneath it). This covers only the key lifecycle; separate
  diagrams for tweak/IV generation and the full userspace-to-kernel
  unlock path are planned but not yet built — don't read anything
  below as covering those.

  ```mermaid
  flowchart TD
      subgraph S1["1. tfm creation (luksOpen)"]
          A1["crypt_alloc_tfms_skcipher()<br/>dm-crypt.c:2297"]
          A2["crypto_alloc_skcipher('aes-xts-plain64', ...)<br/>picks highest-priority registered xts(aes)"]
          A1 --> A2
      end

      subgraph S2["2. Backend selection (crypto API priority)"]
          B1["xts-aes-aesni<br/>priority 401<br/>aesni-intel_glue.c:580-593"]
          B2["xts-aes-lib<br/>priority 110<br/>crypto/aes.c:691-704"]
          B3["xts(ecb(aes))<br/>template composition, inherited priority<br/>crypto/xts.c + crypto/ecb.c<br/>legacy path, unverified reachability"]
          A2 -.->|AES-NI available| B1
          A2 -.->|no AES-NI, lib compiled in<br/>always true in practice| B2
          A2 -.->|structurally exists; whether it can<br/>still be selected is unverified| B3
      end

      subgraph S3["3. Keying — crypt_setkey() / crypto_skcipher_setkey(tfm,key,size)<br/>dm-crypt.c:2388-2414, called exactly once per unlock"]
          C1["xts_setkey_aesni()<br/>aesni-intel_glue.c:358-376"]
          C2["aes_set_key_common()<br/>aesni-intel_glue.c:98-113"]
          C3a["aesni_set_key() [asm]<br/>SIMD usable"]
          C3b["aes_expandkey()<br/>include/crypto/aes.h:146-160<br/>SIMD NOT usable"]
          C4["struct crypto_aes_ctx<br/>(key_enc[], key_dec[], key_length)<br/>aes.h:122-126<br/>inside struct aesni_xts_ctx<br/>aesni-intel_glue.c:49-52"]

          C5["crypto_aes_xts_setkey()<br/>crypto/aes.c:514-525"]
          C6["aes_xts_preparekey()<br/>lib/crypto/aes.c:1206-1229"]
          C7["struct aes_xts_key<br/>include/crypto/aes-xts.h"]

          C8["xts_setkey() [generic template]<br/>crypto/xts.c:42-75"]
          C9["child ecb(aes) skcipher_setkey()<br/>lskcipher adaptation shim — NOT verified"]
          C10["crypto_aes_setkey()<br/>crypto/aes.c ~34-40"]
          C11["aes_preparekey()<br/>include/crypto/aes.h:335<br/>struct aes_key"]

          B1 --> C1 --> C2
          C2 -->|SIMD usable| C3a --> C4
          C2 -->|SIMD unusable| C3b --> C4

          B2 --> C5 --> C6 --> C7

          B3 --> C8 --> C9 --> C10 --> C11
      end

      subgraph S4["4. Bio entry & dispatch (per I/O request)"]
          D1["device-mapper core<br/>invokes target's .map"]
          D2["crypt_map()<br/>dm-crypt.c:3417-3496"]
          D3["kcryptd_queue_crypt()<br/>dm-crypt.c:2233-2256<br/>WRITE path"]
          D4["kcryptd_io_read() /<br/>kcryptd_queue_read()<br/>READ path, ciphertext fetch"]
          D5["kcryptd_crypt()<br/>dm-crypt.c:2223-2231<br/>workqueue callback"]
          D6["kcryptd_crypt_write_convert()<br/>dm-crypt.c:2041-2098"]
          D7["kcryptd_crypt_read_convert()<br/>dm-crypt.c:2122-2146"]
          D8["crypt_convert()<br/>dm-crypt.c:1515-1544"]
          D9["crypt_alloc_req()<br/>dm-crypt.c:1477-1484"]
          D10["crypt_alloc_req_skcipher()<br/>dm-crypt.c:1431-1442<br/>skcipher_request_set_tfm() binds<br/>request to already-keyed tfm"]
          D11["crypt_convert_block_skcipher()<br/>dm-crypt.c:1352-1418"]
          D12["crypto_skcipher_encrypt() /<br/>crypto_skcipher_decrypt()<br/>dm-crypt.c:1416/1418<br/>skcipher.c: pulls tfm off request,<br/>dispatches to alg-&gt;encrypt/decrypt"]

          D1 --> D2
          D2 -->|WRITE| D3 --> D5
          D2 -->|READ| D4 --> D5
          D5 -->|WRITE| D6 --> D8
          D5 -->|READ| D7 --> D8
          D8 --> D9 --> D10
          D8 --> D11 --> D12
      end

      subgraph S5["5. Per-sector encrypt/decrypt (runs continuously, once per sector)"]
          E1a["xts_encrypt_aesni() / xts_decrypt_aesni()<br/>aesni-intel_glue.c:592-593"]
          E1b["xts_crypt()<br/>aesni-intel_glue.c:452-480"]
          E1c["aesni_xts_encrypt() / aesni_xts_decrypt()<br/>aesni-intel_glue.c:490-501"]
          E1d["aesni_xts_enc() / aesni_xts_dec() [asm]<br/>reads struct crypto_aes_ctx directly"]

          E2a["crypto_aes_xts_encrypt() / crypto_aes_xts_decrypt()<br/>crypto/aes.c:576-603"]
          E2b["aes_xts_encrypt() / aes_xts_decrypt()<br/>lib/crypto/aes.c:1401-1431"]
          E2c["aes_xts_encrypt_nocts() / _decrypt_nocts()<br/>lib/crypto/aes.c:1285-1318"]
          E2d["aes_xts_encrypt_arch() / _decrypt_arch()<br/>weak hooks, no x86 override found<br/>lib/crypto/aes.c:1241-1256"]
          E2e["aes_xts_crypt_nocts_blockbyblock()<br/>lib/crypto/aes.c:1258-1282"]
          E2f["aes_encrypt() / aes_decrypt()<br/>lib/crypto/aes.c:511-523<br/>reads struct aes_xts_key"]

          E3a["xts_encrypt() / xts_decrypt() [template]<br/>crypto/xts.c:262-294"]
          E3b["child ecb(aes) encrypt/decrypt<br/>crypto/ecb.c:16-54"]
          E3c["crypto_aes_encrypt() / crypto_aes_decrypt()<br/>crypto/aes.c ~41-47"]

          D12 -->|AES-NI backend| E1a --> E1b --> E1c --> E1d
          D12 -->|xts-aes-lib backend, fast/linear path| E2a --> E2b
          E2a -->|nonlinear/HIGHMEM| E2c
          E2b --> E2c --> E2d
          E2d -->|falls through, no arch override| E2e --> E2f
          D12 -->|xts-ecb-aes backend, unverified reachability| E3a --> E3b --> E3c --> E2f
      end

      subgraph S6["6. Teardown (luksClose)"]
          F1["crypt_dtr()"]
          F2["kfree_sensitive(cc)<br/>zeroes struct crypt_config<br/>source comment: 'Must zero key material before freeing'"]
          F3["crypt_free_tfms_skcipher()<br/>loops every tfms[i]"]
          F4["crypto_free_skcipher()<br/>skcipher.h:328-331<br/>doc comment: 'zeroize and free cipher handle'"]
          F5["crypto_destroy_tfm()<br/>api.c:617-631"]
          F6["kfree_sensitive(mem)<br/>zeroes tfm context —<br/>including whichever key<br/>schedule struct from step 3"]

          F1 --> F2
          F1 --> F3 --> F4 --> F5 --> F6
      end

      C4 -.-> D10
      C7 -.-> D10
      C4 -.-> F6
      C7 -.-> F6

      classDef unverified fill:#fff3cd,stroke:#997404,color:#664d03
      class B3,C9,E3a,E3b,E3c unverified
  ```

  Amber nodes are structurally confirmed to exist in source but have
  at least one unverified edge — most importantly, the `lskcipher`-to-
  `skcipher` adaptation shim that lets `crypto/xts.c`'s generic
  template obtain a handle to `ecb(aes)`, which `crypto/ecb.c` has
  registered as an `lskcipher`, not a `skcipher`, since Linux v6.7
  ([`32a8dc4a`](https://github.com/torvalds/linux/commit/32a8dc4afcfb098ef4e8b465c90db17d22d90107),
  `crypto: ecb - Convert from skcipher to lskcipher`). Do not treat
  amber nodes as fully verified the way the rest of the graph is.

  **The single biggest finding from building this diagram**: an
  earlier version of this doc cited `crypto_aes_expand_key()` in
  `crypto/aes_generic.c` as the AES key-schedule routine. That
  function was real but long outdated. Linux v5.4 replaced it with the
  shared library routine `aes_expandkey()` in `lib/crypto/aes.c`
  ([`5bb12d78`](https://github.com/torvalds/linux/commit/5bb12d7825adf0e80b849a273834f3131a6cc4e1),
  `crypto: aes-generic - drop key expansion routine in favor of
  library version`), and v7.0 deleted `crypto/aes_generic.c`,
  replacing it with `crypto/aes.c`, a Crypto API wrapper around that
  library
  ([`a2484474`](https://github.com/torvalds/linux/commit/a2484474272ef98d9580d8c610b0f7c6ed2f146c),
  `crypto: aes - Replace aes-generic with wrapper around lib`). At
  this diagram's pinned commits, all of which are part of the v7.3
  release, `xts(aes)` is registered **three
  separate times**: AES-NI's `xts-aes-aesni`; the library-backed
  `xts-aes-lib`, which v7.3 added to `crypto/aes.c`
  ([`94efa0c9`](https://github.com/torvalds/linux/commit/94efa0c9fb36b0f8be480f24bce2bb673005bfde),
  `crypto: aes - Add XTS support using library`); and the generic
  `xts` template over `ecb(aes)`. `crypto_alloc_skcipher()` picks the
  highest `cra_priority` available, so the diagram's
  Setup/Keying/Encrypt-Decrypt layers all branch three ways, not two.
  Unreleased kernel master has since moved x86's AES-NI XTS code into
  the library
  ([`2bd68888`](https://github.com/torvalds/linux/commit/2bd6888849d6d2d5497c2470cc71c8d2cb170523))
  and raised `xts-aes-lib`'s x86 priority to 500
  ([`f410daa3`](https://github.com/torvalds/linux/commit/f410daa32cfcd94263f156662a1ad2097505443c));
  this diagram does not reflect that yet.

  **Citations** (all fetched and line-checked directly against the
  pinned commit shown, verified 2026-08-20):

  | File | Pinned commit |
  |---|---|
  | `drivers/md/dm-crypt.c` | [`43fd83c0`](https://github.com/torvalds/linux/tree/43fd83c0b1dc127cf13b4c05303665924e63ef94/drivers/md/dm-crypt.c) |
  | `arch/x86/crypto/aesni-intel_glue.c` | [`ea0c746f`](https://github.com/torvalds/linux/tree/ea0c746ffa1e6e701d39a564f6286a3f5740826b/arch/x86/crypto/aesni-intel_glue.c) |
  | `include/crypto/aes.h` | [`d4e273a5`](https://github.com/torvalds/linux/tree/d4e273a5065f81ca86eca48cb3fed55867cc0115/include/crypto/aes.h) |
  | `crypto/aes.c` | [`f70ad727`](https://github.com/torvalds/linux/tree/f70ad727d1d60a4dfcb1a22152d4169f9a205af9/crypto/aes.c) |
  | `lib/crypto/aes.c` | [`561131a2`](https://github.com/torvalds/linux/tree/561131a27f5533e6e63520b4bc43d9c832a27c09/lib/crypto/aes.c) |
  | `crypto/xts.c` | [`cae575fc`](https://github.com/torvalds/linux/tree/cae575fc09fa824900939960e33bc49b8e964d80/crypto/xts.c) |
  | `crypto/ecb.c` | [`ef93f156`](https://github.com/torvalds/linux/tree/ef93f1562803cd7bb8159e3abedaf7f47dce4e35/crypto/ecb.c) |
  | `include/crypto/skcipher.h` | [`f9bbd547`](https://github.com/torvalds/linux/tree/f9bbd547cfb98b1c5e535aab9b0671a2ff22453a/include/crypto/skcipher.h) |
  | `crypto/api.c` | [`cae575fc`](https://github.com/torvalds/linux/tree/cae575fc09fa824900939960e33bc49b8e964d80/crypto/api.c) |

  A themed, browsable version of this same diagram — same Mermaid
  source, same citation table — is checked into this repo at
  [`docs/diagrams/key-lifecycle.html`](diagrams/key-lifecycle.html);
  open it directly in a browser (it loads Mermaid and its Google Fonts
  from a CDN, so it needs a network connection once, but has no other
  dependency).

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
[How LUKS2 knows the unwrap actually worked](#aside-where-does-that-key-length-number-actually-come-from)).
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
