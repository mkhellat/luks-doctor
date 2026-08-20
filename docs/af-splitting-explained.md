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
  template obtain a handle to `ecb(aes)` (now registered as an
  `lskcipher`, not a `skcipher`, per the same kernel restructuring
  described below). Do not treat amber nodes as fully verified the way
  the rest of the graph is.

  **The single biggest finding from building this diagram**: an
  earlier version of this doc cited `crypto_aes_ctx`/`aes_expandkey()`
  in `crypto/aes_generic.c` as *the* generic AES key-schedule path.
  That file no longer exists — a 2026 kernel restructuring
  (`crypto: aes - Replace aes-generic with wrapper around lib`)
  replaced it with `crypto/aes.c` (a thin Crypto API wrapper) backed
  by a new `lib/crypto/aes.c`. As a direct consequence, `xts(aes)` is
  registered **three separate times** in the current kernel, ranked by
  `cra_priority`, and `crypto_alloc_skcipher()` picks whichever is
  highest and available — this diagram's Setup/Keying/Encrypt-Decrypt
  layers all branch three ways for exactly this reason, not two.

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
