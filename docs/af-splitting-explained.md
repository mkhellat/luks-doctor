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
- [The real algorithm, in plain English](#the-real-algorithm-in-plain-english)
- [A worked example you can trace by hand](#a-worked-example-you-can-trace-by-hand)
  - [Splitting the key](#splitting-the-key)
  - [Merging the stripes back](#merging-the-stripes-back)
- [Why this makes corruption unrecoverable: three demonstrations](#why-this-makes-corruption-unrecoverable-three-demonstrations)
- [Mapping the toy example back to real LUKS2](#mapping-the-toy-example-back-to-real-luks2)
- [What this means when you're inspecting a keyslot](#what-this-means-when-youre-inspecting-a-keyslot)

## The problem AF-splitting solves, restated concretely

Say your LUKS2 volume's master key is 32 bytes. If that 32-byte key were
written to disk as-is (even encrypted under your passphrase-derived key),
an attacker who recovers even a small *fragment* of that region — from
wear-leveling remnants on an SSD, a bad-block remap, filesystem journal
residue, whatever — has a fragment of the actual key. Not the whole key,
but a real, meaningful piece of it, which measurably narrows a brute-force
search.

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
below). The core of `diffuse`'s per-block hashing (`hash_buf`) is:

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

— i.e. each block's hash input is the block's own index (as a
big-endian 32-bit integer) followed by the block's bytes. That index
mix-in is the concrete mechanism behind "the block's position is part
of what gets hashed," mentioned below.

**Splitting** a key into N stripes:

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

**Merging** stripes back into the key reverses this exactly:

1. Start with the same all-zero accumulator.
2. For each stripe *except the last*, in the same order: XOR it into the
   accumulator, then diffuse the accumulator — identical to the split
   process, because the merge side needs to reconstruct the exact same
   accumulator value the split side had.
3. XOR the final stripe with the (now fully reconstructed) accumulator.
   The result is the original key.

The `diffuse` function itself is simple: chop its input into
hash-digest-sized blocks, and hash each block individually, mixing in the
block's position (`0`, `1`, `2`, ...) as part of what gets hashed. This
mixing-in-of-position is what a cryptsetup source comment calls
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
256-bit (32-byte) key — utterly infeasible to trace by hand, and that's
the point (see
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
stripe[0] = 11 22
stripe[1] = 77 88
stripe[2] = c3 90
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

Real LUKS2 differs from the toy example in three ways, all of which make
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
