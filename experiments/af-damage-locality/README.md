# AF damage locality

## Claim

Damage to part of one AF stripe does not spread to the whole merged
key:

- in stripes 1 to 3999 it changes only the hash-digest-sized chunk of
  the key it lines up with (32 bytes for SHA-256, so one half of a
  64-byte key, or all of a 32-byte key);
- in the last stripe it changes only the matching key bytes.

Used in [`docs/af-splitting-explained.md`](../../docs/af-splitting-explained.md).

## Why, from the source

cryptsetup's `diffuse()`
([`lib/luks1/af.c`](https://gitlab.com/cryptsetup/cryptsetup/-/blob/fb6b9480fa519c70366d6743ec84cb0f3afcc8c7/lib/luks1/af.c#L54-84),
lines 54–84) cuts the accumulator into digest-sized chunks and hashes
each chunk on its own, with its index. `AF_merge()` (lines 121–143)
XORs each of stripes 1 to n−1 into the accumulator and diffuses it,
then XORs the last stripe in without diffusion.

The LUKS1 specification, v1.2.3, §2.4.1 (p.4), documents this
chunk-by-chunk diffusion ("H1") as an implementation error, and §2.4.2
(p.5) gives the intended version ("H2"), in which every output chunk
hashes the whole input.

## Requirements

`python3` (standard library only).

## Run

```
experiments/af-damage-locality/run
```

The script splits a random key into 4000 stripes with SHA-256 using
[`../lib/luks_af.py`](../lib/luks_af.py), checks the key merges back,
then flips one bit in chosen stripes and reports which key bytes
change. It does this for a 64-byte key (cryptsetup's default for
`aes-xts-plain64`) and a 32-byte key.

## Result (2026-10-28)

```
64-byte key, 4000 stripes, sha256: round trip OK
  flip one bit in stripe    1, byte  5: 31 key bytes changed, all within bytes 0-31
  flip one bit in stripe    1, byte 40: 32 key bytes changed, all within bytes 32-63
  flip one bit in stripe 2000, byte 31: 32 key bytes changed, all within bytes 0-31
  flip one bit in stripe 2000, byte 32: 32 key bytes changed, all within bytes 32-63
  flip one bit in stripe 3999, byte 63: 32 key bytes changed, all within bytes 32-63
  flip one bit in stripe 4000, byte 10:  1 key bytes changed, all within bytes 10-10
32-byte key, 4000 stripes, sha256: round trip OK
  flip one bit in stripe    1, byte  5: 32 key bytes changed, all within bytes 0-31
  flip one bit in stripe 2000, byte 31: 32 key bytes changed, all within bytes 0-31
  flip one bit in stripe 4000, byte 10:  1 key bytes changed, all within bytes 10-10
```

The key is random, so exact counts vary between runs: a byte inside the
affected chunk can come out unchanged by chance (1 in 256 per byte),
which is why one line shows 31 rather than 32. The ranges do not vary:
damage never crosses a 32-byte chunk boundary, and damage to the last
stripe changes only the flipped byte.

This experiment works on the plaintext stripes only. On disk the
stripes are encrypted, which changes how damage first reaches them; see
[`../keyslot-damage-e2e/`](../keyslot-damage-e2e).
