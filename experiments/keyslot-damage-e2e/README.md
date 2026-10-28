# Keyslot damage, end to end

## Claim

On a LUKS2 volume with cryptsetup's default settings, changing one byte
of a keyslot's area on disk:

- scrambles one 16-byte block of the decrypted split material, because
  the area is encrypted with AES-XTS, which encrypts each 16-byte block
  separately;
- therefore changes one 32-byte half of the 64-byte master key if the
  block falls in stripes 1 to 3999, or 16 bytes of the key if it falls
  in the last stripe (see [`../af-damage-locality/`](../af-damage-locality));
- makes cryptsetup reject the correct passphrase with the same message
  as a wrong one: "No key available with this passphrase."

Used in [`docs/af-splitting-explained.md`](../../docs/af-splitting-explained.md).

## How the experiment checks it

1. `run` creates a 32 MiB image file in a temporary directory and runs
   `cryptsetup luksFormat --type luks2` on it with cryptsetup's default
   cipher (`aes-xts-plain64`, 512-bit key, SHA-256 AF hash). The only
   non-default is `--pbkdf pbkdf2 --pbkdf-force-iterations 1000`, so the
   script can derive the keyslot key with Python's standard library
   instead of an Argon2 library.
2. `cryptsetup luksDump --dump-volume-key` writes the real volume key to
   a file.
3. [`keyslot_damage.py`](keyslot_damage.py) unlocks keyslot 0 on its own,
   following cryptsetup's `lib/luks2/luks2_keyslot_luks2.c` at commit
   [`bae21790`](https://gitlab.com/cryptsetup/cryptsetup/-/blob/bae21790d59897ac50e5471f953f76b3a58aeeb6/lib/luks2/luks2_keyslot_luks2.c):
   - derive the area key with PBKDF2 from the passphrase and the
     keyslot's salt;
   - read `AF_split_sectors(key_size, 4000) × 512` bytes from
     `area.offset` (line 315);
   - decrypt them with AES-XTS in 512-byte sectors, with `plain64` IVs
     counting from 0 at the start of the area (`luks2_decrypt_from_storage()`,
     lines 55–89, which passes `SECTOR_SIZE` and an IV offset of 0 to
     `crypt_storage_wrapper_init()`);
   - `AF_merge()` the result with [`../lib/luks_af.py`](../lib/luks_af.py).

   It checks that this reproduces the key from step 2, which confirms the
   layout: split first, then encrypt, in 512-byte sectors.
4. The script then flips one ciphertext byte at a time and reports which
   decrypted bytes and which key bytes change.
5. `run` flips one byte of the keyslot area in a copy of the image and
   runs `cryptsetup open --test-passphrase` on both copies.

## Requirements

- `cryptsetup` (2.8.8 was used; no root needed, since it works on an
  image file)
- `python3` with the [`cryptography`](https://pypi.org/project/cryptography/)
  package (50.0.2 was used)
- `truncate`, `dd`

## Run

```
experiments/keyslot-damage-e2e/run
```

It uses a synthetic passphrase and deletes the image and key files on
exit.

## Result (2026-10-28)

```
Independent unlock reproduces cryptsetup's volume key: 64-byte key, 4000 stripes, sha256, aes-xts-plain64 in 512-byte sectors.
Stripe 1:
  flipped ciphertext byte 5 (area offset)
  plaintext bytes changed: 16, all within 0-15 (stripe 1)
  key bytes changed: 32, all within 0-31
Stripe 2000:
  flipped ciphertext byte 127976 (area offset)
  plaintext bytes changed: 16, all within 127968-127983 (stripe 2000)
  key bytes changed: 32, all within 32-63
Last stripe, first XTS block:
  flipped ciphertext byte 255939 (area offset)
  plaintext bytes changed: 15, all within 255936-255951 (stripe 4000)
  key bytes changed: 15, all within 0-15
Last stripe, last XTS block:
  flipped ciphertext byte 255986 (area offset)
  plaintext bytes changed: 16, all within 255984-255999 (stripe 4000)
  key bytes changed: 16, all within 48-63

cryptsetup on the intact image:
  passphrase accepted (exit 0)
cryptsetup on the image with one byte of keyslot area changed:
  No key available with this passphrase.
  exit status: 2
```

Keys and salts are random, so counts can be one lower than the block or
chunk size when a byte comes out unchanged by chance; the ranges do not
vary. Each 64-byte stripe holds four 16-byte XTS blocks, and no XTS
block crosses a stripe boundary, so a damaged block always lies inside
one stripe.

## Why this matters for recovery

The smallest possible loss is one 16-byte XTS block in the last stripe:
128 unknown key bits. Anywhere else, it is 256 bits. Neither can be
searched, so a damaged keyslot cannot be repaired from its own data;
the remedy is a header backup taken before the damage, or another
working keyslot.
