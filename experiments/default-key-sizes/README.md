# Default key sizes

## Claim

When `cryptsetup luksFormat` runs without `--key-size`, the master key
is 512 bits (64 bytes) for ciphers whose mode starts with `xts-`, and
256 bits (32 bytes) for other ciphers. The keyslot area uses the
volume's own cipher and key size when that cipher can encrypt
keyslots.

Used in [`docs/af-splitting-explained.md`](../../docs/af-splitting-explained.md).

## Why, from the source

cryptsetup's `get_adjusted_key_size()`
([`src/utils_luks.c`](https://gitlab.com/cryptsetup/cryptsetup/-/blob/bae21790d59897ac50e5471f953f76b3a58aeeb6/src/utils_luks.c#L142-154),
lines 142–154) doubles the compiled-in default key size (256 bits) when
no `--key-size` is given and the mode starts with `xts-` (or the cipher
is a `capi:xts(...)` spec). The compiled-in defaults are in
[`configure.ac`](https://gitlab.com/cryptsetup/cryptsetup/-/blob/bae21790d59897ac50e5471f953f76b3a58aeeb6/configure.ac#L794-803),
lines 794–803. `crypt_keyslot_get_encryption()`
([`lib/setup.c`](https://gitlab.com/cryptsetup/cryptsetup/-/blob/bae21790d59897ac50e5471f953f76b3a58aeeb6/lib/setup.c#L6679-6720),
lines 6679–6720) reuses the volume cipher for keyslots unless it is
incompatible or the volume uses hardware OPAL encryption.

## Requirements

`cryptsetup`, `python3`, `truncate`. No root. The kernel must support
each cipher (Serpent, Twofish, Adiantum); a cipher it does not support
shows up as a failed `luksFormat` line instead of key sizes.

## Run

```
experiments/default-key-sizes/run
```

For each cipher, the script formats a throwaway image without
`--key-size` and prints `key_size` and the `area` cipher and key size
from keyslot 0's metadata. The Adiantum ciphers are spelled the way
cryptsetup's v2.0.6 release notes give them
(`xchacha20,aes-adiantum-plain64`; `docs/v2.0.6-ReleaseNotes`,
lines 55–66).

## Result (2026-10-28)

```
cryptsetup 2.8.8 flags: UDEV BLKID KEYRING KERNEL_CAPI HW_OPAL 

aes-xts-plain64                    key_size= 64  area.encryption=aes-xts-plain64  area.key_size=64  segment sector_size=4096
serpent-xts-plain64                key_size= 64  area.encryption=serpent-xts-plain64  area.key_size=64  segment sector_size=4096
twofish-xts-plain64                key_size= 64  area.encryption=twofish-xts-plain64  area.key_size=64  segment sector_size=4096
aes-cbc-essiv:sha256               key_size= 32  area.encryption=aes-cbc-essiv:sha256  area.key_size=32  segment sector_size=4096
xchacha20,aes-adiantum-plain64     key_size= 32  area.encryption=xchacha20,aes-adiantum-plain64  area.key_size=32  segment sector_size=4096
xchacha12,aes-adiantum-plain64     key_size= 32  area.encryption=xchacha12,aes-adiantum-plain64  area.key_size=32  segment sector_size=4096
```

`segment sector_size` is the data segment's encryption sector size,
which cryptsetup chose for this image file; it does not affect the
keyslot area, which is always encrypted in 512-byte sectors.
