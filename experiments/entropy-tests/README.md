# Entropy tests

## Claims

Run against a real LUKS2 keyslot area and damaged copies of it:

- an intact on-disk keyslot area (ciphertext) passes the chi-squared
  byte-uniformity test and the NIST SP 800-22 Rev. 1a frequency
  (monobit) test, with Shannon entropy just under 8 bits/byte, like
  random data;
- damage that leaves random-looking bytes, such as flipped bits or a
  block overwritten with random data, changes none of these results,
  `scripts/inspect-keyslot`'s heuristics or `cryptsetup repair`;
- chi-squared, entropy and the monobit test catch large low-entropy
  damage (kilobytes of zeros) but miss a 64-byte zero run or a 256-byte
  repeated pattern, which `inspect-keyslot`'s heuristics and `cryptsetup
  repair` both catch;
- chi-squared catches 2 KiB of English text, which entropy and the
  monobit test barely register;
- a truncated image is not a statistical anomaly: the bytes that remain
  are still random, and cryptsetup rejects the device instead;
- one flipped bit in a plaintext stripe changes about half the bits of
  the 32-byte chunk of the key it lines up with: about half of a
  32-byte key, about a quarter of a 64-byte key;
- chi-squared needs about 5% scattered zeroed bytes to detect them in
  128 or 1280 bytes of random data, and 1% at keyslot-area sizes; its
  false-positive rate on random data matches its significance level
  even at 128 bytes.

Used in [`docs/entropy-analysis.md`](../../docs/entropy-analysis.md).

## Method

[`run`](run) formats a throwaway image with cryptsetup's default
cipher (64-byte key; PBKDF2 with 1000 iterations to keep it fast), and
[`entropy_tests.py`](entropy_tests.py) reads keyslot 0's 256,000 bytes
of split material from it, as stored on disk. For each sample it
computes:

- **chi² p**: `scipy.stats.chisquare` of the 256 byte counts against a
  uniform distribution (255 degrees of freedom);
- **Entropy**: Shannon entropy of the byte distribution, bits per byte;
- **Monobit p**: SP 800-22 Rev. 1a §2.1 frequency test,
  `erfc(|S_n| / sqrt(2n))`;
- **Zero run** and **Pattern run**: the same computation as
  `scripts/inspect-keyslot` (lines 186–210): the longest run of zero
  bytes, and the longest run of consecutive positions *i* where byte
  *i* equals byte *i − period*, for periods 1 to 8;
- **`repair`**: whether `cryptsetup repair`, run on a copy of the image
  with the damaged area written back, warns that keyslot 0 "could be
  corrupted".

Damage is applied 8192 bytes into the area unless stated. The English
text is the first 2048 bytes of the repository's `LICENSE`. Random
samples, the plaintext AF-split output and the bit positions use a
fixed seed; the image, and so the on-disk area, is new on every run.

## Requirements

`cryptsetup`, `python3` with [`scipy`](https://scipy.org/) (1.18.1 was
used), `truncate`. No root. A run takes about 20 seconds.

## Run

```
experiments/entropy-tests/run
```

## Result (2026-10-28)

```
cryptsetup 2.8.8 flags: UDEV BLKID KEYRING KERNEL_CAPI HW_OPAL 
scipy 1.18.1
Keyslot 0: 64-byte key, split material 256000 bytes (2048000 bits) at area offset 32768.

Chi-squared critical values, 255 dof: alpha=0.05 -> 293.2478, alpha=0.01 -> 310.4574

== Baselines ==
| Sample | chi² p | Entropy (bits/B) | Monobit p | Zero run | Pattern run | `repair` |
|---|---|---|---|---|---|---|
| On-disk keyslot area (ciphertext) | 0.7238 | 7.999321 | 0.4997 | 2 | 2 (period 1) | silent |
| Plaintext AF-split output (not on disk) | 0.5215 | 7.999288 | 0.3924 | 2 | 2 (period 1) |  |
| Random bytes (seeded PRNG) | 0.4797 | 7.999280 | 0.6771 | 2 | 2 (period 1) |  |

== Damage applied to the on-disk keyslot area ==
| Sample | chi² p | Entropy (bits/B) | Monobit p | Zero run | Pattern run | `repair` |
|---|---|---|---|---|---|---|
| 1 bit flipped | 0.7266 | 7.999321 | 0.4988 | 2 | 2 (period 1) | silent |
| 10 bits flipped, scattered | 0.7200 | 7.999320 | 0.5014 | 2 | 2 (period 1) | silent |
| 4096 bytes overwritten with random bytes | 0.5610 | 7.999293 | 0.4010 | 2 | 2 (period 1) | silent |
| 16-byte zero run | 0.7199 | 7.999320 | 0.4438 | 16 | 15 (period 1) | silent |
| 64-byte zero run | 0.6632 | 7.999310 | 0.2933 | 64 | 63 (period 1) | warns |
| 4096-byte zero run | 0.0000 | 7.975556 | 0.0000 | 4096 | 4095 (period 1) | warns |
| Last 25% zeroed | 0.0000 | 6.787521 | 0.0000 | 64000 | 63999 (period 1) | warns |
| 256 bytes of de ad be ef | 0.6048 | 7.999300 | 0.9666 | 2 | 252 (period 4) | warns |
| 2048 bytes of English text | 0.0000 | 7.998537 | 0.0397 | 2 | 27 (period 1) | warns |
| Image truncated 75% into the area (bytes present) | 0.5346 | 7.999051 | 0.5700 | 2 | 2 (period 1) | fails: Device <tmpdir>/damaged.img is not a valid LUKS device. |

== Damage to one plaintext stripe, merged key (af.c port) ==
  32-byte key, one bit flipped in stripe 1: 125 of 256 key bits differ (48.8%)
  64-byte key, one bit flipped in stripe 1: 120 of 512 key bits differ (23.4%)

== Chi-squared detection of scattered zeroed bytes in random data ==
     128 bytes: 1% zeroed: p=0.7977 missed;  5% zeroed: p=0.0055 detected
    1280 bytes: 1% zeroed: p=0.1882 missed;  5% zeroed: p=0.0000 detected
  128000 bytes: 1% zeroed: p=0.0000 detected;  5% zeroed: p=0.0000 detected
  256000 bytes: 1% zeroed: p=0.0000 detected;  5% zeroed: p=0.0000 detected

== Chi-squared false-positive rate on random data, 2000 trials each ==
     128 bytes: p<0.05 in 5.55%, p<0.01 in 1.45%
    1280 bytes: p<0.05 in 4.75%, p<0.01 in 1.00%
  128000 bytes: p<0.05 in 5.35%, p<0.01 in 0.60%
```

Rows computed from the on-disk area change from run to run, because
each run formats a new image; the seeded rows do not.
