# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Mohammadreza Khellat <mkhellat@beavernets.com>
"""Statistical tests against real and damaged LUKS2 keyslot areas.

Usage (normally via ./run):
    python3 -I entropy_tests.py IMAGE TEXT_FILE WORKDIR

IMAGE is a freshly formatted LUKS2 image (keyslot 0, 64-byte key).
TEXT_FILE supplies English text for the "text residue" case.  WORKDIR
is a scratch directory for damaged copies of IMAGE.

For each sample this prints the chi-squared p-value for byte
uniformity, Shannon entropy, the NIST SP 800-22 Rev. 1a frequency
(monobit) test p-value, the longest zero-byte run and longest pattern
run as scripts/inspect-keyslot computes them, and, for damaged copies
of the image, whether `cryptsetup repair` warns about keyslot 0.
"""
import json
import math
import os
import random
import shutil
import subprocess
import sys

from scipy import stats

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'lib'))
from luks_af import af_merge, af_split  # noqa: E402

SECTOR_SIZE = 512
LUKS_STRIPES = 4000
SEED = 20261028   # fixed seed for the reproducible random samples

img, text_file, work = sys.argv[1:4]
meta = json.loads(subprocess.run(['cryptsetup', 'luksDump', '--dump-json-metadata', img],
                                 check=True, capture_output=True, text=True).stdout)
ks = meta['keyslots']['0']
key_len = ks['key_size']
area_off = int(ks['area']['offset'])
split_len = math.ceil(key_len * LUKS_STRIPES / SECTOR_SIZE) * SECTOR_SIZE
with open(img, 'rb') as fh:
    fh.seek(area_off)
    area = fh.read(split_len)


def chi2_p(data):
    """Chi-squared goodness of fit of byte counts to uniform, 255 dof."""
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    return stats.chisquare(counts).pvalue


def entropy(data):
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    return -sum(c / n * math.log2(c / n) for c in counts if c)


def monobit_p(data):
    """SP 800-22 Rev. 1a §2.1.4: p = erfc(|S_n| / sqrt(n) / sqrt(2))."""
    n = len(data) * 8
    ones = sum(bin(b).count('1') for b in data)
    s = abs(2 * ones - n)
    return math.erfc(s / math.sqrt(n) / math.sqrt(2))


def inspect_keyslot_heuristics(data):
    """Same computation as scripts/inspect-keyslot lines 186-210."""
    zero_max = run = 0
    for b in data:
        run = run + 1 if b == 0 else 0
        zero_max = max(zero_max, run)
    pattern_max = pattern_period = 0
    for period in range(1, 9):
        run = 0
        for i in range(period, len(data)):
            if data[i] == data[i - period]:
                run += 1
                if run > pattern_max:
                    pattern_max, pattern_period = run, period
            else:
                run = 0
    return zero_max, pattern_max, pattern_period


def repair_warns(damaged_area, truncate_to=None):
    """Write the damaged area into a copy of IMAGE and run cryptsetup repair."""
    path = os.path.join(work, 'damaged.img')
    shutil.copyfile(img, path)
    with open(path, 'r+b') as fh:
        fh.seek(area_off)
        fh.write(damaged_area)
        if truncate_to is not None:
            fh.truncate(truncate_to)
    r = subprocess.run(['cryptsetup', 'repair', '--batch-mode', path],
                       capture_output=True, text=True)
    out = (r.stdout + r.stderr).replace(work, '<tmpdir>').strip().splitlines()
    if any('could be corrupted' in line for line in out):
        return 'warns'
    if r.returncode != 0:
        return f'fails: {out[-1] if out else r.returncode}'
    return 'silent'


def row(label, data, repair=''):
    z, p, per = inspect_keyslot_heuristics(data)
    print(f'| {label} | {chi2_p(data):.4f} | {entropy(data):.6f} | {monobit_p(data):.4f} '
          f'| {z} | {p} (period {per}) | {repair} |')


rng = random.Random(SEED)
header = ('| Sample | chi² p | Entropy (bits/B) | Monobit p | Zero run | Pattern run '
          '| `repair` |\n|---|---|---|---|---|---|---|')

print(f'Keyslot 0: {key_len}-byte key, split material {split_len} bytes '
      f'({split_len * 8} bits) at area offset {area_off}.')
print()
print(f'Chi-squared critical values, 255 dof: alpha=0.05 -> {stats.chi2.ppf(0.95, 255):.4f}, '
      f'alpha=0.01 -> {stats.chi2.ppf(0.99, 255):.4f}')

print()
print('== Baselines ==')
print(header)
row('On-disk keyslot area (ciphertext)', area, repair_warns(area))
key = rng.randbytes(key_len)
plain = af_split(key, LUKS_STRIPES, 'sha256', rand=rng.randbytes)
assert af_merge(plain, key_len, LUKS_STRIPES, 'sha256') == key
row('Plaintext AF-split output (not on disk)', plain)
row('Random bytes (seeded PRNG)', rng.randbytes(split_len))


def flip_bits(data, count):
    d = bytearray(data)
    for pos in rng.sample(range(len(d) * 8), count):
        d[pos // 8] ^= 1 << (pos % 8)
    return bytes(d)


def overwrite(data, offset, chunk):
    d = bytearray(data)
    d[offset:offset + len(chunk)] = chunk
    return bytes(d)


text = open(text_file, 'rb').read()[:2048]
cases = [
    ('1 bit flipped', flip_bits(area, 1)),
    ('10 bits flipped, scattered', flip_bits(area, 10)),
    ('4096 bytes overwritten with random bytes', overwrite(area, 8192, rng.randbytes(4096))),
    ('16-byte zero run', overwrite(area, 8192, bytes(16))),
    ('64-byte zero run', overwrite(area, 8192, bytes(64))),
    ('4096-byte zero run', overwrite(area, 8192, bytes(4096))),
    ('Last 25% zeroed', overwrite(area, split_len * 3 // 4, bytes(split_len // 4))),
    ('256 bytes of de ad be ef', overwrite(area, 8192, bytes.fromhex('deadbeef') * 64)),
    ('2048 bytes of English text', overwrite(area, 8192, text)),
]
print()
print('== Damage applied to the on-disk keyslot area ==')
print(header)
for label, data in cases:
    row(label, data, repair_warns(data))

# Truncation: the image ends three quarters of the way through the area.
cut = area_off + split_len * 3 // 4
row('Image truncated 75% into the area (bytes present)', area[:split_len * 3 // 4],
    repair_warns(area, truncate_to=cut))

print()
print('== Damage to one plaintext stripe, merged key (af.c port) ==')
for klen in (32, 64):
    k = rng.randbytes(klen)
    m = bytearray(af_split(k, LUKS_STRIPES, 'sha256', rand=rng.randbytes))
    m[5] ^= 1
    k2 = af_merge(bytes(m), klen, LUKS_STRIPES, 'sha256')
    diff = sum(bin(a ^ b).count('1') for a, b in zip(k, k2))
    print(f'  {klen}-byte key, one bit flipped in stripe 1: '
          f'{diff} of {klen * 8} key bits differ ({100 * diff / (klen * 8):.1f}%)')

print()
print('== Chi-squared detection of scattered zeroed bytes in random data ==')
for size in (128, 1280, 128000, split_len):
    parts = []
    for frac in (0.01, 0.05):
        d = bytearray(rng.randbytes(size))
        for pos in rng.sample(range(size), max(1, round(size * frac))):
            d[pos] = 0
        p = chi2_p(d)
        parts.append(f'{int(frac * 100)}% zeroed: p={p:.4f} {"detected" if p < 0.05 else "missed"}')
    print(f'  {size:6d} bytes: ' + ';  '.join(parts))

print()
print('== Chi-squared false-positive rate on random data, 2000 trials each ==')
for size in (128, 1280, 128000):
    ps = [chi2_p(rng.randbytes(size)) for _ in range(2000)]
    print(f'  {size:6d} bytes: p<0.05 in {sum(p < 0.05 for p in ps) / 20:.2f}%, '
          f'p<0.01 in {sum(p < 0.01 for p in ps) / 20:.2f}%')
