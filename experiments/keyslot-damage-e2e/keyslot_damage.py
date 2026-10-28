# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Mohammadreza Khellat <mkhellat@beavernets.com>
"""How does one damaged byte in a real LUKS2 keyslot area reach the key?

Usage (normally via ./run):
    python3 -I keyslot_damage.py IMAGE PASSPHRASE_FILE VOLUME_KEY_FILE

IMAGE must be a LUKS2 image whose keyslot 0 uses pbkdf2 (so no Argon2
library is needed), af type luks1, and an aes-xts-plain64 area.
VOLUME_KEY_FILE is the key written by
`cryptsetup luksDump --dump-volume-key --volume-key-file`.

Re-implements cryptsetup's keyslot unlock path independently, following
lib/luks2/luks2_keyslot_luks2.c at cryptsetup commit
bae21790d59897ac50e5471f953f76b3a58aeeb6:
  1. derive the area key from the passphrase (crypt_pbkdf, line 332);
  2. read AF_split_sectors(key_len, LUKS_STRIPES) * SECTOR_SIZE bytes
     from area.offset (line 315) and decrypt them with the area cipher
     in 512-byte sectors, IVs counting from sector 0 of the area
     (luks2_decrypt_from_storage, lines 55-89);
  3. AF_merge the result (line 360).
It checks this reproduces the real volume key, then flips single
ciphertext bytes and reports which plaintext and key bytes change.
"""
import base64
import hashlib
import json
import math
import os
import struct
import subprocess
import sys

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'lib'))
from luks_af import af_merge  # noqa: E402

SECTOR_SIZE = 512   # lib/libcryptsetup_macros.h line 39
LUKS_STRIPES = 4000  # lib/libcryptsetup_macros.h line 62

img, passfile, vkfile = sys.argv[1:4]
meta = json.loads(subprocess.run(
    ['cryptsetup', 'luksDump', '--dump-json-metadata', img],
    check=True, capture_output=True, text=True).stdout)
ks = meta['keyslots']['0']
assert ks['kdf']['type'] == 'pbkdf2', 'keyslot 0 must use pbkdf2'
assert ks['af']['type'] == 'luks1'
assert ks['area']['encryption'] == 'aes-xts-plain64'

key_len = ks['key_size']
af_hash = ks['af']['hash']
area_offset = int(ks['area']['offset'])
af_size = math.ceil(key_len * LUKS_STRIPES / SECTOR_SIZE) * SECTOR_SIZE

area_key = hashlib.pbkdf2_hmac(
    ks['kdf']['hash'], open(passfile, 'rb').read(),
    base64.b64decode(ks['kdf']['salt']), ks['kdf']['iterations'],
    ks['area']['key_size'])
volume_key = open(vkfile, 'rb').read()
with open(img, 'rb') as f:
    f.seek(area_offset)
    ciphertext = f.read(af_size)


def decrypt_area(ct):
    out = b''
    for s in range(len(ct) // SECTOR_SIZE):
        tweak = struct.pack('<Q', s) + bytes(8)   # plain64: little-endian sector number
        d = Cipher(algorithms.AES(area_key), modes.XTS(tweak)).decryptor()
        out += d.update(ct[s * SECTOR_SIZE:(s + 1) * SECTOR_SIZE]) + d.finalize()
    return out


def changed(a, b):
    return [i for i in range(len(a)) if a[i] != b[i]]


plaintext = decrypt_area(ciphertext)
assert af_merge(plaintext, key_len, LUKS_STRIPES, af_hash) == volume_key, \
    'independent unlock did NOT reproduce the volume key'
print(f'Independent unlock reproduces cryptsetup\'s volume key: {key_len}-byte key, '
      f'{LUKS_STRIPES} stripes, {af_hash}, aes-xts-plain64 in {SECTOR_SIZE}-byte sectors.')


def probe(label, offset):
    ct = bytearray(ciphertext)
    ct[offset] ^= 0x01
    pt = decrypt_area(bytes(ct))
    pd = changed(plaintext, pt)
    kd = changed(af_merge(pt, key_len, LUKS_STRIPES, af_hash), volume_key)
    print(f'{label}\n'
          f'  flipped ciphertext byte {offset} (area offset)\n'
          f'  plaintext bytes changed: {len(pd)}, all within {pd[0]}-{pd[-1]} '
          f'(stripe {pd[0] // key_len + 1})\n'
          f'  key bytes changed: {len(kd)}, all within {kd[0]}-{kd[-1]}')


last = key_len * (LUKS_STRIPES - 1)
probe('Stripe 1:', 5)
probe('Stripe 2000:', key_len * 1999 + key_len - 24)
probe('Last stripe, first XTS block:', last + 3)
probe('Last stripe, last XTS block:', last + key_len - 14)
