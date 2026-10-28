# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Mohammadreza Khellat <mkhellat@beavernets.com>
"""How far does damage to one AF stripe spread into the merged key?

Splits a random key with the af.c port, checks the round trip, then
flips one bit in chosen stripes and reports which key bytes change.
Run through ./run; see README.md.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'lib'))
from luks_af import af_merge, af_split  # noqa: E402

STRIPES = 4000      # LUKS_STRIPES, lib/libcryptsetup_macros.h
HASH = 'sha256'


def changed(a, b):
    return [i for i in range(len(a)) if a[i] != b[i]]


def run(key_len, probes):
    key = os.urandom(key_len)
    material = af_split(key, STRIPES, HASH)
    assert af_merge(material, key_len, STRIPES, HASH) == key, 'round trip failed'
    print(f'{key_len}-byte key, {STRIPES} stripes, {HASH}: round trip OK')
    for stripe, byte in probes:
        m = bytearray(material)
        m[key_len * (stripe - 1) + byte] ^= 0x01
        d = changed(af_merge(bytes(m), key_len, STRIPES, HASH), key)
        print(f'  flip one bit in stripe {stripe:4d}, byte {byte:2d}: '
              f'{len(d):2d} key bytes changed, all within bytes {d[0]}-{d[-1]}')


run(64, [(1, 5), (1, 40), (2000, 31), (2000, 32), (3999, 63), (4000, 10)])
run(32, [(1, 5), (2000, 31), (4000, 10)])
