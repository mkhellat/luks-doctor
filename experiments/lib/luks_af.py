# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Mohammadreza Khellat <mkhellat@beavernets.com>
"""Python port of cryptsetup's AF splitter (lib/luks1/af.c).

Ported line by line from cryptsetup commit
fb6b9480fa519c70366d6743ec84cb0f3afcc8c7; the same functions are
unchanged at bae21790d59897ac50e5471f953f76b3a58aeeb6 (only shifted
down one line).  Line numbers below refer to fb6b9480:
https://gitlab.com/cryptsetup/cryptsetup/-/blob/fb6b9480fa519c70366d6743ec84cb0f3afcc8c7/lib/luks1/af.c

This is for experiments only.  It is not constant-time and does not
zero memory, so never use it on real key material.
"""
import hashlib
import os
import struct


def hash_buf(src, index, length, hash_name):
    """af.c lines 27-48: hash(be32(index) || src), truncated to length."""
    return hashlib.new(hash_name, struct.pack('>I', index) + src).digest()[:length]


def diffuse(buf, hash_name):
    """af.c lines 54-84.

    Cuts buf into digest-sized chunks and hashes each chunk on its own,
    with its index; a final shorter chunk is hashed and truncated.  A
    change to one chunk therefore changes no other chunk.
    """
    ds = hashlib.new(hash_name).digest_size
    out = b''
    blocks, padding = divmod(len(buf), ds)
    for i in range(blocks):
        out += hash_buf(buf[ds * i:ds * (i + 1)], i, ds, hash_name)
    if padding:
        out += hash_buf(buf[ds * blocks:], blocks, padding, hash_name)
    return out


def xor(a, b):
    """af.c lines 19-25."""
    return bytes(x ^ y for x, y in zip(a, b))


def af_split(key, stripes, hash_name, rand=os.urandom):
    """af.c lines 91-119.  Returns the concatenated split material."""
    acc = bytes(len(key))
    out = []
    for _ in range(stripes - 1):
        s = rand(len(key))
        out.append(s)
        acc = diffuse(xor(s, acc), hash_name)
    out.append(xor(key, acc))
    return b''.join(out)


def af_merge(material, key_len, stripes, hash_name):
    """af.c lines 121-143."""
    acc = bytes(key_len)
    for i in range(stripes - 1):
        acc = diffuse(xor(material[key_len * i:key_len * (i + 1)], acc), hash_name)
    return xor(material[key_len * (stripes - 1):key_len * stripes], acc)
