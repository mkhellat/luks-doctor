# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Mohammadreza Khellat <mkhellat@beavernets.com>
"""Parse both LUKS2 binary headers of an image and report the layout.

Usage (normally via ./run):  python3 -I parse_headers.py IMAGE

Decodes struct luks2_hdr_disk as given in the LUKS2 On-Disk Format
Specification v1.1.4, Figure 2 (p.5), checks each header's checksum the
way cryptsetup's hdr_checksum_calculate() does (lib/luks2/
luks2_disk_metadata.c, cryptsetup commit bae21790): hash the binary
header with the csum field zeroed, followed by the JSON area.  Then it
prints the regions from the JSON metadata and what fills keyslot 0's
area beyond its split key material.
"""
import hashlib
import json
import math
import struct
import sys

LAYOUT = [  # (name, format, size) in on-disk order, spec Figure 2
    ('magic', '6s', 6), ('version', '>H', 2), ('hdr_size', '>Q', 8),
    ('seqid', '>Q', 8), ('label', '48s', 48), ('csum_alg', '32s', 32),
    ('salt', '64s', 64), ('uuid', '40s', 40), ('subsystem', '48s', 48),
    ('hdr_offset', '>Q', 8), ('_padding', '184s', 184), ('csum', '64s', 64),
    ('_padding4096', '3584s', 3584),
]
BIN_LEN = 4096
SECTOR_SIZE = 512
LUKS_STRIPES = 4000


def parse(buf):
    fields, off = {}, 0
    for name, fmt, size in LAYOUT:
        fields[name] = (off, struct.unpack(fmt, buf[off:off + size])[0])
        off += size
    assert off == BIN_LEN
    return fields


def cstr(b):
    return b.split(b'\0', 1)[0].decode(errors='replace')


def checksum_ok(img, offset, f):
    hdr_size = f['hdr_size'][1]
    with open(img, 'rb') as fh:
        fh.seek(offset)
        blob = bytearray(fh.read(hdr_size))
    csum_off = f['csum'][0]
    stored = bytes(blob[csum_off:csum_off + 64])
    blob[csum_off:csum_off + 64] = bytes(64)
    alg = cstr(f['csum_alg'][1])
    digest = hashlib.new(alg, bytes(blob)).digest()
    return stored[:len(digest)] == digest and not any(stored[len(digest):])


img = sys.argv[1]
with open(img, 'rb') as fh:
    first = fh.read(BIN_LEN)
p = parse(first)
hdr_size = p['hdr_size'][1]
with open(img, 'rb') as fh:
    fh.seek(hdr_size)
    second = fh.read(BIN_LEN)
s = parse(second)

print('Binary header fields (offset in struct, primary value | secondary value):')
for name, _, size in LAYOUT:
    off = p[name][0]
    a, b = p[name][1], s[name][1]
    if name in ('label', 'csum_alg', 'uuid', 'subsystem'):
        a, b = repr(cstr(a)), repr(cstr(b))
    elif name == 'magic':
        a, b = repr(a), repr(b)
    elif name in ('salt', 'csum'):
        a, b = a.hex()[:16] + '...', b.hex()[:16] + '...'
    elif name.startswith('_padding'):
        a = 'all zero' if not any(a) else 'NOT ZERO'
        b = 'all zero' if not any(b) else 'NOT ZERO'
    same = 'same' if p[name][1] == s[name][1] else 'DIFFERENT'
    print(f'  0x{off:04x} ({off:4d}) {name:13s} {size:4d} B  {a} | {b}  [{same}]')

print()
print(f'Primary header checksum valid:   {checksum_ok(img, 0, p)}')
print(f'Secondary header checksum valid: {checksum_ok(img, hdr_size, s)}')
print(f'Nonzero bytes after byte 512 of the binary header: '
      f'primary {sum(1 for x in first[512:] if x)}, secondary {sum(1 for x in second[512:] if x)}')

with open(img, 'rb') as fh:
    fh.seek(BIN_LEN)
    json_area = fh.read(hdr_size - BIN_LEN)
meta = json.loads(json_area.split(b'\0', 1)[0])
cfg = meta['config']
seg = meta['segments']['0']
ks = meta['keyslots']['0']
area_off, area_size = int(ks['area']['offset']), int(ks['area']['size'])
print()
print('Layout:')
print(f'  primary binary header      0x{0:08x}  {BIN_LEN} B')
print(f'  primary JSON area          0x{BIN_LEN:08x}  {hdr_size - BIN_LEN} B')
print(f'  secondary binary header    0x{hdr_size:08x}  {BIN_LEN} B')
print(f'  secondary JSON area        0x{hdr_size + BIN_LEN:08x}  {hdr_size - BIN_LEN} B')
print(f'  keyslots area (config)     0x{2 * hdr_size:08x}  {int(cfg["keyslots_size"])} B')
print(f'  keyslot 0 area             0x{area_off:08x}  {area_size} B')
print(f'  data segment               0x{int(seg["offset"]):08x}  size {seg["size"]}')
print(f'  config.json_size = {cfg["json_size"]}, config.keyslots_size = {cfg["keyslots_size"]}')

split_len = math.ceil(ks['key_size'] * LUKS_STRIPES / SECTOR_SIZE) * SECTOR_SIZE
with open(img, 'rb') as fh:
    fh.seek(area_off + split_len)
    tail = fh.read(area_size - split_len)
print()
print(f'Keyslot 0: key_size {ks["key_size"]} B, split material {split_len} B, '
      f'area {area_size} B, unused tail {len(tail)} B, '
      f'tail is {"all zero" if not any(tail) else "NOT all zero"}')
