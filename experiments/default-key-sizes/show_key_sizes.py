# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Mohammadreza Khellat <mkhellat@beavernets.com>
"""Print the key sizes cryptsetup recorded for keyslot 0 of a LUKS2 image.

Usage (normally via ./run):  python3 -I show_key_sizes.py CIPHER IMAGE
"""
import json
import subprocess
import sys

cipher, img = sys.argv[1:3]
meta = json.loads(subprocess.run(
    ['cryptsetup', 'luksDump', '--dump-json-metadata', img],
    check=True, capture_output=True, text=True).stdout)
keyslot = meta['keyslots']['0']
segment = meta['segments']['0']
area = keyslot['area']
print(f'{cipher:34s} key_size={keyslot["key_size"]:3d}  '
      f'area.encryption={area["encryption"]}  area.key_size={area["key_size"]}  '
      f'segment sector_size={segment["sector_size"]}')
