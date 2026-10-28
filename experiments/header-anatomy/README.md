# Header anatomy

## Claims

On a LUKS2 image formatted with cryptsetup's defaults:

- the binary header has the field layout of the LUKS2 specification's
  `struct luks2_hdr_disk`, with only its first 512 bytes in use;
- the primary and secondary binary headers differ in exactly four
  fields: `magic`, `salt`, `hdr_offset` (each header records its own
  offset, so the primary's is 0) and `csum`;
- each header's checksum covers its binary header (with `csum` zeroed)
  and its JSON area;
- the default layout is a 16 KiB header copy (4 KiB binary header and
  12 KiB JSON area) twice, then the keyslots area, with the data segment
  at 16 MiB;
- the part of a keyslot's area beyond its split key material is not
  zero (cryptsetup fills the whole keyslots area with random data when
  formatting);
- a read-only command such as `luksDump` works with a damaged primary
  header but does not fix it, and `cryptsetup repair` rewrites it from
  the secondary with a new salt.

Used in [`docs/luks2-header-anatomy.md`](../../docs/luks2-header-anatomy.md).

## Sources

- LUKS2 On-Disk Format Specification v1.1.4
  ([PDF at commit `a81aa2fe`](https://gitlab.com/cryptsetup/LUKS2-docs/-/blob/a81aa2fef8d176debdbec297c1e0b74bb50cfee8/luks2_doc_wip.pdf)):
  §2 (p.3), §2.1 with Table 1 and Figure 2 (pp.4–5).
- cryptsetup at commit
  [`bae21790`](https://gitlab.com/cryptsetup/cryptsetup/-/tree/bae21790d59897ac50e5471f953f76b3a58aeeb6):
  `hdr_checksum_calculate()` and `LUKS2_disk_hdr_read()` in
  `lib/luks2/luks2_disk_metadata.c` (lines 61 and 640–800), and
  `LUKS2_wipe_header_areas()` in `lib/luks2/luks2_json_format.c`
  (lines 325–379), which zeroes the metadata areas and then fills the
  keyslots area with `CRYPT_WIPE_RANDOM`.

## Requirements

`cryptsetup`, `python3`, `truncate`, `dd`, `cmp`. No root. The format
uses cryptsetup's default Argon2id settings, which benchmark for about
2 seconds and can use up to 1 GiB of RAM.

## Run

```
experiments/header-anatomy/run
```

The script formats a throwaway image, prints `luksDump` (with random
values elided), and runs [`parse_headers.py`](parse_headers.py), which
decodes both binary headers, recomputes their checksums, prints the
layout from the JSON metadata, and checks keyslot 0's unused tail. It
then flips one byte of the primary JSON area at offset 8192, runs
`luksDump` and `repair`, and compares the result with the original.

## Result (2026-10-28)

`luksDump` section (salts, UUID and digest elided by the script):

```
LUKS header information
Version:       	2
Epoch:         	3
Metadata area: 	16384 [bytes]
Keyslots area: 	16744448 [bytes]
UUID:          	<random>
Label:         	(no label)
Subsystem:     	(no subsystem)
Flags:       	(no flags)

Data segments:
  0: crypt
	offset: 16777216 [bytes]
	length: (whole device)
	cipher: aes-xts-plain64
	sector: 4096 [bytes]

Keyslots:
  0: luks2
	Key:        512 bits
	Priority:   normal
	Cipher:     aes-xts-plain64
	Cipher key: 512 bits
	PBKDF:      argon2id
	Time cost:  5
	Memory:     1048576
	Threads:    4
	Salt:       <random>
	            <random>
	AF stripes: 4000
	AF hash:    sha256
	Area offset:32768 [bytes]
	Area length:258048 [bytes]
	Digest ID:  0
Tokens:
Digests:
  0: pbkdf2
	Hash:       sha256
	Iterations: 145312
	Salt:       <random>
	            <random>
	Digest:     <random>
	            <random>
```

Parsed headers, layout and damage test:

```
Binary header fields (offset in struct, primary value | secondary value):
  0x0000 (   0) magic            6 B  b'LUKS\xba\xbe' | b'SKUL\xba\xbe'  [DIFFERENT]
  0x0006 (   6) version          2 B  2 | 2  [same]
  0x0008 (   8) hdr_size         8 B  16384 | 16384  [same]
  0x0010 (  16) seqid            8 B  3 | 3  [same]
  0x0018 (  24) label           48 B  '' | ''  [same]
  0x0048 (  72) csum_alg        32 B  'sha256' | 'sha256'  [same]
  0x0068 ( 104) salt            64 B  0e85879858af5d72... | ecb242dd97aa9763...  [DIFFERENT]
  0x00a8 ( 168) uuid            40 B  '8429b3c7-15c7-4ad7-8733-ba87c8cc959f' | '8429b3c7-15c7-4ad7-8733-ba87c8cc959f'  [same]
  0x00d0 ( 208) subsystem       48 B  '' | ''  [same]
  0x0100 ( 256) hdr_offset       8 B  0 | 16384  [DIFFERENT]
  0x0108 ( 264) _padding       184 B  all zero | all zero  [same]
  0x01c0 ( 448) csum            64 B  b676b78b32a14a9c... | bbf4ab81299c3eea...  [DIFFERENT]
  0x0200 ( 512) _padding4096  3584 B  all zero | all zero  [same]

Primary header checksum valid:   True
Secondary header checksum valid: True
Nonzero bytes after byte 512 of the binary header: primary 0, secondary 0

Layout:
  primary binary header      0x00000000  4096 B
  primary JSON area          0x00001000  12288 B
  secondary binary header    0x00004000  4096 B
  secondary JSON area        0x00005000  12288 B
  keyslots area (config)     0x00008000  16744448 B
  keyslot 0 area             0x00008000  258048 B
  data segment               0x01000000  size dynamic
  config.json_size = 12288, config.keyslots_size = 16744448

Keyslot 0: key_size 64 B, split material 256000 B, area 258048 B, unused tail 2048 B, tail is NOT all zero

== Damage: flip one byte of the primary JSON area ==
-- luksDump on the damaged image (read-only):
   luksDump succeeded
   image still differs from before the damage
-- cryptsetup repair on the damaged image:
   repair succeeded
  0x0068 ( 104) salt            64 B  3a8ee7e395645acd... | ecb242dd97aa9763...  [DIFFERENT]
Primary header checksum valid:   True
Secondary header checksum valid: True
   primary JSON area identical to before the damage
```

Both listings come from the same run. Salts, UUID, checksums and the
digest iteration count change on every run; the
field layout, offsets and sizes do not. After `repair`, the primary
header's salt (`3a8ee7e3...`) differs from the one it had before the
damage (`0e858798...`): the repaired header got a new salt, as
`LUKS2_disk_hdr_read()` does when it rewrites a damaged copy (lines
743–768) and as the specification requires (§2.1, p.4).
