# Argon2id vs. PBKDF2: LUKS1 vs. LUKS2, Cryptographically

LUKS1 derives the key that unlocks a keyslot with PBKDF2; LUKS2
defaults to Argon2id. The difference is usually summarized as
"Argon2id is memory-hard, PBKDF2 isn't". This document backs that
summary with the specifications, cryptsetup's source, and published
cracking benchmarks.

## Contents

- [PBKDF2 (LUKS1), precisely](#pbkdf2-luks1-precisely)
- [Argon2id (LUKS2 default), precisely](#argon2id-luks2-default-precisely)
- [What cryptsetup actually does, per code](#what-cryptsetup-actually-does-per-code)
- [Cleartext KDF parameters: what they do and don't leak](#cleartext-kdf-parameters-what-they-do-and-dont-leak)
- [Summary](#summary)

## PBKDF2 (LUKS1), precisely

**Specification.** PBKDF2 is defined in §5.2 of PKCS #5. The current
version is RFC 8018, *PKCS #5: Password-Based Cryptography
Specification Version 2.1*, K. Moriarty (ed.), B. Kaliski, A. Rusch,
January 2017, Informational
(<https://www.rfc-editor.org/rfc/rfc8018>), which "obsoletes RFC 2898",
the September 2000 version 2.0. The definition of PBKDF2 is the same
in both:

> F (P, S, c, i) = U_1 \xor U_2 \xor ... \xor U_c
>
> where
>
> U_1 = PRF (P, S || INT (i)) ,
> U_2 = PRF (P, U_1) ,
> ...
> U_c = PRF (P, U_{c-1}) .

`P` is the passphrase, `S` the salt, `c` the iteration count, and the
PRF is HMAC with the configured hash. Each output block costs `c`
PRF calls in sequence, each depending only on the previous output, so
computing it needs almost no memory, and the specification asks for
none. An attacker's guessing rate is therefore limited by how many hash
units they can run in parallel, which is what GPUs and dedicated
hardware provide cheaply.

**How LUKS1 chooses `c`.** When a keyslot is created, cryptsetup
benchmarks PBKDF2 on the local machine and picks the iteration count
that takes a target time, 2000 ms by default (see
[below](#what-cryptsetup-actually-does-per-code)), and stores it in
the header. The count is fixed from then on, so as hardware gets
faster, the keyslot gets cheaper to attack; nothing re-tunes it unless
the keyslot is rewritten.

**GPU cracking speed.** hashcat's LUKS1 mode (`-m 14600`) benchmarks at
a fixed iteration count, "equal to jtr -test", that is, the same as
John the Ripper's test:

```c
static const int ROUNDS_LUKS = 163044; // this equal to jtr -test
```

([`src/modules/module_14600.c`](https://github.com/hashcat/hashcat/blob/v7.0.0/src/modules/module_14600.c#L201),
line 201 at tag `v7.0.0`.) Published benchmark results at that count:

| GPU | hashcat version | Guesses/sec | Source |
|---|---|---|---|
| NVIDIA RTX 3090 | 6.1.1 | 28,356 H/s | <https://gist.github.com/Chick3nman/e4fcee00cb6d82874dace72106d73fef> |
| NVIDIA RTX 4090 | 6.2.6 | 65,253 H/s | <https://gist.github.com/Chick3nman/32e662a5bb63bc4f51b847bb422222fd> |

That is 2.30 times faster across two GPU generations at the same
iteration count. At the RTX 3090's rate, a day is about 2.45 billion
guesses. A real header's cost per guess scales with its own iteration
count: one LUKS1 header posted in a hashcat bug report shows a keyslot
with `Iterations: 109010` (and `MK iterations: 27250` for the
master-key digest)
(<https://github.com/hashcat/hashcat/issues/1729>). Scaling the RTX
3090 rate by 163,044 / 109,010 gives about 42,400 guesses per second
for that keyslot; this is arithmetic, not a measurement.

## Argon2id (LUKS2 default), precisely

**Specifications.**

- **RFC 9106**, *Argon2 Memory-Hard Function for Password Hashing and
  Proof-of-Work Applications*, A. Biryukov, D. Dinu, D. Khovratovich,
  S. Josefsson, September 2021
  (<https://www.rfc-editor.org/rfc/rfc9106>): the current
  specification, including Argon2id.
- The peer-reviewed paper: A. Biryukov, D. Dinu, D. Khovratovich,
  "Argon2: New Generation of Memory-Hard Functions for Password Hashing
  and Other Applications", *2016 IEEE European Symposium on Security
  and Privacy (EuroS&P)*, pp. 292–302, DOI
  [10.1109/EuroSP.2016.31](https://doi.org/10.1109/EuroSP.2016.31).
- The designers' specification documents, *Argon2: the memory-hard
  function for password hashing and other applications*:
  "Version 1.2.1 of Argon2: PHC release" (December 2015,
  <https://password-hashing.net/argon2-specs.pdf>) and version 1.3
  (March 2017,
  <https://github.com/P-H-C/phc-winner-argon2/blob/master/argon2-specs.pdf>).
  Version 1.2.1 specifies "two flavors of Argon2 – Argon2d and
  Argon2i" (§3) and describes Argon2id only in Appendix B, as
  functionality "not officially included in the PHC release"; version
  1.3 includes it as type 2.

**The three cost parameters** (RFC 9106 §3.1):

> Degree of parallelism p determines how many independent (but
> synchronizing) computational chains (lanes) can be run.
>
> Memory size m MUST be an integer number of kibibytes from 8*p to
> 2^(32)-1.
>
> Number of passes t (used to tune the running time independently of
> the memory size) MUST be an integer number from 1 to 2^(32)-1.

**Why Argon2id rather than Argon2i or Argon2d** (RFC 9106 §1):

> Argon2d uses data-dependent memory access, which makes it suitable
> for cryptocurrencies and proof-of-work applications with no threats
> from side-channel timing attacks. Argon2i uses data-independent
> memory access, which is preferred for password hashing and
> password-based key derivation. Argon2id works as Argon2i for the
> first half of the first pass over the memory and as Argon2d for the
> rest, thus providing both side-channel attack protection and
> brute-force cost savings due to time-memory trade-offs.

In Argon2i, which memory block is read next depends only on its
position, not on the data, so an observer of memory access timing
learns nothing about the passphrase; but an attacker can also work out
in advance which blocks will be needed, which helps time-memory
trade-off attacks that store fewer blocks and recompute the rest. In
Argon2d, the next block depends on the data computed so far, which
defeats that precomputation but makes the access pattern depend on the
secret. Argon2id uses the first approach for the first half of the
first pass and the second for the rest. RFC 9106 recommends Argon2id
as the default variant (§7.4).

**Why memory-hardness raises an attacker's hardware cost.** From the
designers' specification, §2.1 "Motivation" (p.3, in both v1.2.1 and
v1.3):

> We aim to maximize the cost of password cracking on ASICs. There can
> be different approaches to measure this cost, but we turn to one of
> the most popular – the time-area product

and, in the same section, "The 50-nm DRAM implementation takes 550 mm²
per GByte", "The Blake2b implementation in the 65-nm process should
take about 0.1 mm²", and "The maximum memory bandwidth achieved by
modern GPUs is around 400 GB/sec". By these figures, the chip area of
1 GB of memory would hold about 5,500 Blake2b cores. The authors call
these estimates rough ("we will not attempt to estimate time and area
with large precision"). On trade-off attacks they state: "With default
number of passes over memory (1 for Argon2d, 3 for Argon2i), an
ASIC-equipped adversary can not decrease the time-area product if the
memory is reduced by the factor of 4 or more" (§4.1, p.8).

**A GPU-vs-CPU benchmark for Argon2id.** hashcat 7.0.0's release notes
(`docs/releases_notes_v7.0.0.md`, §2.2 "Argon2",
<https://github.com/hashcat/hashcat/blob/v7.0.0/docs/releases_notes_v7.0.0.md>)
give, for hash-mode 34000 with "RFC 9106 recommended settings
(m=65536, t=3, p=1)", that is, 64 MiB:

| Hardware | Guesses/sec |
|---|---|
| NVIDIA RTX 4090 (GPU) | 1703 H/s |
| AMD Radeon RX 7900 XTX (GPU) | 1367 H/s |
| Intel i7-14700K (CPU) | 96 H/s |
| AMD Ryzen 9 9900X (CPU) | 92 H/s |

The same notes say mode 34000's OpenCL code cannot use the CPUs' SIMD
extensions fully, and give 110 and 109 H/s for the same two CPUs with
the reference implementation (hash-mode 70000). Against that, the
RTX 4090 is about 15.6 times faster than the Ryzen 9 9900X (1703 /
109), or 18.5 times against the OpenCL figure (1703 / 92). These
benchmarks use 64 MiB per guess; cryptsetup's default allows up to
1 GiB (below).

## What cryptsetup actually does, per code

Source: cryptsetup at commit
[`bae21790`](https://gitlab.com/cryptsetup/cryptsetup/-/tree/bae21790d59897ac50e5471f953f76b3a58aeeb6).

**The compiled-in defaults** are in
[`lib/utils_pbkdf.c`](https://gitlab.com/cryptsetup/cryptsetup/-/blob/bae21790d59897ac50e5471f953f76b3a58aeeb6/lib/utils_pbkdf.c#L14-34)
(lines 14–34):

```c
const struct crypt_pbkdf_type default_pbkdf2 = {
	.type = CRYPT_KDF_PBKDF2,
	.hash = DEFAULT_LUKS1_HASH,
	.time_ms = DEFAULT_LUKS1_ITER_TIME
};

const struct crypt_pbkdf_type default_argon2id = {
	.type = CRYPT_KDF_ARGON2ID,
	.hash = DEFAULT_LUKS1_HASH,
	.time_ms = DEFAULT_LUKS2_ITER_TIME,
	.max_memory_kb = DEFAULT_LUKS2_MEMORY_KB,
	.parallel_threads = DEFAULT_LUKS2_PARALLEL_THREADS
};
```

The `DEFAULT_*` values are build options set in
[`configure.ac`](https://gitlab.com/cryptsetup/cryptsetup/-/blob/bae21790d59897ac50e5471f953f76b3a58aeeb6/configure.ac#L806-810)
(lines 806–810):

```
CS_STR_WITH([luks2-pbkdf],           [Default PBKDF algorithm (pbkdf2 or argon2i/argon2id) for LUKS2], [argon2id])
CS_NUM_WITH([luks1-iter-time],       [PBKDF2 iteration time for LUKS1 (in ms)], [2000])
CS_NUM_WITH([luks2-iter-time],       [Argon2 PBKDF iteration time for LUKS2 (in ms)], [2000])
CS_NUM_WITH([luks2-memory-kb],       [Argon2 PBKDF memory cost for LUKS2 (in kB)], [1048576])
CS_NUM_WITH([luks2-parallel-threads],[Argon2 PBKDF max parallel cost for LUKS2 (if CPUs available)], [4])
```

| Default | Value |
|---|---|
| LUKS2 PBKDF | `argon2id` |
| PBKDF2 target time (LUKS1) | 2000 ms |
| Argon2 target time (LUKS2) | 2000 ms |
| Argon2 maximum memory | 1,048,576 KiB = 1 GiB |
| Argon2 maximum threads | 4 |

**Memory is capped by the machine.** `pbkdf_adjusted_phys_memory_kb()`
(same file, lines 51–83) uses at most half of physical memory ("Never
use more than half of physical memory"), and, when that half is under
2 GiB and there is no swap, at most half of the memory currently free.
(If physical memory is under 128 MiB, or cannot be expressed as a
32-bit number of KiB, it uses the 1 GiB default instead.) So a keyslot
showing `Memory: 1048576`, like the one in
[`luks2-header-anatomy.md`](luks2-header-anatomy.md#the-json-metadata-area),
was normally formatted on a machine with at least 2 GiB of RAM.

**The documented bounds** (`man/common_options.adoc`, lines 754–760):

> For *PBKDF2*, the minimum iteration count is 1000 and the maximum is
> 4294967295 (maximum for 32-bit unsigned integer). [...] For *Argon2i*
> and *Argon2id*, the minimum iteration count (CPU cost) is 4, and the
> maximum is 4294967295 (maximum for a 32-bit unsigned integer).
> Minimum memory cost is 32 KiB and maximum is 4 GiB. If the memory
> cost parameter is benchmarked (not specified by a parameter), it is
> always in the range from 64 MiB to 1 GiB.

Two examples fit these bounds: the keyslot in
[`luks2-header-anatomy.md`](luks2-header-anatomy.md#the-json-metadata-area)
(`Time cost: 5`, `Memory: 1048576`, `Threads: 4`), at the 1 GiB
ceiling; and the LUKS2 specification's example
([`af-splitting-explained.md`](af-splitting-explained.md#a-real-example-from-the-spec-itself)),
with `argon2i`, `"time": 4`, `"memory": 235980` (about 230 MiB) in one
keyslot and `pbkdf2` with `"iterations": 1774240` in the other.

## Cleartext KDF parameters: what they do and don't leak

The KDF parameters and salt are stored unencrypted: in LUKS1, each
keyslot's iteration count and salt are fields of the binary header; in
LUKS2, they are the keyslot's `kdf` object in the JSON metadata (see
[`af-splitting-explained.md`](af-splitting-explained.md#the-keyslot-json-object-sketched)).

**They say nothing about the passphrase.** The cost parameters are
chosen by cryptsetup's benchmark or by the administrator, and the salt
is random; none is computed from the passphrase. Both PKCS #5 and RFC
9106 treat the salt as a public input. They have to be readable, since
unlocking must use the same parameters that created the keyslot.

**They do tell an attacker the exact cost of each guess.** With a copy
of the header, `luksDump` shows exactly how many PBKDF2 iterations, or
how much memory and how many Argon2 passes, each guess takes, so the
attacker can plan hardware without guessing.

**This is not a weakness in practice.** Other password-hashing schemes
store their parameters the same way: `crypt(5)` describes every stored
hash as "four components: prefix, options, salt, and hash", with, for
example, `rounds=` in the options of a `$6$` (sha512crypt) hash
(libxcrypt 4.5.2). Knowing the cost does not lower it.

What matters is whether the cost was set high enough, and whether it
still is. A keyslot benchmarked years ago was tuned to the hardware of
the time. Rewriting it on current hardware sets new parameters:
`cryptsetup luksChangeKey` rewrites a keyslot with a new passphrase,
and `cryptsetup luksConvertKey` changes a keyslot's PBKDF parameters,
both benchmarking again. Neither changes the master key, and an old
header backup still holds the old keyslots.

## Summary

| | PBKDF2 (LUKS1) | Argon2id (LUKS2 default) |
|---|---|---|
| Cost parameters | Iterations `c` | Passes `t`, memory `m`, lanes `p` |
| Memory per guess | Negligible | Up to 1 GiB by cryptsetup's default (benchmarked between 64 MiB and 1 GiB) |
| GPU/CPU speed ratio in the cited benchmarks | Not measured here | About 15.6 to 18.5 (RTX 4090 vs. Ryzen 9 9900X, 64 MiB, hashcat 7.0.0) |
| Gets cheaper to attack as hardware improves? | Yes; the iteration count is fixed when the keyslot is created | Yes, unless the keyslot is rewritten; the memory requirement limits how much parallel hardware helps |
| cryptsetup's default target time | 2000 ms | 2000 ms |
| Are the cleartext parameters a weakness? | No: they must be readable to unlock, and knowing the cost does not lower it | Same |
