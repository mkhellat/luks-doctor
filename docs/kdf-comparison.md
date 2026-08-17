# Argon2id vs. PBKDF2: LUKS1 vs. LUKS2, Cryptographically

LUKS1 derives its keyslot-unlock key with PBKDF2. LUKS2 defaults to
Argon2id. Both this project's other docs and the wider LUKS
documentation ecosystem tend to summarize the difference as "Argon2id
is memory-hard, PBKDF2 isn't" and leave it there. This document grounds
that summary in the actual specs, the actual cryptsetup source, and
real published cracking-speed benchmarks — addressing the second
research milestone queued in the README.

## Contents

- [PBKDF2 (LUKS1), precisely](#pbkdf2-luks1-precisely)
- [Argon2id (LUKS2 default), precisely](#argon2id-luks2-default-precisely)
- [What cryptsetup actually does, per code](#what-cryptsetup-actually-does-per-code)
- [Cleartext KDF parameters: what they do and don't leak](#cleartext-kdf-parameters-what-they-do-and-dont-leak)
- [Summary](#summary)

## PBKDF2 (LUKS1), precisely

**Spec**: RFC 2898, *"PKCS #5: Password-Based Cryptography Specification
Version 2.0,"* B. Kaliski (RSA Laboratories), September 2000, status
Informational — <https://www.rfc-editor.org/rfc/rfc2898>. PBKDF2 itself
is defined in §5.2.

The core construction, quoted from the RFC:

> F (P, S, c, i) = U_1 \xor U_2 \xor ... \xor U_c
>
> where U_1 = PRF (P, S || INT (i)), U_2 = PRF (P, U_1), ... U_c = PRF
> (P, U_{c-1})

`P` is the password, `S` the salt, `c` the iteration count, and PRF is
(for LUKS) HMAC over the configured hash. Each derived block costs
exactly **c sequential PRF invocations**, each depending only on a
single prior HMAC output (a few dozen bytes of state). **The spec
defines no memory requirement anywhere.** This is the entire technical
basis for "PBKDF2 isn't memory-hard": nothing in its definition demands
more than trivial working memory, so an attacker's per-guess cost is
governed purely by how many ALUs/hash cores they can fit on a die, not
by how much RAM they can provision — exactly the resource GPUs, FPGAs,
and ASICs have in abundance.

**How LUKS1 picks `c`**: at `luksFormat`/`luksAddKey` time, cryptsetup
benchmarks the PRF on the local machine and picks the iteration count
so derivation takes a target wall-clock duration — 2000 ms by default
(verified against cryptsetup's own build configuration; see
[below](#what-cryptsetup-actually-does-per-code)) — then stores that
raw integer in the header's cleartext `PBKDF2 iterations` field
permanently. Because it's an absolute count tuned to *that machine's*
hash rate at *that moment*, and PBKDF2 has no cost floor besides raw
compute speed, **the real-world cost of an existing header degrades
monotonically as hardware gets faster** — there's no re-tuning
mechanism; the stored number just becomes cheaper to defeat every GPU
generation.

**Real GPU cracking-speed data.** hashcat's LUKS1 module (`-m 14600`,
`module_14600.c`) hardcodes a fixed benchmark iteration count for
cross-tool comparability with John the Ripper, quoted directly from the
source (<https://github.com/hashcat/hashcat/blob/master/src/modules/module_14600.c>):

```c
static const int ROUNDS_LUKS = 163044;
salt->salt_iter = ROUNDS_LUKS;
```

Real published `-b -m 14600` benchmark results at that fixed
163,044-iteration cost:

| GPU | hashcat version | Guesses/sec | Source |
|---|---|---|---|
| NVIDIA RTX 3090 | 6.1.1 | 28,356 H/s | <https://gist.github.com/Chick3nman/e4fcee00cb6d82874dace72106d73fef/> |
| NVIDIA RTX 4090 | 6.2.6 | 65,253 H/s | <https://gist.github.com/Chick3nman/32e662a5bb63bc4f51b847bb422222fd> |

That's a **2.30x** speedup (65,253 / 28,356) across two consumer GPU
generations, against a *fixed* iteration count — real, observed drift
in what a captured LUKS1 header costs to attack over time, not a
theoretical extrapolation. At the RTX 3090 rate alone, 28,356
guesses/sec sustained for a day is roughly 2.45 billion full-passphrase
attempts. (These numbers are guesses/sec at hashcat's specific
163,044-iteration benchmark point — a real captured header's actual
attack cost scales inversely with whatever iteration count *that*
header stores, which varies by hardware and `--iter-time` at the time
it was created; this document does not have a citable, independently
re-verified figure for the real-world distribution of that number
across deployed volumes, so no such range is claimed here.)

## Argon2id (LUKS2 default), precisely

**Spec**: two distinct documents exist — cite the right one for the right claim.

- **RFC 9106**, *"Argon2 Memory-Hard Function for Password Hashing and
  Proof-of-Work Applications,"* A. Biryukov, D. Dinu, D. Khovratovich,
  S. Josefsson, September 2021, status Informational (IRTF CFRG) —
  <https://www.rfc-editor.org/rfc/rfc9106>. This is the current
  normative spec and covers Argon2id.
- The peer-reviewed paper: A. Biryukov, D. Dinu, D. Khovratovich,
  "Argon2: New Generation of Memory-Hard Functions for Password Hashing
  and Other Applications," *IEEE European Symposium on Security and
  Privacy (EuroS&P) 2016*, pp. 292–302, DOI
  [10.1109/EuroSP.2016.31](https://doi.org/10.1109/EuroSP.2016.31).
- **Not** the same as the informal December 2015 "PHC release" spec PDF
  (v1.2.1, hosted at password-hashing.net) — that earlier document
  predates Argon2id entirely; its own text states there are "two
  flavors of Argon2 – Argon2d and Argon2i," full stop. Don't cite it
  for anything Argon2id-specific.

**Three cost parameters**, quoted from RFC 9106:

> Number of passes t (used to tune the running time independently of
> the memory size) MUST be an integer number from 1 to 2^32-1.
>
> Memory size m MUST be an integer number of kibibytes from 8*p to
> 2^32-1.
>
> Degree of parallelism p determines how many independent (but
> synchronizing) computational chains (lanes) can be run.

**Why Argon2id specifically, not Argon2i or Argon2d**, quoted from RFC 9106:

> Argon2id works as Argon2i for the first half of the first pass over
> the memory and as Argon2d for the rest.
>
> Argon2i uses data-independent memory access, which is preferred for
> password hashing.
>
> Argon2d uses data-dependent memory access, which makes it suitable
> for cryptocurrencies.

Concretely: Argon2i's memory-access pattern is a public function of the
index alone, computable by an attacker in advance without knowing any
of the actual accumulated data — good against timing/cache side
channels (nothing observable depends on secret data), but that same
predictability is exactly what a time-memory-tradeoff (TMTO) attacker
exploits to cheaply recompute a missing block instead of being forced
to store it. Argon2d's addressing depends on the actual in-memory data,
which defeats precomputation-based TMTO far more effectively (you can't
know which block you'll need until you've already computed the one
before it) but leaks *which* memory location was touched — a real
timing/cache side channel if an attacker shares hardware with you (a
co-tenant on cloud infrastructure, or another unprivileged local
process). Argon2id's data-independent-then-data-dependent split is a
deliberate compromise between these two failure modes, not an arbitrary
default.

**Why memory-hardness defeats GPU/ASIC economics**, quoted from the
Argon2 design rationale (Section 2.1, "Motivation" — this specific cost
argument is unchanged from the original spec through to today's
recommendations):

> We aim to maximize the cost of password cracking on ASICs... The
> 50-nm DRAM implementation takes 550 mm² per GByte; The Blake2b
> implementation in the 65-nm process should take about 0.1 mm²... The
> maximum memory bandwidth achieved by modern GPUs is around 400
> GB/sec.

Ratio: 550 / 0.1 ≈ **5,500x** — for the same silicon die area, a
pure-compute ASIC (the PBKDF2 case) could pack roughly 5,500 parallel
hash cores where an Argon2-targeting ASIC fits one 1-GiB memory bank.
The source is explicit that this is an order-of-magnitude illustration,
not a precise cost model ("we will not attempt to estimate time and
area with large precision") — treat it as directionally correct, not a
load-bearing exact multiplier. The paper's formal treatment goes
further with an explicit time-area-product TMTO-resistance bound: *"With
default number of passes over memory (1 for Argon2d, 3 for Argon2i), an
ASIC-equipped adversary can not decrease the time-area product if the
memory is reduced by the factor of 4 or more."*

**A real GPU-vs-CPU benchmark for Argon2id itself**, from hashcat
v7.0.0's own release notes (mode 34000, RFC 9106's memory-constrained
profile: m=64 MiB, t=3, p=1):

| Hardware | Guesses/sec |
|---|---|
| NVIDIA RTX 4090 (GPU) | 1,703 H/s |
| AMD Radeon RX 7900 XTX (GPU) | 1,367 H/s |
| Intel i7-14700K (CPU) | 96 H/s |
| AMD Ryzen 9 9900X (CPU) | 92 H/s |

GPU/CPU speedup here: 1,703 / 92 ≈ **18.5x**. That's dramatically
smaller than the 100–10,000x GPU/CPU gaps typical of fast, memory-light
hashes — a real, cited demonstration that memory-hardness closes most
of the usual GPU advantage, not just an assertion that it should.

## What cryptsetup actually does, per code

Source: `gitlab.com/cryptsetup/cryptsetup`, commit
`9b560a0d4948cde06a1a961813ee3c01264a185f` (main, fetched 2026-08-17).

**The compiled-in default PBKDF structs**, `lib/utils_pbkdf.c`:

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

The `DEFAULT_LUKS2_*` macros aren't in a static header — they're
generated by `configure.ac`'s `CS_NUM_WITH`/`CS_STR_WITH` autoconf
macros, each exposing a `--with-*` build flag with a hardcoded
fallback. The actual defaults, quoted directly from `configure.ac`:

```
CS_STR_WITH([luks2-pbkdf],           [Default PBKDF algorithm (pbkdf2 or argon2i/argon2id) for LUKS2], [argon2id])
CS_NUM_WITH([luks1-iter-time],       [PBKDF2 iteration time for LUKS1 (in ms)], [2000])
CS_NUM_WITH([luks2-iter-time],       [Argon2 PBKDF iteration time for LUKS2 (in ms)], [2000])
CS_NUM_WITH([luks2-memory-kb],       [Argon2 PBKDF memory cost for LUKS2 (in kB)], [1048576])
CS_NUM_WITH([luks2-parallel-threads],[Argon2 PBKDF max parallel cost for LUKS2 (if CPUs available)], [4])
```

So, precisely:

| Default | Value | Meaning |
|---|---|---|
| `DEFAULT_LUKS1_ITER_TIME` | 2000 ms | LUKS1 PBKDF2 benchmark target duration |
| LUKS2 default PBKDF algorithm | `argon2id` | Not argon2i or argon2d |
| `DEFAULT_LUKS2_ITER_TIME` | 2000 ms | Same benchmark-duration mechanism as LUKS1, different resulting parameter shape |
| `DEFAULT_LUKS2_MEMORY_KB` | 1,048,576 KiB | Exactly **1 GiB** — the memory-cost ceiling the benchmark is allowed to select |
| `DEFAULT_LUKS2_PARALLEL_THREADS` | 4 | Lanes/threads, capped by actually-available CPUs at benchmark time |

The 1 GiB `DEFAULT_LUKS2_MEMORY_KB` figure is not a coincidence next to
`luks2-header-anatomy.md`'s own `luksDump` example showing `Memory:
1048576` — that example is running with the compiled-in default on a
machine with at least 1 GiB free to spare.

**How the benchmark actually runs**: `crypt_benchmark_pbkdf()` in
`lib/utils_benchmark.c` detects available physical memory and clamps
`max_memory_kb` to what the machine can actually spare, then runs the
KDF for real and measures wall-clock time to compute the iteration
count (PBKDF2) or confirm/adjust memory-and-iterations (Argon2) within
the `time_ms` budget — this is a genuine timing benchmark on real
hardware, not a lookup table. `cryptsetup`'s own documentation
(`man/common_options.adoc`, quoted directly) confirms the resulting
bounds:

> For PBKDF2, the minimum iteration count is 1000 and the maximum is
> 4294967295... For Argon2i and Argon2id, the minimum iteration count
> (CPU cost) is 4, and the maximum is 4294967295. Minimum memory cost is
> 32 KiB and maximum is 4 GiB. If the memory cost parameter is
> benchmarked (not specified by a parameter), it is always in the range
> from 64 MiB to 1 GiB.

Cross-checking against two real `luksDump`-derived examples already in
this project's docs: `luks2-header-anatomy.md`'s example (`Time cost:
5`, `Memory: 1048576` KiB, `Threads: 4`) sits exactly at the documented
1 GiB auto-benchmark ceiling. The LUKS2 spec's own worked JSON example
quoted in
[`af-splitting-explained.md`](af-splitting-explained.md#a-real-example-from-the-spec-itself)
uses `argon2i`, `"time": 4, "memory": 235980` (≈230 MiB, comfortably
inside the 64 MiB–1 GiB auto-benchmark range) for one keyslot and
`pbkdf2`, `"iterations": 1774240` for another — both self-consistent
with these documented bounds.

## Cleartext KDF parameters: what they do and don't leak

Both LUKS1 (`kdf.iterations`, `kdf.hash`, `kdf.salt`) and LUKS2
(`kdf.time`, `kdf.memory`, `kdf.cpus`, `kdf.salt`, or the PBKDF2
equivalent) store their KDF parameters and salt in cleartext in the
JSON metadata — see the keyslot schema in
[`af-splitting-explained.md`](af-splitting-explained.md#the-keyslot-json-object-sketched).

**This leaks nothing about the passphrase itself.** The cost parameters
are inputs chosen by the implementation/administrator, not derived from
the secret — they're independent variables alongside the passphrase,
not a function of it. The salt is likewise not secret by design (its
job is defeating precomputed cross-target attacks, not adding secret
entropy) — both RFC 2898 §5.2 and RFC 9106 take the salt as a public
input parameter. Storing them in cleartext isn't an oversight: the
legitimate `luksOpen` call has to read the exact same parameters to
derive the exact same key the volume was formatted with, so there is no
way to hide them from an attacker with the device without also hiding
them from the legitimate unlock path — which would make the header
unable to describe itself, and therefore unopenable at all.

**It does leak the attacker's exact cost-per-guess.** This is the one
genuinely quantifiable point. An attacker with a captured header
doesn't estimate iteration count under uncertainty — `luksDump` (or
direct JSON inspection) states it exactly, e.g. "this header costs
exactly 163,044 PBKDF2 rounds per guess" or "this header needs exactly
1 GiB of RAM per concurrent Argon2id guess lane." That precision lets
an attacker provision hardware exactly rather than over-provisioning
defensively or under-provisioning and getting it wrong.

**Is this a meaningful weakness?** No — and framing it as one would
overstate it, in the same spirit as this project's earlier correction
of the XTS "doubles a 256-bit key" oversimplification (see
[`af-splitting-explained.md`](af-splitting-explained.md#aside-where-does-that-key-length-number-actually-come-from)).
Every deployed KDF-based scheme necessarily discloses its own cost
parameters — `/etc/shadow`'s `$6$rounds=...$` prefix, bcrypt's visible
cost factor, scrypt's visible N/r/p — because a scheme that hid its
parameters from a verifier would also hide them from the legitimate
holder of the secret, breaking the scheme's basic function. What the
cleartext parameters give an attacker is **certainty about cost**, not
**any reduction in the actual cost itself** — knowing the number
doesn't make the number smaller.

The property that actually matters, and that *is* under the volume
owner's control, is whether the cost parameter was set high enough in
the first place — and whether it still is, years later. A LUKS2 volume
formatted in 2020 with Argon2id parameters benchmarked against 2020
hardware is weaker today not because the parameters are *visible*, but
because they were tuned to a target duration on now-comparatively-slow
hardware and never re-tuned — the same "iteration count degrades with
Moore's law" effect described above for PBKDF2, just softened (not
eliminated) by Argon2id's RAM-cost floor. The actionable takeaway is
re-keying (`luksChangeKey` / `luksConvertKey` with a fresh
`--iter-time`-rebenchmarked run on current hardware) for an old volume,
not attempting to hide already-necessarily-public parameters.

## Summary

| | PBKDF2 (LUKS1) | Argon2id (LUKS2 default) |
|---|---|---|
| Cost dimensions | Iterations only (`c`) | Time (`t`), memory (`m`), parallelism (`p`) |
| Memory requirement per guess | None (a few dozen bytes of hash state) | `DEFAULT_LUKS2_MEMORY_KB` = 1 GiB (compiled-in ceiling; actual value benchmarked 64 MiB–1 GiB) |
| GPU/CPU cracking-speed gap (cited benchmarks) | Not directly benchmarked here for a CPU baseline, but structurally unbounded — pure-compute hashes typically see 100–10,000x GPU speedups | ~18.5x (RTX 4090 vs. Ryzen 9900X, hashcat mode 34000) |
| Degrades with newer hardware? | Yes, iteration count is an absolute number tuned once, never re-benchmarked | Yes, but more slowly — the RAM-cost floor doesn't shrink the same way raw compute speed grows |
| cryptsetup default target duration | 2000 ms (`DEFAULT_LUKS1_ITER_TIME`) | 2000 ms (`DEFAULT_LUKS2_ITER_TIME`) — same mechanism, different resulting parameter shape |
| Cleartext parameters a real weakness? | No — structurally required for any KDF scheme; discloses attacker's exact cost-per-guess, not a reduction in that cost |

The generic "Argon2id is memory-hard, PBKDF2 isn't" summary this
project's other docs use is accurate as far as it goes — this document
is the "per code, per spec, per real benchmark" backing for it.
