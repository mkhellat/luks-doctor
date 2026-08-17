# Quantitative Entropy Analysis of Keyslot Data: What It Can and Can't Tell You

`scripts/inspect-keyslot` flags two things by eye: long zero-byte runs
and short repeating patterns (see
[`checking-for-corruption.md`](checking-for-corruption.md)). Both are
explicitly rough visual heuristics, not a statistical test. This
document asks a more precise question: if you *did* run a real
statistical test suite — chi-squared, Shannon entropy, NIST's own
randomness test battery — against real AF-striped keyslot data, what
would it actually catch that the existing heuristics miss, and what is
it *provably* incapable of catching no matter how sophisticated it
gets?

Every number in this document was produced by a script, not typed in by
hand. The methodology (`AF_split`/`AF_merge` reimplementation, sample
generation, statistics battery) is described inline; run it yourself if
you want to reproduce or extend it.

## Contents

- [Why ask this at all](#why-ask-this-at-all)
- [The tests, precisely](#the-tests-precisely)
  - [NIST SP 800-22 Rev. 1a](#nist-sp-800-22-rev-1a)
  - [Chi-squared goodness-of-fit for byte uniformity](#chi-squared-goodness-of-fit-for-byte-uniformity)
  - [Shannon entropy](#shannon-entropy)
- [Do LUKS2 keyslot areas even have enough bytes for these tests?](#do-luks2-keyslot-areas-even-have-enough-bytes-for-these-tests)
- [The information-theoretic ceiling](#the-information-theoretic-ceiling)
- [Experiment: running the tests against real AF-split output](#experiment-running-the-tests-against-real-af-split-output)
  - [Self-test: does the reimplementation actually match cryptsetup's algorithm?](#self-test-does-the-reimplementation-actually-match-cryptsetups-algorithm)
  - [The headline result: single-bit corruption is invisible](#the-headline-result-single-bit-corruption-is-invisible)
  - [What the tests **do** catch](#what-the-tests-do-catch)
  - [Detection power vs. sample size](#detection-power-vs-sample-size)
- [Where this leaves `inspect-keyslot`](#where-this-leaves-inspect-keyslot)

## Why ask this at all

[`af-splitting-explained.md`](af-splitting-explained.md) and
[`checking-for-corruption.md`](checking-for-corruption.md) both already
assert, in prose, that a healthy keyslot area is "cryptographically
indistinguishable from uniform random noise" and that no visual or
statistical method can detect single-bit corruption. Those claims are
correct, but as stated they're asserted, not demonstrated — and "no
statistical method could ever detect this" is exactly the kind of
strong claim this project's own standard says shouldn't be taken on
faith (see the README's research-milestones framing). This document
makes the claim precise and checks it empirically: run real tests
against real AF-split output, corrupt it in controlled ways, and see
what actually changes.

## The tests, precisely

### NIST SP 800-22 Rev. 1a

The standard reference test suite for cryptographic randomness is NIST
Special Publication 800-22, *"A Statistical Test Suite for Random and
Pseudorandom Number Generators for Cryptographic Applications,"*
Revision 1a, revised April 2010 (Rukhin, Soto, Nechvatal, Smid, Barker,
Leigh, Levenson, Vangel, Banks, Heckert, Dray, Vo, Bassham III) —
<https://nvlpubs.nist.gov/nistpubs/legacy/sp/nistspecialpublication800-22r1a.pdf>.

**Note on versioning**: an earlier document, "SP 800-22 Revision 1"
(2008, no "a" suffix), is a *different*, withdrawn publication
(<https://csrc.nist.gov/pubs/sp/800/22/r1/final>) — don't confuse the
two. Rev. 1a is the version in force. NIST announced in April 2022 that
it intends to revise Rev. 1a further, but as of that announcement no
draft had been started and no completion date was given
(<https://www.nist.gov/news-events/news/2022/04/decision-revise-nist-sp-800-22-rev-1a>) —
Rev. 1a remains the current, non-withdrawn document.

It defines 15 subtests, each with its own minimum input-bitstream
length below which the test's own statistical assumptions (asymptotic
distributions, degrees of freedom) stop being valid — quoting the
"Input Size Recommendation" text from each section:

| § | Test | Minimum length |
|---|---|---|
| 2.1 | Frequency (Monobit) | n ≥ 100 bits |
| 2.2 | Frequency within a Block | n ≥ 100 bits (n ≥ MN; M ≥ 20, M > .01n, N < 100) |
| 2.3 | Runs | n ≥ 100 bits |
| 2.4 | Longest Run of Ones in a Block | 128 bits (M=8) up to 750,000 bits (M=10⁴), by block size |
| 2.5 | Binary Matrix Rank | n ≥ 38,912 bits (M=Q=32) |
| 2.6 | Discrete Fourier Transform (Spectral) | n ≥ 1,000 bits |
| 2.7 | Non-overlapping Template Matching | — |
| 2.8 | Overlapping Template Matching | — |
| 2.9 | Maurer's Universal Statistical | n ≥ 10⁶ bits |
| 2.10 | Linear Complexity | — |
| 2.11 | Serial | n ≥ 10⁶ bits (500 ≤ M ≤ 5000, N ≥ 200) |
| 2.12 | Approximate Entropy | — |
| 2.13 | Cumulative Sums (Cusum) | n ≥ 100 bits |
| 2.14 | Random Excursions | n ≥ 10⁶ bits |
| 2.15 | Random Excursions Variant | n ≥ 10⁶ bits |

The heaviest subtests (Maurer's Universal, Serial, both Random
Excursions tests) want a full **million bits** — 125,000 bytes — before
their statistics are trustworthy. That number matters for the next
section.

### Chi-squared goodness-of-fit for byte uniformity

Not an SP 800-22 subtest, but the standard classical test for "are
these bytes drawn uniformly from all 256 possible values." For a
256-symbol alphabet, degrees of freedom = 255. Critical values
(computed directly, `scipy.stats.chi2.ppf`, not looked up in a printed
table):

```
$ python3 -c "import scipy.stats as st; print(st.chi2.ppf(0.95, 255), st.chi2.ppf(0.99, 255))"
293.2478350807012 310.45738821990585
```

So χ²(dof=255, α=0.05) ≈ 293.25, χ²(dof=255, α=0.01) ≈ 310.46. The
standard rule of thumb for the test's asymptotic approximation to hold
is an expected count of at least 5 per bin, i.e. n ≥ 5×256 = 1,280
bytes — see [below](#detection-power-vs-sample-size) for how
conservative that rule turns out to be for our purposes.

### Shannon entropy

H = −Σ p(x)·log₂p(x), maximum 8.0 bits/byte for a uniform 256-symbol
source. Original source: C.E. Shannon, "A Mathematical Theory of
Communication," *Bell System Technical Journal*, vol. 27, pp. 379–423
(Part I) and 623–656 (Part II), 1948
(DOI [10.1002/j.1538-7305.1948.tb01338.x](https://doi.org/10.1002/j.1538-7305.1948.tb01338.x)).

Why this is a weak signal here specifically: AES-XTS ciphertext and
AF-diffused stripe data are *supposed* to sit at ~8.0 bits/byte
regardless of whether the key or plaintext underneath is correct — high
entropy is the expected, uninformative baseline for both healthy and
subtly-corrupted data. It only drops measurably when something
distinctly non-ciphertext-like gets mixed in (see the experiments
below).

## Do LUKS2 keyslot areas even have enough bytes for these tests?

A keyslot's `area` size is `af.stripes` (4000 by default) times
`key_size` (see
[`af-splitting-explained.md`](af-splitting-explained.md#aside-where-does-that-key-length-number-actually-come-from)
for where `key_size` actually comes from per cipher choice):

```
key_size=32 bytes -> AF area = 128,000 bytes = 1,024,000 bits (125.0 KiB)
key_size=64 bytes -> AF area = 256,000 bytes = 2,048,000 bits (250.0 KiB)
```

This is worth stating precisely because it's not obvious in advance: a
full keyslot area comfortably clears **every** SP 800-22 subtest's
minimum, including the million-bit-hungry ones. The catch is that
`scripts/inspect-keyslot` today only hex-dumps small 128-byte
head/tail windows for display — its zero-run and pattern-repeat
heuristics do already scan the *entire* area, so a future statistical
check could reuse that same full-area pass and stay comfortably inside
SP 800-22's size envelope. Where the size limits actually bite is if a
future feature wanted to test a small *sub-region* (e.g. just the final
32–64-byte stripe) in isolation — at that scale most SP 800-22 subtests
become statistically underpowered or inapplicable outright.

## The information-theoretic ceiling

This is the precise version of the claim already made in prose
elsewhere in this project's docs.

**Every stripe except the last is literally CSPRNG output**, written to
disk unmodified (see the algorithm walkthrough in
[`af-splitting-explained.md`](af-splitting-explained.md#the-real-algorithm-in-plain-english)).
No statistical test can ever flag one of these stripes as "wrong,"
because there is no "wrong" state to detect — the bytes are
unconditionally random whether or not the key being split is the
correct one.

**The last stripe** is `original_key XOR diffuse(accumulator)`. XOR
with any independent value is a bijection on the uniform distribution —
this is the one-time-pad argument, not an assumption specific to
SHA-256. So the last stripe's distribution, as observed by any
statistical test, is identical whether `original_key` is the true
master key, an all-zero key, or arbitrary garbage.

**AES-XTS ciphertext** (the encrypted data segment, distinct from the
keyslot area) has the same property for a related but structurally
different reason: dm-crypt's XTS mode is a keyed pseudorandom
permutation (PRP) construction. A block cipher's PRP-security property
*is* the statement that its output is computationally indistinguishable
from a uniform random permutation's output to anyone without the key —
this holds identically whether the right key is applied to the right
plaintext or the wrong key is applied to the same ciphertext. A cipher
whose output became statistically distinguishable when decrypted under
the wrong key would, by definition, be a broken PRP. (This document
does not have a single citable theorem statement pinned to a specific
page for "XTS-under-wrong-key is indistinguishable from XTS-under-right-key"
— it follows from PRP-security by definition, not from a claim specific
to XTS. If you want to dig further, Iwata & Minematsu's "Evaluating the
Indistinguishability of the XTS Mode" (<https://eprint.iacr.org/2018/124.pdf>)
is a relevant pointer, not independently verified here.)

**Practical upshot**: no statistical test, however sophisticated,
distinguishes "correct key material, corrupted incidentally" from
"wrong key entirely" from "correct key material, uncorrupted." This is
a ceiling, not a current tooling gap — it holds for any future test
suite too, because the underlying input *distributions* are provably
identical, not just empirically similar.

## Experiment: running the tests against real AF-split output

Methodology: reimplemented `AF_split`/`AF_merge`/`diffuse`/`hash_buf`
byte-for-byte against the description in
[`af-splitting-explained.md`](af-splitting-explained.md) (SHA-256
`diffuse`, 4000 stripes, 32-byte key → 128,000-byte area), then ran a
statistics battery — chi-squared byte-uniformity, Shannon entropy,
lag-1 serial correlation, SP 800-22 §2.1 Frequency test, plus the
existing `inspect-keyslot` zero-run/pattern-repeat heuristics — against
real AF-split output and deliberately corrupted variants of it.

### Self-test: does the reimplementation actually match cryptsetup's algorithm?

```
AF_split/AF_merge round-trip OK. area length = 128000 bytes (1024000 bits)
Single-bit corruption in stripe 0 -> recovered key differs in 134/256 bits (52.3%)
  - consistent with full avalanche, not a 'near miss'
```

134/256 ≈ 52.3%, matching the ~50% avalanche behavior SHA-256 is
expected to produce and that `af-splitting-explained.md` already
claims — now backed by a running implementation rather than asserted.

### The headline result: single-bit corruption is invisible

| Sample | chi² p-value | Entropy (bits/B) | Frequency test p | Zero-run | Pattern-run |
|---|---|---|---|---|---|
| Real AF-split output | 0.7596 pass | 7.998654 | 0.851 pass | 2 | 2 (period 1) |
| `/dev/urandom` baseline | 0.4581 pass | 7.998551 | 0.326 pass | 2 | 2 (period 1) |
| 1 bit flipped | 0.7553 pass | 7.998653 | 0.853 pass | 2 | 2 (period 1) |
| 10 bits flipped (scattered) | 0.7565 pass | 7.998653 | 0.845 pass | 2 | 2 (period 1) |

1 or even 10 scattered single-bit flips in real AF-split data are
statistically invisible to chi-squared, Shannon entropy, and the SP
800-22 Frequency test — every metric matches both the unflawed sample
and the pure-`/dev/urandom` baseline to within normal sampling noise.
This is the empirical confirmation of the [information-theoretic
ceiling](#the-information-theoretic-ceiling) above, not just a
restatement of it.

### What the tests **do** catch

| Sample | chi² p-value | Entropy (bits/B) | Frequency test p | Zero-run | Pattern-run |
|---|---|---|---|---|---|
| Trailing 25% zeroed | **0.000000 FAIL** | 6.785722 | **0.000000 FAIL** | 32,000 | 31,999 |
| 64-byte zero run | 0.4760 pass | 7.998564 | 0.465 pass | 64 | 63 |
| 16-byte zero run (sub-threshold) | 0.7158 pass | 7.998638 | 0.743 pass | 16 | 15 |
| 256-byte "deadbeef" pattern (0.2% of area) | 0.1309 pass | 7.998428 | 0.432 pass | 2 | **252 (period 4)** |
| Truncated to 75% length | 0.8383 pass | 7.998249 | 0.266 pass | 2 | 2 (period 1) |
| 2 KB English-text residue (1.6% of area) | **0.000021 FAIL** | 7.998028 | 0.415 pass | 2 | 2 (period 1) |

Two results here are worth calling out specifically because they're not
obvious in advance:

- **Chi-squared catches contamination that entropy and the bit-level
  Frequency test both miss.** The English-text-residue row is the
  clearest example: chi-squared fails decisively (p = 0.000021) while
  Shannon entropy (7.998028 vs. 7.999-ish baseline) and the SP 800-22
  Frequency test (p = 0.415, "pass") both see nothing unusual. Chi-squared
  is sensitive to the *byte-value* distribution; entropy is a single
  scalar summary that can stay near-maximal even with a small
  contaminated region; Frequency only looks at 0/1 bit balance, which a
  small text injection barely perturbs. **Different tests have
  genuinely different sensitivity profiles** — this isn't redundant
  instrumentation.
- **The existing pattern-repeat heuristic catches something chi-squared
  and entropy both miss.** A 256-byte repeating "deadbeef" pattern
  (only 0.2% of the 128,000-byte area) sails through chi-squared
  (p = 0.13) and entropy (7.998428) — because `deadbeef` still uses 4
  distinct byte values in roughly plausible proportion across a large
  area, so an aggregate byte-frequency test doesn't notice — but is
  caught immediately by the *positional* pattern-repeat check (252
  consecutive repeats vs. a threshold of 6). **The structural
  heuristics `inspect-keyslot` already has are not redundant with a
  future statistical test — they catch a different failure mode.**
- **Truncation is not a statistical anomaly.** A truncated-but-otherwise-random
  96,000-byte sample (75% of expected length) passes chi-squared
  cleanly (p = 0.838) — because the bytes that *are* present are still
  random. Truncation is a **length** mismatch against the `Area
  length` recorded in the keyslot's JSON metadata, not a property of
  the byte values present. This is a purely structural check (which
  `inspect-keyslot` already effectively performs, by reading exactly
  `Area length` bytes) — no statistical test on the bytes themselves
  will ever catch it.

### Detection power vs. sample size

The most load-bearing result for scoping any future feature: how much
scattered corruption does chi-squared actually need, at realistic
sample sizes, before it reliably fires?

```
size=128B    zero_frac=0.01: chi2 p=0.7415 [missed]     zero_frac=0.05: p=0.0085 [DETECTED]
size=1280B   zero_frac=0.01: chi2 p=0.0651 [missed]     zero_frac=0.05: p=0.0000 [DETECTED]
size=128000B zero_frac=0.01: chi2 p=0.0000 [DETECTED]   zero_frac=0.05: p=0.0000 [DETECTED]
```

At full keyslot-area scale (128,000 bytes), chi-squared reliably
detects even 1% scattered zero-byte corruption of otherwise-random
data; at 1,280 bytes it needs roughly 5%; at 128 bytes the boundary
sits somewhere between 1% and 5%. This gives a concrete, testable
detection floor rather than a hand-waved "small samples are less
reliable."

A separate 2,000-trial empirical false-positive-rate check against pure
`/dev/urandom` at 128, 1,280, and 128,000 bytes found the chi-squared
test's actual false-positive rate tracked its theoretical α (0.05/0.01)
closely even at 128 bytes — noticeably better than the "expected count
≥ 5 per bin" rule of thumb (which technically wants ≥1,280 bytes) would
suggest. That rule of thumb governs the test's *false-positive rate*
being well-calibrated; it says nothing about *detection power*, which —
per the table above — degrades substantially at small sample sizes even
though the false-positive rate stays fine.

## Where this leaves `inspect-keyslot`

Put together, this is a fairly specific, non-obvious set of findings —
not "statistical tests can add rigor," but a map of exactly which test
catches which failure mode:

- **Chi-squared** (full-area, ~128,000 bytes) — catches gross
  contamination (zero-fill, non-random residue like filesystem/journal
  bleed-through) that a single entropy number can miss, at the cost of
  needing the full area (or at least >1,280 bytes) to be reliable.
- **Shannon entropy** — a fast summary scalar, but the weakest of the
  three at catching small-fraction contamination; useful as a quick
  first pass, not a substitute for chi-squared.
- **The existing zero-run and pattern-repeat heuristics** — still
  necessary, not superseded by a statistical test. Pattern-repeat in
  particular catches small localized fill patterns that chi-squared's
  aggregate byte-frequency view is structurally blind to.
- **None of the above** — nor any future statistical method — can ever
  detect scattered single-bit corruption of otherwise-intact key
  material. That's not a gap in this tooling; it's the [information-theoretic
  ceiling](#the-information-theoretic-ceiling) working as designed, and
  it's the reason `luksHeaderBackup` taken *before* damage occurs
  remains the only real defense (see
  [`checking-for-corruption.md`](checking-for-corruption.md#when-to-run-cryptsetup-repair-and-what-it-cant-fix)).

Whether it's worth adding a chi-squared/entropy pass to
`scripts/inspect-keyslot` itself — beyond this analysis of what it
would and wouldn't buy — is an open question for a future roadmap
decision, not something this document resolves.
