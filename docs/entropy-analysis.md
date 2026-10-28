# Quantitative Entropy Analysis of Keyslot Data: What It Can and Can't Tell You

`scripts/inspect-keyslot` looks for two things: long runs of zero
bytes and short repeating patterns (see
[`checking-for-corruption.md`](checking-for-corruption.md)). These are
rough heuristics, not statistical tests. This document asks what real
statistical tests (chi-squared, Shannon entropy, NIST's randomness
test suite) would catch in a keyslot area that the heuristics miss,
and what kinds of damage no test on the stored bytes can catch.

Every number below comes from
[`experiments/entropy-tests/`](../experiments/entropy-tests), which
runs the tests on a real keyslot area, as stored on disk by
cryptsetup 2.8.8, and on damaged copies of it.

## Contents

- [The tests](#the-tests)
  - [NIST SP 800-22 Rev. 1a](#nist-sp-800-22-rev-1a)
  - [Chi-squared goodness-of-fit for byte uniformity](#chi-squared-goodness-of-fit-for-byte-uniformity)
  - [Shannon entropy](#shannon-entropy)
- [Do keyslot areas have enough bytes for these tests?](#do-keyslot-areas-have-enough-bytes-for-these-tests)
- [What no test on the stored bytes can detect](#what-no-test-on-the-stored-bytes-can-detect)
- [Results](#results)
  - [Intact data](#intact-data)
  - [Damage that leaves random-looking bytes](#damage-that-leaves-random-looking-bytes)
  - [Damage the tests do catch](#damage-the-tests-do-catch)
  - [Detection power vs. sample size](#detection-power-vs-sample-size)
- [Where this leaves `inspect-keyslot`](#where-this-leaves-inspect-keyslot)

## The tests

### NIST SP 800-22 Rev. 1a

The standard suite of statistical tests for random number generators
is NIST Special Publication 800-22 Revision 1a, *A Statistical Test
Suite for Random and Pseudorandom Number Generators for Cryptographic
Applications*, April 2010, by Rukhin et al.
(<https://nvlpubs.nist.gov/nistpubs/legacy/sp/nistspecialpublication800-22r1a.pdf>).
It superseded Revision 1, which NIST withdrew on April 30, 2010
(<https://csrc.nist.gov/pubs/sp/800/22/r1/final>). On April 19, 2022,
NIST announced that it would revise Rev. 1a, adding that "draft
preparation has not yet started"
(<https://www.nist.gov/news-events/news/2022/04/decision-revise-nist-sp-800-22-rev-1a>);
as of 2026-10-28, Rev. 1a's page lists no replacement
(<https://csrc.nist.gov/pubs/sp/800/22/r1/upd1/final>).

The suite has 15 tests. Each section's "Input Size Recommendation"
gives the input it needs for its statistics to be valid:

| § | Test | Input size recommendation |
|---|---|---|
| 2.1 | Frequency (Monobit) | n ≥ 100 bits |
| 2.2 | Frequency within a Block | n ≥ 100 bits; n ≥ MN, M ≥ 20, M > 0.01n, N < 100 |
| 2.3 | Runs | n ≥ 100 bits |
| 2.4 | Longest Run of Ones in a Block | n ≥ 128 (M = 8), 6272 (M = 128) or 750,000 bits (M = 10⁴) |
| 2.5 | Binary Matrix Rank | n ≥ 38,912 bits (M = Q = 32) |
| 2.6 | Discrete Fourier Transform (Spectral) | n ≥ 1000 bits |
| 2.7 | Non-overlapping Template Matching | m = 9 or 10 recommended; N ≤ 100, M > 0.01n |
| 2.8 | Overlapping Template Matching | n ≥ 10⁶ bits |
| 2.9 | Maurer's "Universal Statistical" | n ≥ 387,840 bits (L = 6), larger for larger L |
| 2.10 | Linear Complexity | n ≥ 10⁶ bits; 500 ≤ M ≤ 5000, N ≥ 200 |
| 2.11 | Serial | m < log₂ n − 2 |
| 2.12 | Approximate Entropy | m < log₂ n − 5 |
| 2.13 | Cumulative Sums (Cusum) | n ≥ 100 bits |
| 2.14 | Random Excursions | n ≥ 10⁶ bits |
| 2.15 | Random Excursions Variant | n ≥ 10⁶ bits |

The largest requirement is a million bits, 125,000 bytes.

### Chi-squared goodness-of-fit for byte uniformity

Not part of SP 800-22, but the standard test of whether bytes are
spread evenly over all 256 values. With 256 categories it has 255
degrees of freedom; the critical values, computed with
`scipy.stats.chi2.ppf` in the experiment, are 293.2478 at α = 0.05 and
310.4574 at α = 0.01. A common rule of thumb for the test's
approximation is an expected count of at least 5 per category, which
for 256 categories means at least 1280 bytes; see
[Detection power vs. sample size](#detection-power-vs-sample-size) for
how the test behaves below that.

### Shannon entropy

H = −Σ p(x)·log₂ p(x), at most 8 bits per byte, for bytes spread
evenly over all 256 values. The measure comes from C. E. Shannon, "A
Mathematical Theory of Communication", *Bell System Technical
Journal*, vol. 27, no. 3, pp. 379–423, July 1948
(DOI [10.1002/j.1538-7305.1948.tb01338.x](https://doi.org/10.1002/j.1538-7305.1948.tb01338.x)).

For keyslot data it is a weak signal. Intact ciphertext sits just
under 8 bits per byte, and so does ciphertext with some bytes changed;
it only drops noticeably when a large amount of low-entropy data is
mixed in.

## Do keyslot areas have enough bytes for these tests?

A keyslot's split key material is 4000 times the key size, rounded up
to whole 512-byte sectors (see
[`af-splitting-explained.md#what-is-written-to-disk`](af-splitting-explained.md#what-is-written-to-disk)):

```
32-byte key -> 128,000 bytes = 1,024,000 bits
64-byte key -> 256,000 bytes = 2,048,000 bits
```

Both meet every requirement in the table above, including the
million-bit ones. The area itself is somewhat larger (258,048 bytes
for a 64-byte key with cryptsetup's defaults), and the extra bytes are
random filler (see
[`luks2-header-anatomy.md#reading-area-offset--area-length`](luks2-header-anatomy.md#reading-area-offset--area-length)),
so testing the whole area changes nothing.
`scripts/inspect-keyslot` already reads the whole area for its two
heuristics; it only displays the first and last 128 bytes. A test
limited to a small part of the area, such as one 64-byte stripe, would
be too short for most of these tests.

## What no test on the stored bytes can detect

What a keyslot area stores is ciphertext: the split key material,
encrypted with the area cipher (see
[`af-splitting-explained.md#what-is-written-to-disk`](af-splitting-explained.md#what-is-written-to-disk)).
To anyone without the key, good ciphertext looks like random bytes,
which is what the tests measure. Damage that replaces some of those
bytes with other random-looking bytes therefore leaves data that
still looks random:

- **Flipped bits.** If bits are flipped at positions that do not
  depend on the data, the result is the original XORed with a fixed
  mask. XOR with a fixed mask maps uniformly random bytes to uniformly
  random bytes, so the result has exactly the same distribution as
  before.
- **A block overwritten with random data**, or with other ciphertext,
  is random-looking by construction.

None of the tests here, nor any other test that looks only at the
stored bytes, can tell such damage from intact data, and the
experiment confirms it below. This is not a limit of the tests chosen;
the information is not in the bytes. The only check that does notice
is the master-key digest when you try to unlock, which cannot tell
damage from a wrong passphrase (see
[`checking-for-corruption.md#what-no-inspection-can-detect`](checking-for-corruption.md#what-no-inspection-can-detect)).

## Results

Columns, all computed by the experiment:

- **chi² p**: chi-squared p-value for byte uniformity; below 0.05
  means the bytes are unlikely to be uniform.
- **Entropy**: Shannon entropy, bits per byte.
- **Monobit p**: p-value of the SP 800-22 frequency (monobit) test,
  §2.1.
- **Zero run** and **Pattern run**: `inspect-keyslot`'s two values, the
  longest run of zero bytes and the longest run of consecutive
  positions where a byte equals the one 1 to 8 bytes before it. Its
  default thresholds are 32 and 6.
- **`repair`**: whether `cryptsetup repair` warns that the keyslot
  "could be corrupted" (see
  [`checking-for-corruption.md`](checking-for-corruption.md#what-corrupted-key-material-looks-like)).

Damage was applied 8192 bytes into the 256,000-byte area. The figures
are from one run; the on-disk rows vary between runs because each run
formats a new image, but not enough to change any conclusion.

### Intact data

| Sample | chi² p | Entropy | Monobit p | Zero run | Pattern run | `repair` |
|---|---|---|---|---|---|---|
| On-disk keyslot area (ciphertext) | 0.7238 | 7.999321 | 0.4997 | 2 | 2 (period 1) | silent |
| Plaintext AF-split output (not on disk) | 0.5215 | 7.999288 | 0.3924 | 2 | 2 (period 1) |  |
| Random bytes (seeded PRNG) | 0.4797 | 7.999280 | 0.6771 | 2 | 2 (period 1) |  |

The stored area is indistinguishable from random bytes by every
measure. (So is the plaintext split output, since 3999 of its 4000
stripes are random, but that is not what is on disk.)

### Damage that leaves random-looking bytes

| Sample | chi² p | Entropy | Monobit p | Zero run | Pattern run | `repair` |
|---|---|---|---|---|---|---|
| 1 bit flipped | 0.7266 | 7.999321 | 0.4988 | 2 | 2 (period 1) | silent |
| 10 bits flipped, scattered | 0.7200 | 7.999320 | 0.5014 | 2 | 2 (period 1) | silent |
| 4096 bytes overwritten with random bytes | 0.5610 | 7.999293 | 0.4010 | 2 | 2 (period 1) | silent |

Nothing changes beyond normal variation, as
[the previous section](#what-no-test-on-the-stored-bytes-can-detect)
predicts. Yet such damage destroys at least 128 bits of the key (see
[`af-splitting-explained.md#what-damage-does-to-the-key`](af-splitting-explained.md#what-damage-does-to-the-key)).
In the experiment's check on plaintext stripes, one flipped bit
changed 125 of a 32-byte key's 256 bits, and 120 of a 64-byte key's
512 bits, all within the 32-byte half that the damaged bytes line up
with.

### Damage the tests do catch

| Sample | chi² p | Entropy | Monobit p | Zero run | Pattern run | `repair` |
|---|---|---|---|---|---|---|
| 16-byte zero run | 0.7199 | 7.999320 | 0.4438 | 16 | 15 (period 1) | silent |
| 64-byte zero run | 0.6632 | 7.999310 | 0.2933 | 64 | 63 (period 1) | warns |
| 4096-byte zero run | 0.0000 | 7.975556 | 0.0000 | 4096 | 4095 (period 1) | warns |
| Last 25% zeroed | 0.0000 | 6.787521 | 0.0000 | 64000 | 63999 (period 1) | warns |
| 256 bytes of de ad be ef | 0.6048 | 7.999300 | 0.9666 | 2 | 252 (period 4) | warns |
| 2048 bytes of English text | 0.0000 | 7.998537 | 0.0397 | 2 | 27 (period 1) | warns |
| Image truncated 75% into the area (bytes present) | 0.5346 | 7.999051 | 0.5700 | 2 | 2 (period 1) | fails: Device <tmpdir>/damaged.img is not a valid LUKS device. |

What these show:

- **Different tests catch different things.** Chi-squared catches the
  English text decisively (p below 0.0001), while entropy barely moves
  (7.9985 instead of 7.9993) and the monobit test is borderline
  (p = 0.0397 in this run, just under 0.05). Text changes which byte
  values occur much more than it changes the overall balance of ones
  and zeros.
- **Small fills slip past the statistics.** A 16- or 64-byte zero run
  and a 256-byte repeating pattern leave chi-squared, entropy and the
  monobit test within normal variation. `inspect-keyslot`'s heuristics
  flag all three: the pattern runs (15, 63 and 252) exceed its
  pattern threshold of 6, and the 64-byte zero run also exceeds its
  zero-run threshold of 32. Chi-squared counts byte values over the
  whole area, so a short local pattern barely moves it; the heuristics
  look at where bytes are.
- **`cryptsetup repair` misses the shortest one.** It warned about the
  64-byte zero run and the pattern, but not the 16-byte zero run.
- **Truncation is not a statistical anomaly.** The bytes that remain
  are still random. cryptsetup catches it differently: the device is
  smaller than its header says, so cryptsetup rejects it as "not a
  valid LUKS device".

### Detection power vs. sample size

How much scattered damage does chi-squared need before it notices? The
experiment set a fraction of bytes in random data to zero:

```
     128 bytes: 1% zeroed: p=0.7977 missed;  5% zeroed: p=0.0055 detected
    1280 bytes: 1% zeroed: p=0.1882 missed;  5% zeroed: p=0.0000 detected
  128000 bytes: 1% zeroed: p=0.0000 detected;  5% zeroed: p=0.0000 detected
  256000 bytes: 1% zeroed: p=0.0000 detected;  5% zeroed: p=0.0000 detected
```

At keyslot-area sizes, 1% scattered zero bytes is enough; at 128 and
1280 bytes, 1% is missed and 5% is detected.

On 2000 samples of pure random data at each size, chi-squared reported
p < 0.05 in 5.55%, 4.75% and 5.35% of samples (128, 1280 and 128,000
bytes) and p < 0.01 in 1.45%, 1.00% and 0.60%: close to the 5% and 1%
expected, even at 128 bytes, below the 1280-byte rule of thumb. So the
false-positive rate stays right at small sizes; what suffers is
detection power, as the table above shows.

## Where this leaves `inspect-keyslot`

Which check catches which kind of damage:

- **Chi-squared**, over the whole area, catches large amounts of
  zeros and non-random contamination such as text, including some
  that entropy misses.
- **Shannon entropy** is the weakest of the three statistics at
  catching small contaminated regions.
- **`inspect-keyslot`'s zero-run and pattern heuristics** catch short
  local fills that the statistics miss, so they are not replaced by a
  statistical test.
- **`cryptsetup repair`** caught every case here except the 16-byte
  zero run, which the pattern heuristic flagged, and is already
  installed wherever cryptsetup is.
- **Nothing** catches damage that leaves random-looking bytes, such as
  flipped bits; that information is not in the stored bytes (see
  [above](#what-no-test-on-the-stored-bytes-can-detect)). Another
  keyslot or a header backup taken before the damage is the way back
  in (see
  [`checking-for-corruption.md`](checking-for-corruption.md#when-to-run-cryptsetup-repair-and-what-it-cant-fix)).

Whether to add a chi-squared check to `scripts/inspect-keyslot` is a
roadmap question this document does not settle. On these results,
the heuristics already flag every case chi-squared catches here
(the text through its pattern run of 27), so chi-squared would mainly
add a measure that does not depend on local structure.
