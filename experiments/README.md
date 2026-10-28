# Experiments

Reproducible checks behind specific claims in [`docs/`](../docs). Each
subdirectory is one experiment, with:

- `README.md`: the claim being tested, the sources it is checked
  against, requirements, how to run it, and the output it produced when
  the docs were written;
- `run`: a POSIX `sh` script that runs the whole experiment;
- the experiment's own code.

Shared code lives in [`lib/`](lib):

- [`lib/luks_af.py`](lib/luks_af.py): a line-by-line Python port of
  cryptsetup's AF splitter (`lib/luks1/af.c`), with the upstream line
  numbers in its comments. It is for experiments only: it is not
  constant-time and does not wipe memory, so never use it on real key
  material.

No experiment needs root, touches a block device, or uses real key
material. Experiments that need a LUKS2 volume create a throwaway image
file with a synthetic passphrase in a temporary directory and delete it
on exit.

## Index

| Experiment | Claim tested | Needs |
|---|---|---|
| [`af-damage-locality/`](af-damage-locality) | How far damage to one AF stripe spreads into the merged key | `python3` |
| [`keyslot-damage-e2e/`](keyslot-damage-e2e) | How one damaged byte in a real LUKS2 keyslot area reaches the key, and what cryptsetup reports | `cryptsetup`, `python3`, Python `cryptography` |
| [`default-key-sizes/`](default-key-sizes) | Which master key size `luksFormat` picks for each cipher without `--key-size`, and which cipher the keyslot area uses | `cryptsetup`, `python3` |
| [`header-anatomy/`](header-anatomy) | The binary header layout, how the primary and secondary headers differ, the default on-disk layout, and how cryptsetup handles a damaged primary header | `cryptsetup`, `python3`; up to 1 GiB RAM for the default Argon2id |
| [`corruption-signals/`](corruption-signals) | What `luksDump`, `repair` and `open --test-passphrase` report for different kinds of keyslot and header damage, and what a header backup contains | `cryptsetup`, `xxd` |

## Running

From the repository root:

```
experiments/af-damage-locality/run
experiments/keyslot-damage-e2e/run
experiments/default-key-sizes/run
experiments/header-anatomy/run
experiments/corruption-signals/run
```

The `run` scripts pass `shellcheck --shell=sh`. They were run under
`bash --posix`; `dash` was not available on the machine used.
