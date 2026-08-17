# Cold Boot and DMA Attacks: A Different Threat Model Entirely

[`af-splitting-explained.md`](af-splitting-explained.md#aside-where-does-that-key-length-number-actually-come-from)
documents precisely where a LUKS2 volume's cleartext master key lives
while mounted: briefly in `cryptsetup`'s own memory during unlock, and
then continuously, for as long as the volume stays mapped, inside the
Linux kernel's `dm-crypt` target (`struct crypt_config`, plain kernel
heap memory, no special hardware isolation). That naturally raises the
question: if the key just sits there in ordinary RAM the whole time a
volume is mounted, can't someone with physical access to the machine
just read it out of memory?

Yes — and that's a real, well-studied attack class. This document
covers it on its own, separately from the rest of this project, because
it is a **fundamentally different threat model** from everything else
`luks-doctor` addresses.

## Contents

- [Why this is a separate document, not a subsection](#why-this-is-a-separate-document-not-a-subsection)
- [Cold boot attacks](#cold-boot-attacks)
- [DMA attacks](#dma-attacks)
- [Why the kernel-resident key specifically is the target](#why-the-kernel-resident-key-specifically-is-the-target)
- [Real mitigations, checked against actual source](#real-mitigations-checked-against-actual-source)
  - [`cryptsetup luksSuspend`](#cryptsetup-lukssuspend)
  - [Reset-attack mitigation (UEFI memory clearing)](#reset-attack-mitigation-uefi-memory-clearing)
  - [IOMMU-based DMA protection](#iommu-based-dma-protection)
  - [Register-only key residency: TRESOR and why it's not the answer either](#register-only-key-residency-tresor-and-why-its-not-the-answer-either)
- [What no software mitigation fixes](#what-no-software-mitigation-fixes)

## Why this is a separate document, not a subsection

Every other document in this repo assumes the same starting scenario:
a LUKS2 volume that's **powered off and disconnected** — the actual
situation this project's recovery tooling and diagnostic docs are built
for (see the project's own scope statement in `CLAUDE.md`). Cold boot
and DMA attacks require the opposite: **physical access to a machine
that is already running, with the volume already unlocked.** That's not
a variation on this project's scope — it's a different problem with a
different attacker, different preconditions, and no overlap with
AF-splitting, keyslot inspection, or passphrase recovery. Folding it
into an existing doc would blur that boundary; this document exists so
the boundary stays sharp.

## Cold boot attacks

The foundational reference is Halderman, Schoen, Heninger, Clarkson,
Paul, Calandrino, Feldman, Appelbaum, Felten, *"Lest We Remember: Cold
Boot Attacks on Encryption Keys,"* 17th USENIX Security Symposium,
2008, pp. 45–60 — <https://www.usenix.org/legacy/event/sec08/tech/full_papers/halderman/halderman.pdf>
(fetched and read directly, not summarized secondhand).

**The core physical fact (DRAM remanence)**: DRAM doesn't lose its
contents the instant power is cut — it decays gradually. From the
paper's own measurements (§3):

- At normal operating temperature, decay varied by machine: complete
  data loss in as little as ~2.5 seconds on the fastest-decaying
  machine tested, but as long as ~35 seconds on the slowest.
- Cooled to about -50°C with an inverted can of compressed air, fewer
  than 1% of bits had decayed after a full **10 minutes** without
  power.
- In an extreme test, a DRAM module cooled to -50°C, then powered off
  and submerged in **liquid nitrogen (-196°C) for 60 minutes**, showed
  only 0.17% bit decay (14,000 errors in a 1 MB region) — cold enough
  DRAM stays readable for a genuinely long time with no power at all.

**Extracting a usable key from a decayed memory image (§5–6)**: the
paper doesn't need a perfect, error-free capture. It exploits the fact
that an AES/DES *key schedule* (the expanded round-key material an
implementation actually keeps in memory, not just the raw key) is
highly redundant — many of its bits are derivable from others — so
error-correction techniques can reconstruct the original key even from
a memory image with a meaningful bit-error rate. Their `keyfind` tool
scans a memory image for byte patterns that satisfy (or nearly satisfy)
the mathematical structure of a valid key schedule, without needing to
already know the key.

**dm-crypt/LUKS was directly tested, not just theorized about** —
quoted verbatim from the paper (§7, "dm-crypt" subsection, p. 57):

> We tested a dm-crypt volume created and mounted using the LUKS (Linux
> Unified Key Setup) branch of the `cryptsetup` utility and kernel
> version 2.6.20. The volume used the default AES-CBC format. We
> briefly powered down the system and captured a memory image with our
> PXE kernel. Our `keyfind` program identified the correct 128-bit AES
> key, which did not contain any bit errors. After recovering this key,
> an attacker could decrypt and mount the dm-crypt volume by modifying
> the `cryptsetup` program to allow input of the raw key.

The paper's own conclusion is blunt (§9, p. 59): *"There seems to be
no easy remedy for these vulnerabilities... The risk seems highest for
laptops, which are often taken out in public in states that are
vulnerable to our attacks."*

## DMA attacks

Mechanically distinct from cold boot: **no power cycle needed at all**.
A DMA-capable peripheral — historically FireWire, now more commonly
PCIe, Thunderbolt, or USB-C with Thunderbolt/USB4 support — can read
(and write) physical memory directly while the target machine is
powered on and running, because Direct Memory Access is designed to
bypass the CPU's normal memory-protection path for performance. Without
active IOMMU constraints, a malicious device plugged into a live,
unlocked machine can read arbitrary physical memory in seconds — no
exploit against the OS itself required.

A credible, peer-reviewed demonstration: A. Theodore Markettos, Colin
Rothwell, Brett F. Gutstein, Allison Pearce, Peter G. Neumann, Simon W.
Moore, Robert N. M. Watson, *"Thunderclap: Exploring Vulnerabilities in
Operating System IOMMU Protection via DMA from Untrustworthy
Peripherals,"* NDSS Symposium 2019, DOI
[10.14722/ndss.2019.23194](https://doi.org/10.14722/ndss.2019.23194)
(fetched directly). Using an FPGA-based malicious-peripheral platform
emulating ordinary device classes (a network card), disguised as
plausible hardware like a Thunderbolt dock or USB-C charger, the
authors demonstrated memory compromise "within seconds of connecting"
on vulnerable macOS, FreeBSD, and Linux systems — not by defeating
IOMMU translation outright, but by exploiting how OS/driver code
manages shared-memory structures exposed to DMA-capable devices (race
conditions, windows where IOMMU protections are momentarily open). The
practical takeaway: **an IOMMU being present and nominally enabled does
not, by itself, guarantee protection** — implementation details in the
driver stack matter.

(PCILeech, an open-source PCIe-hardware DMA toolkit, is a real and
widely-referenced tool for this same attack class, but this document
doesn't quote specific capability claims from its own documentation —
that wasn't independently fetched and verified for this doc, so treat
"PCILeech exists and does PCIe DMA memory access" as the extent of the
verified claim here, not a citation for anything more specific.)

## Why the kernel-resident key specifically is the target

Both attack classes are indifferent to whether the key sits in
userspace or kernel memory — they target *physical RAM contents*, and
`struct crypt_config`'s key material
([`drivers/md/dm-crypt.c`](https://github.com/torvalds/linux/blob/master/drivers/md/dm-crypt.c),
per [`af-splitting-explained.md`](af-splitting-explained.md)) occupies
ordinary kernel heap pages like any other allocation — no TPM sealing,
no CPU enclave, no special isolation in a default configuration. If
anything, the kernel-resident copy is the *better* target of the two
copies discussed in the af-splitting doc: it's resident continuously
for the entire time a volume stays mounted, not just for the brief
window `crypt_safe_alloc()`/`crypt_safe_free()` hold the userspace
copy during unlock.

The precise scope boundary worth repeating: both attacks require
**physical access to an already-unlocked, running (or very recently
running) machine.** Neither one says anything about LUKS2's on-disk
format, AF-splitting's correctness, or this project's recovery tooling
— all of which concern a volume that's powered off. This is a
completely different attacker with a completely different set of
preconditions.

## Real mitigations, checked against actual source

### `cryptsetup luksSuspend`

The strongest, most directly relevant mitigation this research turned
up — LUKS-specific, not a general OS feature. Per the man page
(`cryptsetup-luksSuspend(8)`, fetched 2026-08-17): it "suspends an
active device (all IO operations will block) and wipes the encryption
key from kernel memory." An explicit caveat in the same man page: *"it
does not remove possible plaintext data in various caches or in-kernel
metadata for mounted filesystems"* — this wipes the key specifically,
not a general memory scrub. Resuming requires `luksResume`, which
re-prompts for and re-derives the key from the passphrase.

The actual wipe, confirmed directly in kernel source
(`drivers/md/dm-crypt.c`, `crypt_wipe_key()`, current mainline as of
2026-08-17):

```c
static int crypt_wipe_key(struct crypt_config *cc)
{
	int r;

	clear_bit(DM_CRYPT_KEY_VALID, &cc->flags);
	get_random_bytes(&cc->key, cc->key_size);

	/* Wipe IV private keys */
	if (cc->iv_gen_ops && cc->iv_gen_ops->wipe)
		cc->iv_gen_ops->wipe(cc);

	kfree_sensitive(cc->key_string);
	cc->key_string = NULL;
	r = crypt_setkey(cc);
	memset(&cc->key, 0, cc->key_size * sizeof(u8));

	return r;
}
```

Notably, this doesn't just zero the key — it first **overwrites it
with fresh random bytes** (`get_random_bytes`) and re-derives the
(now-meaningless) cipher schedule from that garbage, *then* zeroes the
buffer. That extra step matters against exactly the attack described
above: Halderman et al.'s key-schedule reconstruction (§5 of their
paper) exploits redundant structure in a *valid* key schedule; briefly
overwriting with random data before zeroing destroys that structure
first, rather than relying on the zero-write alone.

`crypt_message()` (same file) requires the device already be suspended
(`DM_CRYPT_SUSPENDED` flag set) before it will honor a `"key wipe"`
message — confirmed via the source's own inline comment (`/* Message
interface: key set <key> / key wipe */`) and an explicit rejection path
(`-EINVAL`, logged as "not suspended during key manipulation") when
that precondition isn't met — matching the man page's combined
suspend-then-wipe description.

Systemd integration exists specifically for the suspend/resume power
state (`cryptsetup-suspend(7)` man page, fetched 2026-08-17), which
states its own purpose in exactly these terms: *"Suspending LUKS
devices basically means to remove the corresponding encryption keys
from system memory. This protects against all sort of attacks that try
to read out the memory from a suspended system, like for example
cold-boot attacks."* Its own stated limitation: it protects only the
LUKS encryption keys, not other sensitive data that might be in RAM.

**What this doesn't cover**: a volume that's actively mounted and in
use, not suspended. By definition, the key has to be valid in ordinary
kernel memory for I/O to work at all — `luksSuspend` only helps for the
specific window where the machine (or just that volume) is
deliberately put in a non-working, suspended state.

A 2015 kernel patch series proposing *automatic* key-wiping on
suspend/hibernation (`[PATCH 0/3] dm-crypt: Adds support for wiping key
when doing suspend/hibernation`,
<https://lore.kernel.org/linux-pm/5530C9DE.2040302@redhat.com/>) does
not appear to have been merged — a direct search of current mainline
`dm-crypt.c` for the function/flag names that patch series introduced
turned up nothing. Only the manual `"key wipe"` message (via
`luksSuspend`) exists in mainline today; don't assume dm-crypt
auto-wipes on suspend without it being explicitly invoked.

### Reset-attack mitigation (UEFI memory clearing)

Confirmed directly against current mainline kernel source
(`drivers/firmware/efi/Kconfig`, fetched 2026-08-17):

```
config RESET_ATTACK_MITIGATION
	bool "Reset memory attack mitigation"
	depends on EFI_STUB
	help
	  Request that the firmware clear the contents of RAM after a reboot
	  using the TCG Platform Reset Attack Mitigation specification. This
	  protects against an attacker forcibly rebooting the system while it
	  still contains secrets in RAM, booting another OS and extracting the
	  secrets. This should only be enabled when userland is configured to
	  clear the MemoryOverwriteRequest flag on clean shutdown after secrets
	  have been evicted, since otherwise it will trigger even on clean
	  reboots.
```

This targets a specific variant sometimes called a "warm boot attack":
forcing a reboot while secrets are still resident, then booting an
attacker-controlled OS to read them, via a UEFI-level
`MemoryOverwriteRequestControl` flag that tells firmware to zero RAM on
the next boot. It requires `EFI_STUB` and correct userland cooperation
(clearing the flag only after secrets are actually gone, on a clean
shutdown). **What it doesn't cover**: it does nothing against a DMA
attack (no reboot involved at all), and nothing against the "physically
remove the DRAM modules and cool them" variant of cold boot the
Halderman paper describes (§4) — pulling the RAM chips out entirely
bypasses any firmware-triggered clearing on the next boot, since there
is no next boot on that hardware.

### IOMMU-based DMA protection

Confirmed directly against current mainline kernel source
(`drivers/iommu/Kconfig`, fetched 2026-08-17):

```
config IOMMU_DEFAULT_DMA_STRICT
	bool "Translated - Strict"
	help
	  Trusted devices use translation to restrict their access to only
	  DMA-mapped pages, with strict TLB invalidation on unmap. ...

config IOMMU_DEFAULT_DMA_LAZY
	bool "Translated - Lazy"
	help
	  Trusted devices use translation to restrict their access to only
	  DMA-mapped pages, but with "lazy" batched TLB invalidation. This
	  mode allows higher performance with some IOMMUs due to reduced TLB
	  flushing, but at the cost of reduced isolation since devices may be
	  able to access memory for some time after it has been unmapped. ...
```

The default on x86 and s390 is the **lazy** mode (`default
IOMMU_DEFAULT_DMA_LAZY if X86 || S390`), which the kernel's own help
text admits trades isolation for performance — a device can retain
access to recently-unmapped memory for some time. This can be
overridden with the `iommu.strict=1` boot parameter (equivalent to
selecting `IOMMU_DEFAULT_DMA_STRICT`).

Even strict mode isn't a complete answer, per the Thunderclap paper
above: their bypass worked against systems with IOMMUs nominally
enabled, by exploiting driver-level assumptions and timing windows
around shared DMA buffers, not by defeating IOMMU translation directly.
IOMMU protection narrows the attack surface; it doesn't close it.

### Register-only key residency: TRESOR, and why it's not the answer either

TRESOR ("TRESOR Runs Encryption Securely Outside RAM," Müller,
Freiling, Dewald, USENIX Security 2011) is a real research project that
stores AES key material in x86 debug registers (DR0–DR3) instead of
RAM, and blocks `ptrace` access to those registers — a direct attempt
to make cold boot irrelevant by never letting the key touch memory at
all. Its status today: **dormant, out-of-tree, never merged into
mainline Linux.** The project's own page (Friedrich-Alexander-Universität
Erlangen-Nürnberg,
<https://www.cs1.tf.fau.de/research/system-security-group/tresor-trevisor-armored/>,
fetched 2026-08-17) lists patches only through roughly kernel 3.18 —
around 2014/2015 — with no sign of continued maintenance since.
Related projects from the same group (TreVisor, combining TRESOR with
a hypervisor; ARMORED, an ARM port) share the same dormant status.

Even setting aside its unmaintained state, register-only storage
doesn't fully close the gap: TRESOR-HUNT (Blass & Robertson, ACSAC
2012, "TRESOR-HUNT: Attacking CPU-Bound Encryption") is a DMA-based
attack specifically targeting TRESOR — a DMA-capable attacker can
inject a privileged payload that forces the CPU to copy the
register-held key back out into memory, from which ordinary DMA read
recovers it. (This document did not independently fetch and verify the
TRESOR-HUNT paper's exact technical claims — treat this paragraph as
based on a secondary search summary, not a directly-read primary
source, and verify further before citing specifics beyond "a real,
published DMA-based attack against TRESOR exists.") The general lesson
still holds without needing every technical detail nailed down:
register-only residency is a plausible-sounding fix for cold boot
specifically, but a DMA attacker — who can write to memory and force
CPU behavior, not just passively read RAM — is a different enough
adversary that a cold-boot mitigation doesn't automatically defend
against it too.

## What no software mitigation fixes

None of the mitigations above protect a machine that is simply
**mounted and actively in use**. By definition, the kernel-resident key
must be valid, in ordinary kernel memory, for I/O to work at all — none
of `RESET_ATTACK_MITIGATION`, IOMMU strict mode, or `luksSuspend`
change that basic fact while the volume is genuinely in active use.
There is no software configuration that keeps a LUKS volume both usable
and cryptographically inert to a physically-present attacker while it's
mounted — the closest research got (register-only residency) is
unmaintained and has its own documented DMA-specific bypass.

More broadly: an attacker with unsupervised physical access to a
running, unlocked machine has a large attack surface generally, of
which cold boot and DMA are just two, comparatively fast and quiet,
instances — the same attacker could install a hardware keylogger, image
the mounted filesystem through the OS's own APIs, or simply use the
already-unlocked session directly. The mitigations above narrow one
specific vector; none of them, individually or combined, make an
unattended, unlocked, running machine safe in any general sense. Sound
physical security for a machine that will be left running and unlocked
is a separate problem from anything LUKS2 or this project's tooling can
solve.
