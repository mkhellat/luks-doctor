# Cold Boot and DMA Attacks: A Different Threat Model Entirely

[`master-key-lifecycle.md`](master-key-lifecycle.md#where-the-key-lives-in-memory)
shows where a LUKS2 volume's plaintext master key lives while the
volume is open: briefly in `cryptsetup`'s memory during unlock, and for
as long as the volume stays mapped, in the kernel's dm-crypt target, in
ordinary kernel heap memory. So can someone with physical access to the
running machine read it out of memory? Yes: this is a well-studied
class of attack, covered here separately because its threat model is
different from the rest of `luks-doctor`.

## Contents

- [Why this is a separate document](#why-this-is-a-separate-document)
- [Cold boot attacks](#cold-boot-attacks)
- [DMA attacks](#dma-attacks)
- [Why the kernel-resident key is the target](#why-the-kernel-resident-key-is-the-target)
- [Mitigations, checked against source](#mitigations-checked-against-source)
  - [`cryptsetup luksSuspend`](#cryptsetup-lukssuspend)
  - [Reset attack mitigation (UEFI memory clearing)](#reset-attack-mitigation-uefi-memory-clearing)
  - [IOMMU-based DMA protection](#iommu-based-dma-protection)
  - [Keeping the key out of RAM: TRESOR](#keeping-the-key-out-of-ram-tresor)
- [What no software mitigation fixes](#what-no-software-mitigation-fixes)

## Why this is a separate document

The rest of this project deals with a volume that is not in use: a
locked device whose header, keyslots or passphrase need inspecting or
recovering. Cold boot and DMA attacks need the opposite: physical
access to a machine that is running, or was running moments ago, with
the volume unlocked. They have nothing to do with AF-splitting,
keyslot inspection or passphrase recovery.

## Cold boot attacks

The standard reference is J. A. Halderman, S. D. Schoen, N. Heninger,
W. Clarkson, W. Paul, J. A. Calandrino, A. J. Feldman, J. Appelbaum,
E. W. Felten, "Lest We Remember: Cold Boot Attacks on Encryption
Keys", *17th USENIX Security Symposium*, 2008, pp. 45–60
(<https://www.usenix.org/legacy/event/sec08/tech/full_papers/halderman/halderman.pdf>).
Page numbers below are the proceedings' (the PDF's page 1 is p.45).

**DRAM keeps its contents for a while without power.** The paper
measured:

- at normal operating temperature, "the fastest exhibiting complete
  data loss in approximately 2.5 seconds and the slowest taking an
  average of 35 seconds" (§3.1, p.48);
- cooled to about −50 °C by spraying an inverted can of compressed-air
  duster on the chips, "we typically found that fewer than 1% of bits
  decayed even after 10 minutes without power" (§1, p.46);
- cooled to −50 °C, removed from the machine and kept in liquid
  nitrogen for 60 minutes, "only 14,000 bit errors within a 1 MB test
  region (0.17% decay)" (§3.2, p.49).

**Keys can be found and repaired in a decayed memory image.** An AES
implementation keeps the expanded *key schedule* in memory, not just
the key, and the schedule has a lot of redundant structure. The paper
uses that structure to correct bit errors in recovered keys (§5) and to
find keys in a memory image without knowing them in advance, with its
`keyfind` tool (§6).

**dm-crypt with LUKS was tested directly** (§7 "Attacking Encrypted
Disks", p.57):

> We tested a dm-crypt volume created and mounted using the LUKS
> (Linux Unified Key Setup) branch of the cryptsetup utility and kernel
> version 2.6.20. The volume used the default AES-CBC format. We
> briefly powered down the system and captured a memory image with our
> PXE kernel. Our keyfind program identified the correct 128-bit AES
> key, which did not contain any bit errors. After recovering this key,
> an attacker could decrypt and mount the dm-crypt volume by modifying
> the cryptsetup program to allow input of the raw key.

The paper's conclusion (§9, p.59): "There seems to be no easy remedy
for these vulnerabilities. [...] The risk seems highest for laptops,
which are often taken out in public in states that are vulnerable to
our attacks."

## DMA attacks

A DMA attack needs no power cycle. A device with direct memory access,
on PCIe or Thunderbolt for example, can read and write physical memory
while the machine runs, unless an IOMMU restricts what it can reach.

A peer-reviewed demonstration: A. T. Markettos, C. Rothwell, B. F.
Gutstein, A. Pearce, P. G. Neumann, S. W. Moore, R. N. M. Watson,
"Thunderclap: Exploring Vulnerabilities in Operating System IOMMU
Protection via DMA from Untrustworthy Peripherals", *NDSS Symposium
2019*, DOI
[10.14722/ndss.2019.23194](https://doi.org/10.14722/ndss.2019.23194).
The authors built an FPGA platform that behaves as a working network
card, packaged as "malicious docking stations [...], USB-C chargers,
and projectors", and report: "We are able to achieve IOMMU bypass
within seconds of connecting on vulnerable macOS, FreeBSD, and Linux
systems across a range of hardware vendors." They did not break IOMMU
translation itself; they exploited what the operating system and its
drivers expose to the device through shared memory. An IOMMU that is
present and enabled therefore does not, on its own, guarantee
protection.

## Why the kernel-resident key is the target

Both attacks read physical memory, so they do not care whether the key
is in user or kernel memory. dm-crypt's copy, in `struct crypt_config`
([`drivers/md/dm-crypt.c`](https://github.com/torvalds/linux/blob/43fd83c0b1dc127cf13b4c05303665924e63ef94/drivers/md/dm-crypt.c#L237),
line 237), and the key schedules in its cipher objects are ordinary
kernel heap memory, with no hardware isolation in a default setup (see
[`master-key-lifecycle.md`](master-key-lifecycle.md)). They stay there
for as long as the volume is mapped, while cryptsetup's own copy exists
only during unlock, which makes the kernel's copy the better target.

Both attacks need physical access to an unlocked, running (or just
switched off) machine. Neither says anything about LUKS2's on-disk
format or this project's recovery tooling.

## Mitigations, checked against source

### `cryptsetup luksSuspend`

`cryptsetup luksSuspend` "Suspends an active device (all IO operations
will block and accesses to the device will wait indefinitely) and
wipes the encryption key from kernel memory". The same man page adds:
"While the _luksSuspend_ operation wipes encryption keys from memory,
it does not remove possible plaintext data in various caches or
in-kernel metadata for mounted filesystems"
([`cryptsetup-luksSuspend(8)`](https://gitlab.com/cryptsetup/cryptsetup/-/blob/bae21790d59897ac50e5471f953f76b3a58aeeb6/man/cryptsetup-luksSuspend.8.adoc)).
`cryptsetup luksResume` "Resumes a suspended device and reinstates the
encryption key", taking it from a passphrase, a key file or a token
([`cryptsetup-luksResume(8)`](https://gitlab.com/cryptsetup/cryptsetup/-/blob/bae21790d59897ac50e5471f953f76b3a58aeeb6/man/cryptsetup-luksResume.8.adoc)).

In the kernel, the wipe is the "key wipe" message to dm-crypt.
`crypt_message()` accepts key messages only while the device is
suspended, and otherwise logs "not suspended during key manipulation."
and returns an error
([`dm-crypt.c`](https://github.com/torvalds/linux/blob/43fd83c0b1dc127cf13b4c05303665924e63ef94/drivers/md/dm-crypt.c#L3625-L3668),
lines 3625–3668). "key wipe" calls `crypt_wipe_key()` (lines
2633–2650):

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

It overwrites the key in `struct crypt_config` with random bytes, loads
those random bytes into the cipher objects with `crypt_setkey()`, which
replaces the real key's schedules there, and then zeroes the key
buffer. `crypt_preresume()` refuses to resume a device whose key has
not been set again ("aborting resume - crypt key is not set.", lines
3606–3616).

Suspending the machine does not do this by itself. dm-crypt's own
suspend hook, `crypt_postsuspend()`, only marks the device suspended
(lines 3599–3604), and the file has no code that runs on system sleep
or hibernation; the key is wiped only when a "key wipe" message is
sent. Debian's `cryptsetup-suspend` package adds that: it "brings
support to automatically suspend LUKS devices before entering system
suspend mode", and its man page says "Suspending LUKS devices
basically means to remove the corresponding encryption keys from
system memory. This protects against all sort of attacks that try to
read out the memory from a suspended system, like for example
cold-boot attacks", and that it "protects only the encryption keys of
your LUKS devices"
([`cryptsetup-suspend(7)`](https://manpages.debian.org/unstable/cryptsetup-suspend/cryptsetup-suspend.7.en.html),
Debian package `cryptsetup-suspend` 2:2.8.8-1).

**What this does not cover**: a volume in use. While the volume is
being read and written, the key has to be in kernel memory;
`luksSuspend` only helps while the volume, or the whole machine, is
suspended.

### Reset attack mitigation (UEFI memory clearing)

The kernel option `RESET_ATTACK_MITIGATION`
([`drivers/firmware/efi/Kconfig`](https://github.com/torvalds/linux/blob/43fd83c0b1dc127cf13b4c05303665924e63ef94/drivers/firmware/efi/Kconfig#L170-L181),
lines 170–181):

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

The flag is the UEFI variable `MemoryOverwriteRequestControl`, which
the kernel's EFI stub sets
([`drivers/firmware/efi/libstub/tpm.c`](https://github.com/torvalds/linux/blob/43fd83c0b1dc127cf13b4c05303665924e63ef94/drivers/firmware/efi/libstub/tpm.c#L18),
line 18). It covers an attacker who reboots the machine into their own
system. It does nothing against a DMA attack, which needs no reboot,
or against moving the memory modules to another machine, a variant the
cold boot paper describes in §4 ("Transferring DRAM modules"), since
the original machine's firmware never runs.

### IOMMU-based DMA protection

How the IOMMU handles devices is a kernel build choice
([`drivers/iommu/Kconfig`](https://github.com/torvalds/linux/blob/43fd83c0b1dc127cf13b4c05303665924e63ef94/drivers/iommu/Kconfig#L96-L140),
lines 96–140). The default on x86 and s390 is lazy mode
(`default IOMMU_DEFAULT_DMA_LAZY if X86 || S390`):

```
config IOMMU_DEFAULT_DMA_STRICT
	bool "Translated - Strict"
	help
	  Trusted devices use translation to restrict their access to only
	  DMA-mapped pages, with strict TLB invalidation on unmap. Equivalent
	  to passing "iommu.passthrough=0 iommu.strict=1" on the command line.

	  Untrusted devices always use this mode, with an additional layer of
	  bounce-buffering such that they cannot gain access to any unrelated
	  data within a mapped page.

config IOMMU_DEFAULT_DMA_LAZY
	bool "Translated - Lazy"
	help
	  Trusted devices use translation to restrict their access to only
	  DMA-mapped pages, but with "lazy" batched TLB invalidation. This
	  mode allows higher performance with some IOMMUs due to reduced TLB
	  flushing, but at the cost of reduced isolation since devices may be
	  able to access memory for some time after it has been unmapped.
	  Equivalent to passing "iommu.passthrough=0 iommu.strict=0" on the
	  command line.
```

So lazy mode applies to devices the kernel trusts; devices it treats
as untrusted always get strict mode with bounce buffers. The
`iommu.strict=1` boot parameter selects strict mode for trusted devices
too
([`kernel-parameters.txt`](https://github.com/torvalds/linux/blob/43fd83c0b1dc127cf13b4c05303665924e63ef94/Documentation/admin-guide/kernel-parameters.txt#L2668-L2679),
lines 2668–2679). As Thunderclap showed, even with translation in
place, a device can attack what the operating system shares with it;
an IOMMU narrows DMA attacks but does not rule them out.

### Keeping the key out of RAM: TRESOR

T. Müller, F. C. Freiling, A. Dewald, "TRESOR Runs Encryption Securely
Outside RAM", *20th USENIX Security Symposium*, 2011
(<https://www.usenix.org/legacy/event/sec11/tech/full_papers/Muller.pdf>),
keeps the AES key in the x86 debug registers instead of RAM, and
patches the `ptrace` system call "to return -EBUSY whenever a
breakpoint register is requested", so that user programs cannot read
them. It was never part of mainline Linux. Its project page lists
kernel patches up to `tresor-patch-3.18.5`, along with the related
TreVisor and ARMORED projects
(<https://www.cs1.tf.fau.de/research/system-security-group/tresor-trevisor-armored/>,
fetched 2026-10-28).

Keeping the key in registers addresses cold boot, not necessarily DMA.
E.-O. Blass and W. Robertson, "TRESOR-HUNT: Attacking CPU-Bound
Encryption", *ACSAC 2012*, pp. 71–78, DOI
[10.1145/2420950.2420961](https://doi.org/10.1145/2420950.2420961),
is a published attack on such schemes. This project could not obtain
the paper, so its technique is not described here.

## What no software mitigation fixes

None of the mitigations above protect a volume that is mounted and in
use: the key must be in kernel memory for reads and writes to work,
and neither `RESET_ATTACK_MITIGATION`, the IOMMU nor `luksSuspend`
changes that while the volume is active. Keeping the key in CPU
registers was tried, outside mainline, and has a published attack.

More generally, someone with unsupervised physical access to a running,
unlocked machine has many options besides cold boot and DMA, such as
using the unlocked session directly or installing a hardware
keylogger. The mitigations here each close one route; keeping an
unlocked, running machine physically secure is a separate problem from
anything LUKS2 or this project addresses.
