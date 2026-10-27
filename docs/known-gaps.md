# Known gaps

What whiff deliberately leaves out of the formats it already handles, and
formats in an implemented family that are not read yet. Each item was set
aside on purpose, usually because no tool or sample was at hand to check
whiff against, or because it needs work planned for a later stage. Files
in these formats are still identified by signature, and partial support is
reported as such (a warning, or facts without a listing).

Contributions are welcome. A gap closes like any other format: a benign
fixture made by a real tool, a snapshot, and agreement with an independent
reader (see [CONTRIBUTING.md](../CONTRIBUTING.md)).

## Compressed files and archives (0.5.0)

- **Entries listed but not decompressed:** RAR (only stored entries are
  handed on), LHA and ARJ (stored only), CAB Quantum and LZX folders, 7z
  PPMd and BCJ2 folders. Their names, sizes, times and methods are listed.
- **Headers only:** lzop and LZFSE files are described but not
  decompressed.
- **Not read:** ZOO, ACE, StuffIt, ARC, WIM and shell archives (`shar`),
  for lack of a writer or reader to check against.
- **Multi-volume sets** (`.z01`, `.part2.rar`, `.7z.002` …): only the
  volume given is read.
- **Self-extractors inside executables:** a ZIP after an executable is
  found; other self-extracting formats come with executables (Stage 6).

## Packages (0.5.1)

- **Signatures are described, not verified:** whiff reports who signed a
  package and how, but does not check the signature or the certificate
  chain.
- **Not read:** Solaris SVR4 packages, Windows update packages (`.msu`),
  Unity packages, Homebrew bottles.

## Disk images (0.5.1, feature `forensics`)

- **File listings:** FAT, ext2 / 3 / 4, ISO 9660, UDF, squashfs, Amiga
  and C64 volumes are listed. NTFS, HFS+, APFS and exFAT volumes are
  described (label, UUID, sizes, times, APFS volumes) but not listed.
- **Encrypted volumes** (LUKS, BitLocker, encrypted APFS volumes and
  QCOW2 images) are detected and described, never unlocked.
- **UDF:** write-once discs with a virtual allocation table are described
  but not listed. The metadata partitions of UDF 2.50 and later are read
  but untested on a real disc; revisions 1.02, 1.50 and 2.01 are checked.
- **Evidence files:** EnCase `.Ex01` is not read, and of a split E01 set
  only the first segment is (the acquired disk is cut short there).
- **Not read:** Nero `.nrg`, Alcohol `.mds` / `.mdf`, Amstrad CPC `.dsk`,
  Atari ST specifics, sparse bundles (a folder, not a file), Android
  Verified Boot footers, UEFI firmware volumes, Flatpak `.flatpak`
  bundles.
- **Backing files:** a differencing or overlay disk (VHD, VMDK, QCOW2,
  QED) whose blocks live in a parent image reads those blocks as zeros;
  the parent's name is reported.
