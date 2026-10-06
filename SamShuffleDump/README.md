# SamShuffleDump

**Purpose:** a small C# utility that decrypts local SAM account NTLM hashes using only the Registry API. It reads everything through registry calls — no `reg.exe`, no hive file export, no `reg save`, no VSS snapshots — and self-elevates to SYSTEM.

## Overview

Runs as SYSTEM and reads the local SAM directly through the Registry API. The tool uses a deliberate, configurable read schedule that differs from the conventional order most SAM dumpers follow:

1. all `Users\<RID>` `V` records are read **before** the `SAM\Domains\Account` `F` value;
2. the SYSTEM bootkey class values are read in reverse order: **Data → GBG → Skew1 → JD**.

The tool emits the same registry reads any SAM dumper would, but under a schedule the operator controls, so downstream consumers cannot assume a fixed access order. Hash decryption ports the impacket/creddump algorithm (bootkey permutation; RC4/DES old-style and AES new-style; derive Key1/Key2 from the RID).

## Environment

- **OS / arch:** Windows x64, .NET Framework 4.8.
- **Privilege required:** SYSTEM. The tool self-elevates from an elevated Administrator session via a winlogon token, with a `schtasks` fallback.

## Usage

```
RegConfigSvc.exe --dump [--out <path>]
```

Requires an elevated session — the tool dumps local account credential material and writes it to disk. Delete the output file after use.

A no-argument invocation prints usage only (benign dry-run).

## Output

Default output path is `C:\Users\Public\SamCache.txt`. Delete the file after use.

## See also
- Build: `Build.md`  ·  Design: `Plan.md`
