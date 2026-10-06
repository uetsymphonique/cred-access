# SamShuffleDump — Design & Implementation

**Purpose:** a standalone C# utility that obtains local SAM NTLM hashes by reading the registry directly, with a deliberately controlled, unconventional read schedule.

---

## 1. Purpose

- Decrypt local SAM account NTLM hashes using registry reads alone — no `reg.exe`, no `reg save`, no hive-file copy, no VSS snapshots.
- Preserve a controlled, unusual read schedule as a deliberate design property: the tool performs the same registry access any SAM dumper requires, but in an order the operator controls rather than the conventional fixed sequence.

## 2. Design goals

- **Functional:** dump local SAM hashes from the registry alone, on a standard Windows host, with no dependencies beyond .NET Framework 4.8.
- **Design quirk:** preserve a controlled, unusual read schedule — user records first, account data last; bootkey classes in reverse order — as an intentional, configurable property of the access pattern.

## 3. Components

1. **SYSTEM self-elevation**
   - Enable `SeDebugPrivilege`; open `winlogon.exe`; `DuplicateTokenEx` (primary token); `CreateProcessWithTokenW` relaunching self with `--dump`.
   - **Fallback:** relaunch via `schtasks /create /RU SYSTEM` (note: this adds T1569.002 behavior).
2. **Bootkey read (SYSTEM hive)** — read `Control\Lsa` class values `Data`, `GBG`, `Skew1`, `JD` — in that order (reverse of the conventional order); assemble the bootkey from the class names plus the standard permutation.
3. **SAM read (SAM hive)** — open `HKLM\SAM\SAM\Domains\Account\Users`; enumerate subkey names (RIDs); for each RID read value `V`. Then read `Domains\Account` `F` **last**, completing the user-records-first schedule.
4. **Hash decryption** — port the impacket/creddump routine: assemble the bootkey (hex class values + permutation); derive the hashed bootkey from `Domains\Account` `F` (`Key0` revision `0x01` = RC4/DES old-style; `0x02` = AES new-style); derive per-RID Key1/Key2 and decrypt the NT hash.
5. **Output** — write results to the path passed via `--out` (default `C:\Users\Public\SamCache.txt`). Delete the output file after use.
6. **CLI** — `RegConfigSvc.exe [--dump] [--out <path>]`; no args → usage only (benign dry-run).

## 4. CLI & environment requirements

- **CLI:** `RegConfigSvc.exe --dump [--out <path>]`. No-argument invocation prints usage and performs no reads.
- **OS / arch:** Windows x64, .NET Framework 4.8 present.
- **Privilege:** launched from an elevated Administrator session; the tool self-elevates to **SYSTEM** (required to read `SAM\SAM`).

## 5. Known limitations

- Hashed bootkey stored in `$ATTRIBUTE_LIST` form is not resolved (values must be resident in `F`).
- Tested on Windows Server 2022 / Windows 10+ with .NET Framework 4.8 present; RT (AES) hashed bootkeys are the expected format on modern builds, RC4/DES legacy is handled for older revision `0x01` domains.

## 6. Build & verify

- **Build:** see `Build.md` (`csc.exe`, single file, no external assemblies).
- **Dev dry-run:** run the binary with no arguments → usage output only; no registry reads occur.
- **Correctness check:** on an authorized test target as SYSTEM, run `--dump` and compare a decrypted hash against the known-good account NTLM for that account (e.g. compute `hashlib.new('md4', pw.encode('utf-16le')).hexdigest()` for a password you control). A match confirms the bootkey assembly and decryption port are correct.

## 7. Risks & mitigations

| # | Risk | Level | Mitigation |
|---|---|---|---|
| 1 | `CreateProcessWithTokenW` SYSTEM self-spawn fails (session quirks) | Med | `schtasks` fallback; both paths documented |
| 2 | RC4/DES or AES decryption port incorrect | Med | Independent known-good hash verification (§6) before operational use |
| 3 | Read schedule accidentally altered by future edits | Med | Ordering constraints enforced in code and documented (§8) |
| 4 | Output file leaks account hashes | Low | Delete after use; runtime-generated only, no hardcoded secrets |
| 5 | Token manipulation exceeds pure T1003.002 (adds T1134) | Low | Documented as an ATT&CK technique — the self-elevation path is inherent to the design |

## 8. Order constraints that must be preserved (design integrity)

The unconventional schedule is a deliberate, configurable property of the tool. Any modification must keep:

- bootkey class reads strictly Data → GBG → Skew1 → JD (bootkey *assembly* still combines JD + Skew1 + GBG + Data);
- all `Users\<RID>` reads strictly before the single `Domains\Account` `F` read;
- no `reg.exe` invocation, no `reg save`, no hive file copy, no VSS — all access via the Registry API.
