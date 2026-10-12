# SamShuffleDump (RegConfigSvc.exe) — Flow

**Entry:** `Main` (C#)  ·  **Artifact summary:** registry-only SAM NTLM dump written to disk; self-elevates to SYSTEM in-process.
*Rows 2–7 are the elevation path (skipped when already SYSTEM); the self-relaunched child or task-run instance performs rows 8–12.*

| # | Behavior (`actor action artifact`) | Artifact [class] → consumed by | Tactic / TID — Technique Name | Context (baseline) |
|---|---|---|---|---|
| 1 | payload checks if running as SYSTEM/admin | — [no-artifact] → #2 | — | runtime identity check, no trace |
| 2 | payload enables SeDebug+SeImpersonate in own token | adjusted token privileges [identity] → #3 | — | SeDebug use baseline: diagnostics/AV tooling |
| 3 | payload opens winlogon process handle | probe-open handle on winlogon [process] → #4 | — | winlogon rarely accessed by userland tools |
| 4 | payload duplicates winlogon token to primary | duplicated primary token [identity] → #5 | — | token duplication normal in services, rare in userland exes |
| 5 | payload relaunches self as SYSTEM via CreateProcessWithTokenW | self-spawned child process [process] → #8 | — | single-run tools normally do not self-spawn as another user |
| 6 | payload creates scheduled task `RegConfig_<8hex>` to rerun self as SYSTEM | task definition in Tasks store [file/registry] → #7 | — | one-off named tasks seen from installers/updaters |
| 7 | payload runs then deletes the task via schtasks.exe | schtasks child processes [process] → #8 | — | create→run→delete in same session |
| 8 | payload enumerates `Users\<RID>` subkeys and reads every V value via Registry API | SAM user V records in process memory [registry] → #11 | — | Users\<RID> value reads confined to account-management tooling |
| 9 | payload reads SYSTEM Lsa bootkey class values in reverse order (Data→GBG→Skew1→JD) | bootkey class values in process memory [registry] → #11 | — | Lsa subkey class attribute reads rare; fixed order assumed by chain detectors |
| 10 | payload reads `SAM\Domains\Account` F value | domain F record in process memory [registry] → #11 | — | read after all user records here; typical SamDumper order is before |
| 11 | payload decrypts NTLM hashes in memory (bootkey, RC4/DES, AES) and writes credential table to `<out>` | plaintext credential file created [file] | — | default `C:\Users\Public\SamCache.txt`; no hive export, reg.exe, or VSS |
| 12 | payload appends status log to `<out>.log` | sibling .log file appended [file] | — | log file created outside log directories |
