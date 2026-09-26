# credvault

**Purpose:** Windows Credential Manager enumeration + secret recovery in one Go binary — replaces the `cmdkey /list` + CredentialManager-module `Get-StoredCredential` pattern pair of Phase 2 Step 1 with a custom, in-session tool (T1555.004).

## Overview

Both well-known patterns are thin wrappers around `advapi32`: `cmdkey /list` is `CredEnumerateW`, and the CredentialManager PowerShell module's `Get-StoredCredential` is `CredReadW` + blob decode. credvault calls both APIs directly — no PowerShell spawn, no AMSI exposure, no NuGet/module install on the victim. Blobs are decoded as plain UTF-16 (the format `CredWrite`/`cmdkey` store), with a `credui!CredUnPackAuthenticationBufferW` fallback for CredUI-packed blobs.

Run **in-session as the user who owns the vault** (same constraint as the PowerShell module): `CredRead` returns the decrypted blob only in the calling user's context — no offline DPAPI needed.

## Target context

- **Host / OS / arch:** Windows, amd64 (WS01 in Phase 2)
- **Privilege required:** the owning user's session (labuser), medium integrity

## Usage

```text
credvault [-o <output-file>] <subcommand> [args...]

credvault enum  [filter]     list stored credentials (cmdkey /list equivalent)
credvault read  <target>     print user/secret for one credential target
credvault dump [filter]      enumerate + read every generic credential
```

☣️ In-session (TONESHELL as labuser), replace the Phase 2 Step 1 pair:

```text
credvault enum
credvault dump Microsoft:SSMS
```

`-o` redirects stdout to a file for `sp_OA WScript.Shell.Run` / cmd.exe-free reading via `sp_OA ADODB.Stream`, mirroring go-thehash.

## See also

- Build: `Build.md` · Code flow & ATT&CK mapping: `Flow.md`
