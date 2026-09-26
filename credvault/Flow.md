# credvault — Flow

**Entry:** `main` → `run` subcommand dispatch (`enum` / `read` / `dump`)  ·  **Artifact summary:** reads Windows Credential Manager in-session and emits plaintext user/secret pairs to console or `-o` file

| # | Behavior (`actor action artifact`) | Artifact [class] → consumed by | Tactic / TID — Technique Name | Context (baseline) |
|---|---|---|---|---|
| 1a | credvault enumerates stored credentials via advapi32 CredEnumerateW (optional filter arg) | vault entry list with targets/users/persistence [identity] → #2 | Credential Access / T1555.004 — Credentials from Password Stores: Windows Credential Manager | same API pair as `cmdkey /list`, but from a non-system binary |
| 1b | credvault enumerates stored credentials via advapi32 CredEnumerateW (optional filter arg) | vault entry list with targets/users/persistence [identity] → #2 | Execution / T1106 — Native API | same API pair as `cmdkey /list`, but from a non-system binary |
| 2a | credvault reads one generic credential's decrypted blob in-session via advapi32 CredReadW and decodes it (plain UTF-16 primary, credui CredUnPackAuthenticationBufferW fallback) | plaintext secret held in own process [memory] → #3 | Credential Access / T1555.004 — Credentials from Password Stores: Windows Credential Manager | identical in-session requirement as CredentialManager module; no offline DPAPI step |
| 2b | credvault reads one generic credential's decrypted blob in-session via advapi32 CredReadW and decodes it (plain UTF-16 primary, credui CredUnPackAuthenticationBufferW fallback) | plaintext secret held in own process [memory] → #3 | Execution / T1106 — Native API | identical in-session requirement as CredentialManager module; no offline DPAPI step |
| 3 | credvault emits username and plaintext secret to stdout, or writes them to `-o` output file | console text [no-artifact] (file [file] with -o) | Credential Access / T1555.004 — Credentials from Password Stores: Windows Credential Manager | replaces `Get-StoredCredential` + `GetNetworkCredential().Password` display step |
