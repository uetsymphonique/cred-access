# DcsyncSharp

**Purpose:** Single-account DCSync client over raw DRSuAPI RPC - replicates one directory account's password data from a domain controller and prints the NTLM hash to the console.

## Overview

Pure-C# implementation of the DCSync technique with no external protocol library: the binary drives `rpcrt4.dll` directly (`RpcStringBindingCompose`, `RpcBindingSetAuthInfoEx` with PKT_PRIVACY + Negotiate, hand-built MIDL format strings driven through `NdrClientCall2`). It binds to the drsuapi interface (GUID `e3514235-4b06-11d1-ab04-00c04fc2dcd2`), resolves the target account to an object GUID via `DRSCrackNames`, issues a single-object `DRSGetNCChanges` request, and decrypts `unicodePwd` with the SID-keyed DES scheme into the NTLM hash. The decryption AES/RC4 session key comes from the RPC security callback (`I_RpcBindingInqSecurityContext` -> `QueryContextAttributes`).

Provenance: adapted from [`3gstudent/Homework-of-C-Sharp` SharpDCSync.cs](https://github.com/3gstudent/Homework-of-C-Sharp/blob/master/SharpDCSync.cs) (itself based on `vletoux/MakeMeEnterpriseAdmin`), upstream source retained alongside as `SharpDCSync.cs`. Changes from upstream: single-account scope (no LDAP enumeration of all users), `IMPERSONATE` output format, no `System.DirectoryServices` dependency.

Note: DCSync produces no file artifact on either host - output lives only on the console, so record the console output itself.

## Target context

- **Host / OS / arch:** Windows x64, .NET Framework 4.x standalone executable
- **Privilege required:** any account with DS-Replication-Get-Changes(-All) on the domain (Domain Admin or a domain controller by default); no elevated local privilege needed
- **Network:** RPC tcp/135 (endpoint mapper) + a dynamic RPC port inbound on the DC from the source host

## Usage

```cmd
DcsyncSharp.exe <dc fqdn> <domain> [username]
```

- `<dc fqdn>` - FQDN of the domain controller (e.g. `dc01.test.local`)
- `<domain>` - DNS domain name (e.g. `test.local`)
- `[username]` - samAccountName to replicate; defaults to `krbtgt`

Output lines:

```text
IMPERSONATE:<username>:<ntlm hex>
```

## See also

- Build: `Build.md`
