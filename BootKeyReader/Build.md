# BootKeyReader — Build

**Toolchain:** C# — .NET Framework `csc.exe` (ships with Windows; supports C# 5, which this source targets).

## Build

From this directory:

```cmd
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /nologo /optimize+ /debug- /target:exe ^
    /out:BootKeyReader.exe BootKeyReader.cs
```

## Options

- `/optimize+ /debug-` — release build, no PDB.
- No external assemblies required (`advapi32.dll` is bound via P/Invoke; `System.Text`/`StringBuilder` come from `mscorlib`).

## Output

- **Artifact:** `BootKeyReader.exe` (single self-contained EXE, AnyCPU).
- **Dry-run verify (benign):** running it with no arguments only reads four registry class names and prints them plus the derived key — no write, no file created.
