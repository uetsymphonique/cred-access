# DcsyncSharp - Build

**Toolchain:** in-box C# compiler from .NET Framework (`C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe`).

Important: the Roslyn C# compiler shipped with VS 2022 BuildTools **rejects `__arglist(...)` calls that pass `out`/`in` arguments** (`CS8378`) - the NDR stub calls in the source rely on the legacy `__arglist` semantics, so the build must use the in-box compiler, whose C# 5 language level still accepts them (this matches the compile note in the upstream source).

## Build

```cmd
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe -nologo -platform:x64 -out:DcsyncSharp.exe DcsyncSharp.cs
```

## Options

- `-platform:x64` - pins the image to 64-bit; the source carries both x64 and x86 NDR format-string variants and selects by `IntPtr.Size`, so building with `-platform:anycpu` also works (x86 process would take the x86 stubs).
- No other options; no external references beyond the default set.

## Output

- **Artifact:** `DcsyncSharp.exe` (~32 KB)
- **Dev-env verify:** run with no arguments - prints usage and exits 0 (no attack behavior)
