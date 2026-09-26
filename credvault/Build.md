# credvault — Build

**Toolchain:** Go (stdlib only — `syscall`/`unsafe` for advapi32 + credui, no external modules)

## Build

```text
go build -ldflags="-s -w" -o credvault.exe .
```

Cross-compile from non-Windows:

```text
GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o credvault.exe .
```

## Options

- `-ldflags="-s -w"` — strip symbol table and DWARF (smaller binary, no debug info)
- No CGO; `go.mod` has zero dependencies so no network/module proxy is needed

## Output

- **Artifact:** `credvault.exe` (~1.5 MB stripped)
- **Dev-env verify:** `.\credvault.exe` (no args → usage text, exit 2). Do **not** run `enum`/`read`/`dump` in the dev environment — they touch the local credential vault and are lab-only behavior.
