// Command signrelease signs a packaged Open Trestle release archive offline.
//
// It is a maintainer tool for the release phase, not part of the product. It
// reads an Ed25519 private key from a PKCS#8 PEM file (for example one made
// with `openssl genpkey -algorithm ed25519`), the archive and its SHA-256
// sidecar, and writes the detached signature open-trestle-linux-amd64.pyz.sig
// that `trestle update` verifies against the keys pinned in
// internal/update/release_keys.txt. It never overwrites a file, never prints
// the private key and makes no network request.
//
//	go run ./tools/signrelease sign --key KEY.pem --archive DIR/open-trestle-linux-amd64.pyz --tag vX.Y.Z
//	go run ./tools/signrelease public-key --key KEY.pem
//	go run ./tools/signrelease verify --keys internal/update/release_keys.txt --archive DIR/open-trestle-linux-amd64.pyz
package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/georgejieh/open-trestle/internal/update"
)

const maxKeyFileBytes = 4096

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func usage(w io.Writer) {
	fmt.Fprintln(w, "usage: signrelease sign --key KEY.pem --archive DIR/"+update.ArchiveName+" --tag vX.Y.Z")
	fmt.Fprintln(w, "       signrelease public-key --key KEY.pem")
	fmt.Fprintln(w, "       signrelease verify --keys KEYFILE --archive DIR/"+update.ArchiveName)
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		usage(stderr)
		return 2
	}
	flags := flag.NewFlagSet("signrelease "+args[0], flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	key := flags.String("key", "", "private key")
	keys := flags.String("keys", "", "public key file")
	archive := flags.String("archive", "", "archive")
	tag := flags.String("tag", "", "release tag")
	if err := flags.Parse(args[1:]); err != nil || flags.NArg() != 0 {
		usage(stderr)
		return 2
	}
	var err error
	switch {
	case args[0] == "sign" && *key != "" && *archive != "" && *tag != "" && *keys == "":
		err = sign(*key, *archive, *tag, stdout)
	case args[0] == "public-key" && *key != "" && *archive == "" && *tag == "" && *keys == "":
		err = printPublicKey(*key, stdout)
	case args[0] == "verify" && *keys != "" && *archive != "" && *key == "" && *tag == "":
		err = verify(*keys, *archive, stdout)
	default:
		usage(stderr)
		return 2
	}
	if err != nil {
		fmt.Fprintln(stderr, "signrelease: "+err.Error())
		return 1
	}
	return 0
}

// readPrivateKey reads a PKCS#8 PEM Ed25519 private key from a regular file
// that only its owner can read.
func readPrivateKey(path string) (ed25519.PrivateKey, error) {
	raw, err := readBounded(path, maxKeyFileBytes)
	if err != nil {
		return nil, err
	}
	info, err := os.Lstat(path)
	if err != nil || info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("%s must be readable by its owner only (mode 0600 or 0400)", path)
	}
	block, rest := pem.Decode(raw)
	if block == nil || block.Type != "PRIVATE KEY" || len(rest) != 0 {
		return nil, fmt.Errorf("%s is not one PKCS#8 PEM private key", path)
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%s is not one PKCS#8 PEM private key", path)
	}
	private, ok := parsed.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("%s is not an Ed25519 key", path)
	}
	return private, nil
}

// openRegular opens path only when it is a regular file and not a symbolic
// link, and the file opened is the one inspected.
func openRegular(path string) (*os.File, error) {
	refused := fmt.Errorf("%s is not a regular file (a symbolic link is refused)", path)
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() {
		return nil, refused
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, refused
	}
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) || !opened.Mode().IsRegular() {
		_ = file.Close()
		return nil, refused
	}
	return file, nil
}

// readBounded reads a regular, non-symlinked file of at most limit bytes.
func readBounded(path string, limit int64) ([]byte, error) {
	file, err := openRegular(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || info.Size() > limit {
		return nil, fmt.Errorf("%s is not a regular file of at most %d bytes", path, limit)
	}
	raw, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || int64(len(raw)) > limit {
		return nil, fmt.Errorf("%s cannot be read", path)
	}
	return raw, nil
}

// measured is an archive's digest, size and manifest, read from one open
// file whose identity did not change while it was read.
type measured struct {
	digest  string
	size    int64
	version update.Version
}

func measure(path string) (measured, error) {
	if filepath.Base(path) != update.ArchiveName {
		return measured{}, fmt.Errorf("the archive must be named %s, the release asset name", update.ArchiveName)
	}
	file, err := openRegular(path)
	if err != nil {
		return measured{}, err
	}
	defer file.Close()
	before, err := file.Stat()
	if err != nil || before.Size() <= 0 || before.Size() > update.MaxArchiveBytes {
		return measured{}, fmt.Errorf("%s is not a regular file of at most %d bytes", path, update.MaxArchiveBytes)
	}
	hash := sha256.New()
	size, err := io.Copy(hash, io.LimitReader(file, update.MaxArchiveBytes+1))
	if err != nil || size != before.Size() {
		return measured{}, fmt.Errorf("%s could not be read completely", path)
	}
	_, version, err := update.ReadManifest(file, size)
	if err != nil {
		return measured{}, err
	}
	after, err := file.Stat()
	if err != nil || !os.SameFile(before, after) || after.Size() != before.Size() || !after.ModTime().Equal(before.ModTime()) {
		return measured{}, fmt.Errorf("%s changed while it was read", path)
	}
	result := measured{digest: hex.EncodeToString(hash.Sum(nil)), size: size, version: version}
	sidecar, err := readBounded(path+".sha256", 1024)
	if err != nil {
		return measured{}, err
	}
	if string(sidecar) != result.digest+"  "+update.ArchiveName+"\n" {
		return measured{}, fmt.Errorf("%s.sha256 does not match the archive", path)
	}
	return result, nil
}

func sign(keyPath, archivePath, tag string, stdout io.Writer) error {
	private, err := readPrivateKey(keyPath)
	if err != nil {
		return err
	}
	archive, err := measure(archivePath)
	if err != nil {
		return err
	}
	if tag != "v"+archive.version.String() {
		return fmt.Errorf("the tag %s does not name the archive's version %s (expected v%s)", tag, archive.version, archive.version)
	}
	raw, err := update.Sign(private, update.Statement{
		Archive:       update.ArchiveName,
		ArchiveSHA256: archive.digest,
		ArchiveSize:   archive.size,
		Contract:      update.StatementContract,
		SchemaVersion: 1,
		Tag:           tag,
		Target:        update.Target,
		Version:       archive.version.String(),
	})
	if err != nil {
		return err
	}
	output := archivePath + ".sig"
	// O_EXCL also refuses a symbolic link at the output path.
	file, err := os.OpenFile(output, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o444)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return fmt.Errorf("%s already exists; it is never replaced", output)
		}
		return fmt.Errorf("%s cannot be created", output)
	}
	_, writeErr := file.Write(raw)
	syncErr := file.Sync()
	if err := errors.Join(writeErr, syncErr, file.Close()); err != nil {
		return fmt.Errorf("%s could not be written completely; remove it and sign again", output)
	}
	public := private.Public().(ed25519.PublicKey)
	ring, err := update.ParseKeyRing([]byte("ed25519 " + base64.StdEncoding.EncodeToString(public)))
	if err != nil {
		return err
	}
	if _, _, err := ring.Verify(raw); err != nil {
		return fmt.Errorf("the new signature does not verify: %w", err)
	}
	fmt.Fprintf(stdout, "signed %s %s (%s, %d bytes, sha256 %s) with key %s: %s\n", update.ArchiveName, archive.version, tag, archive.size, archive.digest, ring[0].ID, output)
	return nil
}

func printPublicKey(keyPath string, stdout io.Writer) error {
	private, err := readPrivateKey(keyPath)
	if err != nil {
		return err
	}
	line := "ed25519 " + base64.StdEncoding.EncodeToString(private.Public().(ed25519.PublicKey))
	ring, err := update.ParseKeyRing([]byte(line))
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout, "# key %s\n%s\n", ring[0].ID, line)
	return nil
}

func verify(keysPath, archivePath string, stdout io.Writer) error {
	keyFile, err := readBounded(keysPath, 64<<10)
	if err != nil {
		return err
	}
	ring, err := update.ParseKeyRing(keyFile)
	if err != nil {
		return err
	}
	raw, err := readBounded(archivePath+".sig", update.MaxSignatureBytes)
	if err != nil {
		return err
	}
	statement, key, err := ring.Verify(raw)
	if err != nil {
		return err
	}
	archive, err := measure(archivePath)
	if err != nil {
		return err
	}
	if statement.ArchiveSHA256 != archive.digest || statement.ArchiveSize != archive.size || statement.Version != archive.version.String() {
		return errors.New("the signature does not describe this archive")
	}
	fmt.Fprintf(stdout, "verified %s %s (%s) signed with key %s\n", update.ArchiveName, statement.Version, statement.Tag, key.ID)
	return nil
}
