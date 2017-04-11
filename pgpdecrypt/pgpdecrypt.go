// Command pgpdecrypt decrypts encrypted file
package main

import (
	"fmt"
	"io"
	"os"

	"github.com/artyom/autoflags"

	"golang.org/x/crypto/openpgp"
)

func main() {
	p := struct {
		Keyring string `flag:"keyring,path to keyring"`
		Source  string `flag:"src,source file (encrypted to one of the keys in keyring)"`
		Dest    string `flag:"dst,output file (decrypted)"`
	}{
		Source: "/dev/stdin",
		Dest:   "/dev/stdout",
	}
	autoflags.Parse(&p)
	if err := run(p.Keyring, p.Source, p.Dest); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(keyring, src, dest string) error {
	kr, err := readKeyRing(keyring)
	if err != nil {
		return err
	}
	return do(kr, src, dest)
}

func do(keyring openpgp.KeyRing, source, dest string) error {
	from, err := os.Open(source)
	if err != nil {
		return err
	}
	defer from.Close()
	to, err := os.Open(dest)
	if err != nil {
		return err
	}
	defer to.Close()
	plaintextReader, err := decrypt(keyring, from)
	if err != nil {
		return err
	}
	if _, err = io.Copy(to, plaintextReader); err != nil {
		return err
	}
	return to.Close()
}

func decrypt(keyring openpgp.KeyRing, encrypted io.Reader) (io.Reader, error) {
	md, err := openpgp.ReadMessage(encrypted, keyring, nil, nil)
	if err != nil {
		return nil, err
	}
	return md.UnverifiedBody, nil
}

func readKeyRing(name string) (openpgp.KeyRing, error) {
	f, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return openpgp.ReadArmoredKeyRing(f)
}
