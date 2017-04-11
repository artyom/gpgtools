// Command pgpdecrypt decrypts encrypted file
package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/artyom/autoflags"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/sync/errgroup"
)

func main() {
	p := struct {
		Keyring string `flag:"keyring,path to keyring"`
		Source  string `flag:"src,source file (encrypted to one of the keys in keyring)"`
		Dest    string `flag:"dst,output file (decrypted)"`
		Rec     bool   `flag:"r,recursive (src and dst should be directories then)"`
	}{
		Source: "/dev/stdin",
		Dest:   "/dev/stdout",
	}
	autoflags.Parse(&p)
	if err := run(p.Keyring, p.Source, p.Dest, p.Rec); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(keyring, src, dest string, recursive bool) error {
	if src == dst {
		return fmt.Errorf("source and destination cannot be the same")
	}
	kr, err := readKeyRing(keyring)
	if err != nil {
		return err
	}
	if !recursive {
		return decryptFile(kr, src, dest)
	}
	return decryptRecursive(kr, src, dest)
}

func decryptRecursive(keyring openpgp.KeyRing, src, dst string) error {
	if err := os.MkdirAll(dst, 0755); err != nil {
		return err
	}
	g, ctx := errgroup.WithContext(context.Background())
	paths := make(chan string)
	g.Go(func() error {
		defer close(paths)
		return filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if !info.Mode().IsRegular() {
				return nil
			}
			select {
			case paths <- path:
			case <-ctx.Done():
				return ctx.Err()
			}
			return nil
		})
	})
	for i := 0; i < runtime.NumCPU(); i++ {
		g.Go(func() error {
			for path := range paths {
				dst := filepath.Join(dst, strings.TrimPrefix(path, src))
				if err := os.MkdirAll(filepath.Dir(dst), 0755); err != nil {
					return err
				}
				if err := decryptFile(keyring, path, dst); err != nil {
					return err
				}
			}
			return nil
		})
	}
	return g.Wait()
}

func decryptFile(keyring openpgp.KeyRing, source, dest string) error {
	from, err := os.Open(source)
	if err != nil {
		return err
	}
	defer from.Close()
	to, err := os.Create(dest)
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
