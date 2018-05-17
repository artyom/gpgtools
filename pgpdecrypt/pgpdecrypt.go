// Command pgpdecrypt decrypts encrypted file
package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/artyom/autoflags"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/sync/errgroup"
)

func main() {
	p := &mainArgs{
		Src: "/dev/stdin",
		Dst: "/dev/stdout",
	}
	autoflags.Parse(p)
	if err := run(p); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

type mainArgs struct {
	Keys string `flag:"keyring,path to keyring"`
	Src  string `flag:"src,source file (encrypted to one of the keys in keyring)"`
	Dst  string `flag:"dst,output file (decrypted)"`
	Rec  bool   `flag:"r,recursive (src and dst should be directories then)"`
	Rm   bool   `flag:"rm,remove source files when decrypted in recursive mode"`
}

func run(args *mainArgs) error {
	if args.Src == args.Dst {
		return fmt.Errorf("source and destination cannot be the same")
	}
	kr, err := readKeyRing(args.Keys)
	if err != nil {
		return err
	}
	if !args.Rec {
		return decryptFile(kr, args.Src, args.Dst)
	}
	return decryptRecursive(kr, args.Src, args.Dst, args.Rm)
}

func decryptRecursive(keyring openpgp.KeyRing, src, dst string, rm bool) error {
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
				if rm {
					_ = os.Remove(path)
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
	stat, err := from.Stat()
	if err != nil {
		return err
	}
	var dstFile *os.File
	var writer io.Writer
	switch dest {
	case os.Stdout.Name():
		writer = os.Stdout
	default:
		if dstFile, err = ioutil.TempFile(filepath.Dir(dest), ".pgpdecrypt-"); err != nil {
			return err
		}
		defer dstFile.Close()
		defer os.Remove(dstFile.Name())
		writer = bufio.NewWriterSize(dstFile, 1<<19)
	}
	plaintextReader, err := decrypt(keyring, from)
	if err != nil {
		return err
	}
	if _, err = io.Copy(writer, plaintextReader); err != nil {
		return err
	}
	if f, ok := writer.(*os.File); ok && f.Name() == os.Stdout.Name() {
		return f.Sync()
	}
	if bw, ok := writer.(*bufio.Writer); ok {
		if err := bw.Flush(); err != nil {
			return err
		}
	}
	if err := dstFile.Chmod(stat.Mode()); err != nil {
		return err
	}
	if err := dstFile.Close(); err != nil {
		return err
	}
	return os.Rename(dstFile.Name(), dest)
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
