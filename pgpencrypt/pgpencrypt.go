// Command pgpencrypt encrypts/signs given file
package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/artyom/autoflags"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
	"golang.org/x/crypto/openpgp/packet"
)

func main() {
	args := struct {
		Ours   string `flag:"ours,our pgp ascii-armored key"`
		Theirs string `flag:"theirs,theirs pgp ascii-armored public key"`
		Src    string `flag:"src,file to encrypt"`
		Dst    string `flag:"dst,file to write encrypted content to"`
	}{
		Src: "/dev/stdin",
		Dst: "/dev/stdout",
	}
	autoflags.Parse(&args)
	if args.Ours == "" || args.Theirs == "" || args.Src == "" || args.Dst == "" {
		flag.Usage()
		os.Exit(1)
	}
	if err := run(args.Ours, args.Theirs, args.Src, args.Dst); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(ours, theirs, file, saveto string) error {
	f, err := os.Open(file)
	if err != nil {
		return err
	}
	defer f.Close()
	signer, err := readEntity(ours)
	if err != nil {
		return err
	}
	recipient, err := readEntity(theirs)
	if err != nil {
		return err
	}
	dst, err := os.Create(saveto)
	if err != nil {
		return err
	}
	defer dst.Close()
	return encrypt([]*openpgp.Entity{recipient}, signer, f, dst)
}

func encrypt(recip []*openpgp.Entity, signer *openpgp.Entity, r io.Reader, w io.Writer) error {
	wc, err := openpgp.Encrypt(w, recip, signer, &openpgp.FileHints{IsBinary: true}, nil)
	if err != nil {
		return err
	}
	if _, err := io.Copy(wc, r); err != nil {
		return err
	}
	return wc.Close()
}

func readEntity(name string) (*openpgp.Entity, error) {
	f, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	block, err := armor.Decode(f)
	if err != nil {
		return nil, err
	}
	return openpgp.ReadEntity(packet.NewReader(block.Body))
}
