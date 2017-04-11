// Command genkey generates PGP key compatible with gpg tools
package main

import (
	"crypto"
	"fmt"
	"io"
	"os"

	"github.com/artyom/autoflags"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
	"golang.org/x/crypto/openpgp/packet"
	"golang.org/x/crypto/openpgp/s2k"
)

func main() {
	p := struct {
		Name  string `flag:"name,full name"`
		Email string `flag:"email,email address"`
	}{}
	autoflags.Parse(&p)
	if p.Email == "" {
		fmt.Fprintln(os.Stderr, "email should be set")
		os.Exit(1)
	}
	if err := genkey(os.Stdout, p.Name, p.Email); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Fprintln(os.Stdout)
}

func genkey(w io.Writer, name, email string) error {
	ent, err := openpgp.NewEntity(name, "", email, nil)
	if err != nil {
		return err
	}

	for _, id := range ent.Identities {
		if id.SelfSignature == nil {
			continue
		}
		id.SelfSignature.PreferredSymmetric = []uint8{
			uint8(packet.CipherAES256),
			uint8(packet.CipherAES192),
			uint8(packet.CipherAES128),
			uint8(packet.CipherCAST5),
		}
		id.SelfSignature.PreferredHash = []uint8{
			hashToHashId(crypto.SHA256),
			hashToHashId(crypto.SHA512),
			hashToHashId(crypto.SHA1),
			hashToHashId(crypto.RIPEMD160),
		}
	}

	wc, err := armor.Encode(w, openpgp.PrivateKeyType, nil)
	if err != nil {
		return err
	}
	if err := ent.SerializePrivate(wc, nil); err != nil {
		return err
	}
	if err := wc.Close(); err != nil {
		return err
	}
	fmt.Fprintln(w)
	wc, err = armor.Encode(w, openpgp.PublicKeyType, nil)
	if err != nil {
		return err
	}
	if err := ent.Serialize(wc); err != nil {
		return err
	}
	return wc.Close()
}

func hashToHashId(h crypto.Hash) uint8 {
	v, ok := s2k.HashToHashId(h)
	if !ok {
		panic("tried to convert unknown hash")
	}
	return v
}
