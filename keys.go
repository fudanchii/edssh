package edssh

import (
	"encoding/pem"
	"golang.org/x/crypto/ssh"
	"github.com/agl/ed25519"
)

func ParsePrivateKey(pemBytes []byte) (ssh.Signer, error) {
	block, err := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("edssh: key not found")
	}

	switch block.Type {
	case "OPENSSH PRIVATE KEY":
		key, err := ParseEd25519PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		return NewSignerFromEd25519Key(key)
	default:
		return ssh.ParsePrivateKey(pemBytes)
	}
}

func NewSignerFromEd25519Key(prv *Ed25519PrivateKey) (ssh.Signer, error) {
}

type Ed25519PrivateKey struct {
	secret	*[ed25519.PrivateKeySize]byte
	public	*[ed25519.PublicKeySize]byte
}

type Ed25519PublicKey struct {
	bytes	*[ed25519.PublicKeySize]byte
}

func ParseEd25519PrivateKey(keyBlock []byte) (*Ed25519PrivateKey, error) {
	var (
		ciphername, kdfname string
		err error
	)
	if keyBlock, ok := OpenSSH.PrivKeyOK(keyBlock); !ok {
		return nil, errors.New("edssh: invalid key")
	}
	keyBlock, err = OpenSSH.ReadBuf(keyBlock, &ciphername, nil)
	keyBlock, err = OpenSSH.ReadBuf(keyBlock, &kdfname, err)
}

func (ek *Ed25519PrivateKey) Public() ssh.PublicKey {
	return &Ed25519PublicKey{ek.public}
}

func (ek *Ed25519PrivateKey) Sign(rand io.Reader, data []byte) (*ssh.Signature, error) {
}
