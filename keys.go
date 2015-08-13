package edssh

import (
	"encoding/pem"
	"github.com/agl/ed25519"
	"golang.org/x/crypto/ssh"
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
	secret *[ed25519.PrivateKeySize]byte
	public *[ed25519.PublicKeySize]byte
}

type Ed25519PublicKey struct {
	bytes *[ed25519.PublicKeySize]byte
}

func ParseEd25519PrivateKey(keyBlock []byte) (*Ed25519PrivateKey, error) {
	var (
		ciphername, kdfname string
		num, l, uint32
		err error
	)
	if keyBlock, ok := OpenSSHKey.FormatOK(keyBlock); !ok {
		return nil, errors.New("edssh: invalid key")
	}
	keyBlock, err = OpenSSHKey.ReadString(keyBlock, &ciphername, nil)
	keyBlock, err = OpenSSHKey.ReadString(keyBlock, &kdfname, err)
	// TODO: support encrypted private key
	if ciphername != "none" && kdfname != "none" {
		return nil, errors.New("edssh: encrypted key is not supported yet")
	}
	// kdfoption (zeroed out since we don't support encryption)
	keyBlock, err = OpenSSHKey.ReadUint32(keyBlock, &num, err)

	// number of keys (only 1)
	keyBlock, err = OpenSSHKey.ReadUint32(keyBlock, &num, err)

	// public key
	var pubKeyBuf []byte
	keyBlock, err = OpenSSHKey.ReadBuf(keyBlock, &pubKeyBuf, err)
}

func (ek *Ed25519PrivateKey) Public() ssh.PublicKey {
	return &Ed25519PublicKey{ek.public}
}

func (ek *Ed25519PrivateKey) Sign(rand io.Reader, data []byte) (*ssh.Signature, error) {
}
