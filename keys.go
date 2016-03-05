package edssh

import (
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/agl/ed25519"
	"golang.org/x/crypto/ssh"
	"io"
)

func ParsePrivateKey(pemBytes []byte) (ssh.Signer, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("edssh: key not found")
	}

	switch block.Type {
	case "OPENSSH PRIVATE KEY":
		return ParseEd25519PrivateKey(block.Bytes)
	default:
		return ssh.ParsePrivateKey(pemBytes)
	}
}

type Ed25519PrivateKey struct {
	bytes     *[ed25519.PrivateKeySize]byte
	publicKey *Ed25519PublicKey
}

func ParseEd25519PrivateKey(keyBlock []byte) (*Ed25519PrivateKey, error) {
	var (
		ciphername, kdfname string
		num                 uint32
		err                 error
		ok                  bool
	)
	if keyBlock, ok = OpenSSHKey.FormatOK(keyBlock); !ok {
		return nil, errors.New("edssh: invalid key")
	}
	keyBlock, err = OpenSSHKey.ReadString(keyBlock, &ciphername, nil)
	keyBlock, err = OpenSSHKey.ReadString(keyBlock, &kdfname, err)
	// TODO: support encrypted private key
	if ciphername != "none" && kdfname != "none" {
		return nil, errors.New("edssh: encrypted key is not supported yet")
	}

	// kdfoption (zeroed out since we don't support encryption yet)
	keyBlock, err = OpenSSHKey.ReadUint32(keyBlock, &num, err)

	// number of keys (only 1)
	keyBlock, err = OpenSSHKey.ReadUint32(keyBlock, &num, err)

	// public key
	var pubKeyBuf []byte
	keyBlock, err = OpenSSHKey.ReadBuf(keyBlock, &pubKeyBuf, err)

	// private key
	var privKeyBuf []byte
	keyBlock, err = OpenSSHKey.ReadBuf(keyBlock, &privKeyBuf, err)

	var privateKey = &Ed25519PrivateKey{}
	if err = privateKey.parseFromBuf(privKeyBuf, err); err != nil {
		return nil, err
	}

	return privateKey, nil
}

func (ek *Ed25519PrivateKey) parseFromBuf(buf []byte, prevErr error) error {
	if prevErr != nil {
		return prevErr
	}

	var checkint uint32
	buf, prevErr = OpenSSHKey.ReadUint32(buf, &checkint, prevErr)
	buf, prevErr = OpenSSHKey.ReadUint32(buf, &checkint, prevErr)

	var keyType string
	buf, prevErr = OpenSSHKey.ReadString(buf, &keyType, prevErr)

	var pubKey []byte
	buf, prevErr = OpenSSHKey.ReadBuf(buf, &pubKey, prevErr)

	var privKey []byte
	if buf, prevErr = OpenSSHKey.ReadBuf(buf, &privKey, prevErr); prevErr != nil {
		return prevErr
	}

	if len(privKey) != ed25519.PrivateKeySize {
		return errors.New("edssh: invalid private key length")
	}

	edPubKey := new([ed25519.PublicKeySize]byte)
	copy(edPubKey[:], pubKey)
	ek.publicKey = &Ed25519PublicKey{edPubKey}

	ek.bytes = new([ed25519.PrivateKeySize]byte)
	copy(ek.bytes[:], privKey)

	return nil
}

func (ek *Ed25519PrivateKey) PublicKey() ssh.PublicKey {
	return ek.publicKey
}

func (ek *Ed25519PrivateKey) Sign(rand io.Reader, data []byte) (*ssh.Signature, error) {
	signature := ed25519.Sign(ek.bytes, data)
	return &ssh.Signature{
		Format: ek.PublicKey().Type(),
		Blob:   (*signature)[:],
	}, nil
}

type Ed25519PublicKey struct {
	bytes *[ed25519.PublicKeySize]byte
}

func (ek *Ed25519PublicKey) Type() string {
	return "ssh-ed25519"
}

func (ek *Ed25519PublicKey) Marshal() []byte {
	wirekey := struct {
		Name string
		Pub  []byte
	}{
		ek.Type(),
		(*ek.bytes)[:],
	}
	return ssh.Marshal(&wirekey)
}

func (ek *Ed25519PublicKey) Verify(message []byte, signature *ssh.Signature) error {
	if signature.Format != ek.Type() {
		return fmt.Errorf("edssh: signature type %s for key type %s", signature.Format, ek.Type())
	}
	sig := new([ed25519.SignatureSize]byte)
	copy(sig[:], signature.Blob)
	if ok := ed25519.Verify(ek.bytes, message, sig); !ok {
		return errors.New("edssh: invalid signature for given message")
	}
	return nil
}
