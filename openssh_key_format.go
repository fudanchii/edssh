package edssh

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

type opensshKey struct{}

const (
	UINT32_SIZE = 4
	AUTH_MAGIC  = "openssh-key-v1"
)

var (
	OpenSSHKey = &opensshKey{}
)

func (o *opensshKey) FormatOK(buf []byte) ([]byte, bool) {
	ok := string(buf[:15]) == string(append([]byte(AUTH_MAGIC), 0))
	if ok {
		return buf[15:], ok
	}
	return buf, ok
}

func (o *opensshKey) ReadBuf(buf []byte, result *[]byte, prevErr error) ([]byte, error) {
	var l uint32
	if prevErr != nil {
		return buf, prevErr
	}
	if len(buf) < UINT32_SIZE {
		return buf, fmt.Errorf("edssh: key block length error: %v", len(buf))
	}
	fmt.Println(fmt.Errorf("%X", buf[:4]))
	if buf, prevErr = o.ReadUint32(buf, &l, prevErr); prevErr != nil {
		return buf, prevErr
	}
	if uint32(len(buf)) < l {
		return buf, fmt.Errorf("edssh: buffer length %v < %v (field length)", len(buf), l)
	}

	*result = buf[:l]
	return shiftBuf(buf, int(l)), nil
}

func (o *opensshKey) ReadString(buf []byte, result *string, prevErr error) ([]byte, error) {
	if prevErr != nil {
		return buf, prevErr
	}

	var res []byte
	if buf, prevErr = o.ReadBuf(buf, &res, prevErr); prevErr != nil {
		return buf, prevErr
	}
	*result = string(res)
	return buf, nil
}

func (o *opensshKey) ReadUint32(buf []byte, result *uint32, prevErr error) ([]byte, error) {
	if prevErr != nil {
		return buf, prevErr
	}
	if prevErr = binary.Read(bytes.NewReader(buf), binary.BigEndian, result); prevErr != nil {
		return buf, prevErr
	}
	return shiftBuf(buf, UINT32_SIZE), nil
}

func shiftBuf(buf []byte, offset int) []byte {
	if len(buf) > offset {
		return buf[offset:]
	}
	return []byte("")
}
