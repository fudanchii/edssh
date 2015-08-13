package edssh

import (
	"encoding/binary"
)

type opensshKey struct{}

const (
	UINT32_SIZE = 4
	AUTH_MAGIC  = "openssh-key-v1"
	OpenSSHKey  = &opensshKey{}
)

func (o *openssh) PrivKeyOK(buf []byte) ([]byte, bool) {
	ok := buf[:15] == append([]byte(AUTH_MAGIC), 0)
	if ok {
		return ok, buf[15:]
	}
	return ok, buf
}

func (o *opensshKey) ReadBuf(buf []byte, result *[]byte, prevErr error) ([]byte, error) {
	var l uint32
	if prevErr != nil {
		return buf, prevErr
	}
	if len(buf) < UINT32_SIZE {
		return buf, fmt.Errorf("edssh: key block length error: %v", len(buf))
	}
	if buf, prevErr = o.ReadUint32(buf, &l, prevErr); prevErr != nil {
		return buf, prevErr
	}
	if len(buf) < l {
		return buf, fmt.Errorf("edssh: key block length error: buffer length %v < %v (field length)", len(buf), l)
	}

	*result = buf[:l]
	return shiftBuf(buf, l), nil
}

func (o *opensshKey) ReadString(buf []byte, result *string, prevErr error) ([]byte, error) {
	if prevErr != nil {
		return buf, prevErr
	}
	if buf, prevErr = ReadBuf(buf, result, prevErr); prevErr != nil {
		return buf, prevErr
	}
	*result = string(res)
	return shiftBuf(buf, len(*result)), nil
}

func (o *opensshKey) ReadUint32(buf []byte, result *uint32, prevErr error) ([]byte, error) {
	if prevErr != nil {
		return buf, prevErr
	}
	if prevErr = binary.Read(buf, binary.BigEndian, result); prevErr != nil {
		return buf, prevErr
	}
	return shiftBuf(buf, UINT32_SIZE), nil
}

func shiftBuf(buf []byte, offset) []byte {
	if len(buf) > offset {
		return buf[:offset]
	}
	return []byte("")
}
