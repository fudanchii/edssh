package edssh

import (
	"encoding/binary"
)

const (
	AUTH_MAGIC = "openssh-key-v1"
	OpenSSH = &openssh{}
)

func (o *openssh) PrivKeyOK(buf []byte) ([]byte, bool) {
	ok := buf[:15] == AUTH_MAGIC + "\0"
	if ok {
		return ok, buf[15:]
	}
	return ok, buf
}

func (o *openssh) ReadBuf(buf []byte, result *[]byte, prevErr error) ([]byte, error) {
	var l uint32
	if prevErr != nil {
		return buf, prevErr
	}
	if len(buf) < 4 {
		return buf, fmt.Errorf("edssh: key block length error: %v", len(buf))
	}
	if err := binary.Read(buf, binary.LittleEndian, &l); err != nil {
		return buf, fmt.Errorf("edssh: key block read error: %s", err)
	}
	if len(buf) < l {
		return buf, fmt.Errorf("edssh: key block length error: buffer length %v < %v (field length)", len(buf), l)
	}

	*result = buf[5:l]
	if lOffset := 4 + l + 1; len(buf) > lOffset {
		return buf[lOffset:], nil
	}
	return []byte(""), nil
}

func (o *openssh) ReadString(buf []byte, result *string, prevErr) (string, error) {
	res, err := ReadBuf(buf, result, prevErr)
	*result = string(res)
}
