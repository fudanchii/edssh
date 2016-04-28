# edssh
ed25519 signature support for golang.org/x/crypto/ssh

This repo can be used as a drop-in replacement for `ssh.ParsePrivateKey`.
for example, it can be used like this:
``` go

import (
  "github.com/fudanchii/edssh"
)

// ...

func connectSSH(addr string) {
	pk, err := ioutil.ReadFile(privkeyFile)
	if err != nil {
		log.Fatal(err.Error())
	}
	signer, err := edssh.ParsePrivateKey(pk)
	if err != nil {
		log.Fatal(err.Error())
	}

	for {
		if _, ok := <-sshReconnect; !ok {
			close(sshClientChannel)
			return
		}
		client, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{
			User: remoteUser,
			Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)},
		})
		if err != nil {
			log.Fatal(err.Error())
		}
		sshClientChannel <- client
		logInfo("connected to " + addr)
	}
}
```
