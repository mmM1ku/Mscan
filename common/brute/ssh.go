package brute

import (
	"github.com/kpango/glg"
	"golang.org/x/crypto/ssh"
	"net"
	"sync"
)

func sshCon(addr, user, pass string) (bool, error) {
	var state bool
	client, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{
		User: user,
		Auth: []ssh.AuthMethod{
			ssh.Password(pass),
		},
		//HostKeyCallback: modSsh.InsecureIgnoreHostKey(),
		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			return nil
		},
		//Timeout: 3 * time.Second,
	})
	if err == nil {
		defer client.Close()
		session, err := client.NewSession()
		errRet := session.Run("echo OK")
		if err == nil && errRet == nil {
			session.Close()
			state = true
		}
	} else {
		return false, err
	}
	return state, nil
}

func (b *Brute) sshBrute(target string) {
	var wg = &sync.WaitGroup{}
	workChan := make(chan struct{}, 10)
	for _, dic := range b.bruteDic {
		wg.Add(1)
		workChan <- struct{}{}
		dic := dic
		go func() {
			res, err := sshCon(target, dic.User, dic.Pwd)
			if err != nil {

			}
			if res {
				glg.Warnf("[!]%s存在ssh弱口令%s/%s", target, dic.User, dic.Pwd)
				b.BruteResult.Store(target, "ssh弱口令:"+dic.User+"/"+dic.Pwd)
			}
			wg.Done()
			<-workChan
		}()
	}
	wg.Wait()
	glg.Infof("[+]%s的ssh爆破已完成", target)
	close(workChan)
}

/*todo ssh 并发重试 */
