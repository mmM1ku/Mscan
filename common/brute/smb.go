package brute

import (
	"github.com/hirochachacha/go-smb2"
	"github.com/kpango/glg"
	"net"
	"sync"
)

func smbCon(addr, user, pass string) error {
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return err
	}
	defer conn.Close()

	d := smb2.Dialer{
		Initiator: &smb2.NTLMInitiator{
			User:     user,
			Password: pass,
		},
	}
	s, err := d.Dial(conn)
	if err != nil {
		return err
	}
	defer s.Logoff()
	return nil
}

func smbUnauth(addr string) bool {
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return false
	}
	defer conn.Close()

	d := smb2.Dialer{
		Initiator: &smb2.NTLMInitiator{
			User: "guest",
		},
	}
	s, err := d.Dial(conn)
	if err != nil {
		return false
	}
	defer s.Logoff()
	return true
}

func (b *Brute) smbBrute(target string) {
	var wg = &sync.WaitGroup{}
	workChan := make(chan struct{}, 10)
	if smbUnauth(target) {
		glg.Warnf("[+]%s存在smb匿名用户guest登录", target)
		b.BruteResult.Store(target, "smb匿名用户guest登录")
	} else {
		for _, dic := range b.smbDic {
			wg.Add(1)
			workChan <- struct{}{}
			dic := dic
			go func() {
				if err := smbCon(target, dic.User, dic.Pwd); err == nil {
					glg.Warnf("[+]%s存在smb弱口令%s/%s", target, dic.User, dic.Pwd)
					b.BruteResult.Store(target, "smb弱口令:"+dic.User+"/"+dic.Pwd)
				}
				wg.Done()
				<-workChan
			}()
		}
	}
	wg.Wait()
	glg.Infof("%s的smb爆破已完成", target)
	close(workChan)
}
