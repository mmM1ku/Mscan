package brute

import (
	"Mscan/common/util"
	"github.com/jlaffaye/ftp"
	"github.com/kpango/glg"
	"sync"
	"time"
)

type FTP struct {
	addr        []string
	thread      int
	wg          *sync.WaitGroup
	Result      util.Result
	ResultSlice []util.Result
	lock        *sync.Mutex
	workerChan  chan struct{}
	Finish      int64
	total       int64
	dicchan     *chan string
	userdic     *[]string
	passdic     *[]string
}

func ftpCon(addr, user, pass string) error {
	c, err := ftp.Dial(addr, ftp.DialWithTimeout(3*time.Second))
	if err != nil {
		return err
	}
	err = c.Login(user, pass)
	if err != nil {
		return err
	}
	defer c.Logout()
	return nil
}

func (b *Brute) ftpBrute(target string) {
	var wg = &sync.WaitGroup{}
	workChan := make(chan struct{}, 10)
	for _, dic := range b.bruteDic {
		wg.Add(1)
		workChan <- struct{}{}
		dic := dic
		go func() {
			if err := ftpCon(target, dic.User, dic.Pwd); err == nil {
				glg.Warnf("[!]%s存在ftp弱口令%s/%s", target, dic.User, dic.Pwd)
				b.BruteResult.Store(target, "ftp弱口令:"+dic.User+"/"+dic.Pwd)
			}
			wg.Done()
			<-workChan
		}()
	}
	wg.Wait()
	glg.Infof("[+]%s的ftp爆破已完成", target)
	close(workChan)
}
