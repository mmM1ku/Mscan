package brute

import (
	"Mscan/common/util"
	"github.com/kpango/glg"
	"golang.org/x/crypto/ssh"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type SSH struct {
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

func NewSSH(addr []string, thread int, group *sync.WaitGroup, mutex *sync.Mutex, userdic, passdic *[]string, dicchan *chan string) *SSH {
	return &SSH{
		addr:    addr,
		thread:  thread,
		wg:      group,
		lock:    mutex,
		total:   int64(len(addr) * len(*userdic) * len(*passdic)),
		Finish:  0,
		userdic: userdic,
		passdic: passdic,
		dicchan: dicchan,
	}
}

func SshCon(addr, user, pass string) (bool, error) {
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
		//Timeout: 10 * time.Second,
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

func (s *SSH) bruteSSHWorker() {
	for str := range *s.dicchan {
		dic := strings.Split(str, "???")
		for _, addr := range s.addr {
			s.wg.Add(1)
			s.workerChan <- struct{}{}
			addr := addr
			go func() {
			LOOP:
				state, err := SshCon(addr, dic[0], dic[1])
				if state {
					glg.Warnf("[+]发现弱口令：%v/%v, %s", dic[0], dic[1], addr)
					s.lock.Lock()
					s.Result.Addr = &addr
					s.Result.User = dic[0]
					s.Result.Pass = dic[1]
					s.ResultSlice = append(s.ResultSlice, s.Result)
					s.lock.Unlock()
				}
				if err != nil && err.Error() == "ssh: handshake failed: EOF" {
					//fmt.Println("重新请求...")
					goto LOOP

				} else if err != nil && strings.Contains(err.Error(), "connection reset by peer") {
					//fmt.Println("重新请求...")
					goto LOOP
				}
				atomic.AddInt64(&s.Finish, 1)
				s.wg.Done()
				<-s.workerChan
			}()
		}
	}
}

func (s *SSH) BruteSSHPool() []util.Result {
	s.workerChan = make(chan struct{}, s.thread)
	s.wg.Add(3)
	go func() {
		MakeDic(s.userdic, s.passdic, s.dicchan)
		s.wg.Done()
	}()
	go func() {
		s.bruteSSHWorker()
		s.wg.Done()
	}()
	go func() {
		for {
			if atomic.LoadInt64(&s.Finish) == s.total {
				util.GetProgress(atomic.LoadInt64(&s.Finish), s.total)
				break
			} else {
				util.GetProgress(atomic.LoadInt64(&s.Finish), s.total)
				time.Sleep(1 * time.Second)
			}
		}
		s.wg.Done()
	}()
	s.wg.Wait()
	return s.ResultSlice
}
