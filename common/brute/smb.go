package brute

import (
	"Mscan/common/util"
	"github.com/hirochachacha/go-smb2"
	"github.com/kpango/glg"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type SMB struct {
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

func NewSMB(addr []string, thread int, group *sync.WaitGroup, mutex *sync.Mutex, userdic, passdic *[]string, dicchan *chan string) *SMB {
	return &SMB{
		addr:    addr,
		thread:  thread,
		wg:      group,
		lock:    mutex,
		Finish:  0,
		total:   int64(len(addr) * len(*userdic) * len(*passdic)),
		userdic: userdic,
		passdic: passdic,
		dicchan: dicchan,
	}
}

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

func (s *SMB) bruteSMBWorker() {
	for str := range *s.dicchan {
		dic := strings.Split(str, "???")
		for _, addr := range s.addr {
			s.wg.Add(1)
			s.workerChan <- struct{}{}
			addr := addr
			go func() {
				if err := smbCon(addr, dic[0], dic[1]); err == nil {
					glg.Warnf("[+]发现弱口令：%v/%v, %s", dic[0], dic[1], addr)
					s.lock.Lock()
					s.Result.Addr = &addr
					s.Result.User = dic[0]
					s.Result.Pass = dic[1]
					s.ResultSlice = append(s.ResultSlice, s.Result)
					s.lock.Unlock()
				}
				atomic.AddInt64(&s.Finish, 1)
				s.wg.Done()
				<-s.workerChan
			}()
		}
	}
}

func (s *SMB) BruteSMBPool() []util.Result {
	s.workerChan = make(chan struct{}, s.thread)
	s.wg.Add(3)
	go func() {
		MakeDic(s.userdic, s.passdic, s.dicchan)
		s.wg.Done()
	}()
	go func() {
		s.bruteSMBWorker()
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
