package brute

import (
	"Mscan/common/util"
	"github.com/jlaffaye/ftp"
	"github.com/kpango/glg"
	"strings"
	"sync"
	"sync/atomic"
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

func NewFTP(addr []string, thread int, group *sync.WaitGroup, mutex *sync.Mutex, userdic, passdic *[]string, dicchan *chan string) *FTP {
	return &FTP{
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

func (f *FTP) bruteFtpWorker() {
	for str := range *f.dicchan {
		dic := strings.Split(str, "???")
		for _, addr := range f.addr {
			f.wg.Add(1)
			f.workerChan <- struct{}{}
			addr := addr
			go func() {
				if err := ftpCon(addr, dic[0], dic[1]); err == nil {
					glg.Warnf("[+]发现弱口令：%v/%v, %s", dic[0], dic[1], addr)
					f.lock.Lock()
					f.Result.Addr = &addr
					f.Result.User = dic[0]
					f.Result.Pass = dic[1]
					f.ResultSlice = append(f.ResultSlice, f.Result)
					f.lock.Unlock()
				}
				atomic.AddInt64(&f.Finish, 1)
				f.wg.Done()
				<-f.workerChan
			}()
		}
	}
}

func (f *FTP) BruteFtpPool() []util.Result {
	f.workerChan = make(chan struct{}, f.thread)
	f.wg.Add(3)
	go func() {
		MakeDic(f.userdic, f.passdic, f.dicchan)
		f.wg.Done()
	}()
	go func() {
		f.bruteFtpWorker()
		f.wg.Done()
	}()
	go func() {
		for {
			if atomic.LoadInt64(&f.Finish) == f.total {
				util.GetProgress(atomic.LoadInt64(&f.Finish), f.total)
				break
			} else {
				util.GetProgress(atomic.LoadInt64(&f.Finish), f.total)
				time.Sleep(1 * time.Second)
			}
		}
		f.wg.Done()
	}()
	f.wg.Wait()
	return f.ResultSlice
}
