package brute

import (
	"Mscan/common/util"
	"database/sql"
	"fmt"
	_ "github.com/denisenkom/go-mssqldb"
	"github.com/kpango/glg"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type Mssql struct {
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

func NewMssql(addr []string, thread int, group *sync.WaitGroup, mutex *sync.Mutex, userdic, passdic *[]string, dicchan *chan string) *Mssql {
	return &Mssql{
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

func MssqlCon(addr, user, pass string) error {
	addrstr := strings.Split(addr, ":")
	host := addrstr[0]
	port := addrstr[1]
	dataSource := fmt.Sprintf("server=%s;user id=%s;password=%s;port=%v;encrypt=disable;timeout=%v", host, user, pass, port, 3*time.Second)
	db, err := sql.Open("sqlserver", dataSource)
	if err != nil {
		return err
	} else {
		db.SetConnMaxLifetime(3 * time.Second)
		db.SetConnMaxIdleTime(3 * time.Second)
		db.SetMaxIdleConns(0)
		defer db.Close()
		err = db.Ping()
		if err != nil {
			return err
		}
	}
	return nil
}

func (m *Mssql) bruteMssqlWorker() {
	m.workerChan = make(chan struct{}, m.thread)
	for str := range *m.dicchan {
		dic := strings.Split(str, "???")
		for _, addr := range m.addr {
			m.wg.Add(1)
			m.workerChan <- struct{}{}
			addr := addr
			go func() {
				if err := MssqlCon(addr, dic[0], dic[1]); err == nil {
					glg.Warnf("[+]发现弱口令：%v/%v, %s", dic[0], dic[1], addr)
					m.lock.Lock()
					m.Result.Addr = &addr
					m.Result.User = dic[0]
					m.Result.Pass = dic[1]
					m.ResultSlice = append(m.ResultSlice, m.Result)
					m.lock.Unlock()
				}
				atomic.AddInt64(&m.Finish, 1)
				m.wg.Done()
				<-m.workerChan
			}()
		}
	}
}

func (m *Mssql) BruteMssqlPool() []util.Result {
	m.wg.Add(3)
	go func() {
		MakeDic(m.userdic, m.passdic, m.dicchan)
		m.wg.Done()
	}()
	go func() {
		m.bruteMssqlWorker()
		m.wg.Done()
	}()
	go func() {
		for {
			if atomic.LoadInt64(&m.Finish) == m.total {
				util.GetProgress(atomic.LoadInt64(&m.Finish), m.total)
				break
			} else {
				util.GetProgress(atomic.LoadInt64(&m.Finish), m.total)
				time.Sleep(1 * time.Second)
			}
		}
		m.wg.Done()
	}()
	m.wg.Wait()
	return m.ResultSlice
}
