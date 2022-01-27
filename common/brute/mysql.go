package brute

import (
	"Mscan/common/util"
	"database/sql"
	"fmt"
	_ "github.com/go-sql-driver/mysql"
	"github.com/kpango/glg"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type Mysql struct {
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

func mysqlCon(addr, user, pass string) error {
	dataSource := fmt.Sprintf("%v:%v@tcp(%v)/", user, pass, addr)
	db, err := sql.Open("mysql", dataSource)
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

func NewMysql(addr []string, thread int, group *sync.WaitGroup, mutex *sync.Mutex, total int64, userdic, passdic *[]string, dicchan *chan string) *Mysql {
	return &Mysql{
		addr:    addr,
		thread:  thread,
		wg:      group,
		lock:    mutex,
		Finish:  0,
		total:   total,
		userdic: userdic,
		passdic: passdic,
		dicchan: dicchan,
	}
}

func (m *Mysql) bruteMysqlWorker() {
	m.workerChan = make(chan struct{}, m.thread)
	for str := range *m.dicchan {
		dic := strings.Split(str, "???")
		for _, addr := range m.addr {
			m.wg.Add(1)
			m.workerChan <- struct{}{}
			addr := addr
			go func() {
				if err := mysqlCon(addr, dic[0], dic[1]); err == nil {
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

func (m *Mysql) BruteMysqlPool() []util.Result {
	m.wg.Add(3)
	go func() {
		MakeDic(m.userdic, m.passdic, m.dicchan)
		m.wg.Done()
	}()
	go func() {
		m.bruteMysqlWorker()
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
