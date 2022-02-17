package brute

import (
	"Mscan/common/util"
	"database/sql"
	"fmt"
	"github.com/kpango/glg"
	_ "github.com/lib/pq"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type Postgres struct {
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

func NewPostgres(addr []string, thread int, group *sync.WaitGroup, mutex *sync.Mutex, userdic, passdic *[]string, dicchan *chan string) *Postgres {
	return &Postgres{
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

func PostgresCon(addr, user, pass string) error {
	dataSource := fmt.Sprintf("postgres://%v:%v@%v/postgres?sslmode=disable", user, pass, addr)
	//fmt.Println(dataSource)
	db, err := sql.Open("postgres", dataSource)
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

func (p *Postgres) brutePostgresWorker() {
	p.workerChan = make(chan struct{}, p.thread)
	for str := range *p.dicchan {
		dic := strings.Split(str, "???")
		for _, addr := range p.addr {
			p.wg.Add(1)
			p.workerChan <- struct{}{}
			addr := addr
			go func() {
				if err := PostgresCon(addr, dic[0], dic[1]); err == nil {
					glg.Warnf("[+]发现弱口令：%v/%v, %s", dic[0], dic[1], addr)
					p.lock.Lock()
					p.Result.Addr = &addr
					p.Result.User = dic[0]
					p.Result.Pass = dic[1]
					p.ResultSlice = append(p.ResultSlice, p.Result)
					p.lock.Unlock()
				}
				atomic.AddInt64(&p.Finish, 1)
				p.wg.Done()
				<-p.workerChan
			}()
		}
	}
}

func (p *Postgres) BrutePostgresPool() []util.Result {
	p.wg.Add(3)
	go func() {
		MakeDic(p.userdic, p.passdic, p.dicchan)
		p.wg.Done()
	}()
	go func() {
		p.brutePostgresWorker()
		p.wg.Done()
	}()
	go func() {
		for {
			if atomic.LoadInt64(&p.Finish) == p.total {
				util.GetProgress(atomic.LoadInt64(&p.Finish), p.total)
				break
			} else {
				util.GetProgress(atomic.LoadInt64(&p.Finish), p.total)
				time.Sleep(1 * time.Second)
			}
		}
		p.wg.Done()
	}()
	p.wg.Wait()
	return p.ResultSlice
}
