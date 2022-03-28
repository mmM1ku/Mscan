package brute

import (
	"database/sql"
	"fmt"
	_ "github.com/go-sql-driver/mysql"
	"github.com/kpango/glg"
	"sync"
	"time"
)

func (b *Brute) mysqlBrute(target string) {
	var wg = &sync.WaitGroup{}
	workChan := make(chan struct{}, 10)
	for _, dic := range b.bruteDic {
		wg.Add(1)
		workChan <- struct{}{}
		dic := dic
		go func() {
			if err := mysqlCon(target, dic.User, dic.Pwd); err == nil {
				glg.Warnf("[!]%s存在mysql弱口令%s/%s", target, dic.User, dic.Pwd)
				b.BruteResult.Store(target, "mysql弱口令:"+dic.User+"/"+dic.Pwd)
			}
			wg.Done()
			<-workChan
		}()
	}
	wg.Wait()
	glg.Infof("[+]%s的mysql爆破已完成", target)
	close(workChan)
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
