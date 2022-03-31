package brute

import (
	"database/sql"
	"fmt"
	_ "github.com/denisenkom/go-mssqldb"
	"github.com/kpango/glg"
	"strings"
	"sync"
	"time"
)

func mssqlCon(addr, user, pass string) error {
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

func (b *Brute) mssqlBrute(target string) {
	var wg = &sync.WaitGroup{}
	workChan := make(chan struct{}, 10)
	for _, dic := range b.mssqlDic {
		wg.Add(1)
		workChan <- struct{}{}
		dic := dic
		go func() {
			if err := mssqlCon(target, dic.User, dic.Pwd); err == nil {
				glg.Warnf("[!]%s存在mssql弱口令%s/%s", target, dic.User, dic.Pwd)
				b.BruteResult.Store(target, "mssql弱口令:"+dic.User+"/"+dic.Pwd)
			}
			wg.Done()
			<-workChan
		}()
	}
	wg.Wait()
	glg.Infof("[+]%s的mssql爆破已完成", target)
	close(workChan)
}
