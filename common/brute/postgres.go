package brute

import (
	"database/sql"
	"fmt"
	"github.com/kpango/glg"
	_ "github.com/lib/pq"
	"sync"
	"time"
)

func postgresCon(addr, user, pass string) error {
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

func postgresDefaultUser(addr string) bool {
	dataSource := fmt.Sprintf("postgres://%v@%v/postgres?sslmode=disable", "postgres", addr)
	db, err := sql.Open("postgres", dataSource)
	if err != nil {
		return false
	} else {
		db.SetConnMaxLifetime(3 * time.Second)
		db.SetConnMaxIdleTime(3 * time.Second)
		db.SetMaxIdleConns(0)
		defer db.Close()
		err = db.Ping()
		if err != nil {
			return false
		}
	}
	return true
}

func (b *Brute) postgresqlBrute(target string) {
	var wg = &sync.WaitGroup{}
	workChan := make(chan struct{}, 10)
	if postgresDefaultUser(target) {
		glg.Warnf("[+]%s存在默认用户postgres无密码登录!", target)
		b.BruteResult.Store(target, "postgres用户无密码登录")
	} else {
		for _, dic := range b.bruteDic {
			wg.Add(1)
			workChan <- struct{}{}
			dic := dic
			go func() {
				if err := postgresCon(target, dic.User, dic.Pwd); err == nil {
					glg.Warnf("[!]%s存在postgresql弱口令%s/%s", target, dic.User, dic.Pwd)
					b.BruteResult.Store(target, "postgresql弱口令:"+dic.User+"/"+dic.Pwd)
				}
				wg.Done()
				<-workChan
			}()
		}
	}
	wg.Wait()
	glg.Infof("[+]%s的postgres爆破已完成", target)
	close(workChan)
}
