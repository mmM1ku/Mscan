package brute

import (
	"Mscan/common/util"
	"sync"
)

type Brute struct {
	bruteModule string
	bruteThread int
	bruteDic    []Dic
	ftpDic      []Dic
	mssqlDic    []Dic
	mysqlDic    []Dic
	postgresDic []Dic
	smbDic      []Dic
	sshDic      []Dic
	targetChan  chan util.Target
	BruteResult sync.Map
}

func NewBrute(module string, thread int, target chan util.Target) *Brute {
	return &Brute{
		bruteModule: module,
		bruteThread: thread,
		targetChan:  target,
	}
}

func (b *Brute) BrutePool() {
	//init
	b.genDic()
	var wg = &sync.WaitGroup{}
	workChan := make(chan struct{}, 10)
	for target := range b.targetChan {
		target := target
		wg.Add(1)
		workChan <- struct{}{}
		go func() {
			switch target.Service {
			case "ssh":
				b.sshBrute(target.Target)
			case "ftp":
				b.ftpBrute(target.Target)
			case "redis":
				b.redisBrute(target.Target)
			case "mysql":
				b.mysqlBrute(target.Target)
			case "mongodb":
				b.mongoBrute(target.Target)
			case "microsoft-ds":
				b.smbBrute(target.Target)
			case "netbios-ssn":
				b.smbBrute(target.Target)
			case "postgresql":
				b.postgresqlBrute(target.Target)
			case "ms-sql-s":
				b.mssqlBrute(target.Target)
			}
			wg.Done()
			<-workChan
		}()
	}
	wg.Wait()
	close(workChan)
}
