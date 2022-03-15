package ScanTask

import (
	"Mscan/common/brute"
	"Mscan/common/portscan"
	"Mscan/common/util"
	"github.com/kpango/glg"
	"sync"
)

type Task struct {
	AddrList        string
	PortList        string
	Thread          int
	Module          string
	ScanResult      []string
	Wg              *sync.WaitGroup
	UserDicList     []string
	PassDicList     []string
	userpath        string
	passpath        string
	dicChan         chan string
	bruteThread     int
	lock            *sync.Mutex
	BruteResult     []util.Result
	bruteFinishChan chan int64
	Reuslt          map[string]*util.DetailResult
	outputMode      string
}

// NewTask 创建新扫描结构体对象，初始化
func NewTask(addr, port string, thread int, module string, bruteThread int, userpath string, passpath string, output string) *Task {
	return &Task{
		AddrList:    addr,
		PortList:    port,
		Thread:      thread,
		Module:      module,
		Wg:          &sync.WaitGroup{},
		bruteThread: bruteThread,
		lock:        &sync.Mutex{},
		userpath:    userpath,
		passpath:    passpath,
		outputMode:  output,
	}

}

func (t *Task) Run() {
	//端口扫描
	t.Scan()
	if t.Module != "" {
		t.Brute()
	}
	//导出结果
	if t.outputMode != "" {
		glg.Log("[+]开始导出结果...")
		util.Output(t.outputMode, t.Reuslt)
		glg.Success("[+]结果已生成")
	}
}

func (t *Task) Scan() {
	glg.Info("[+]开始扫描")
	s := portscan.NewScan(t.AddrList, t.PortList, t.Thread, t.Wg, t.lock)
	t.Reuslt = s.ScanPool()
	glg.Success("[+]扫描已完成")
}

func (t *Task) Brute() {
	glg.Info("[+]开始弱口令扫描...")
	t.bruteFinishChan = make(chan int64, t.bruteThread)
	t.dicChan = make(chan string, t.bruteThread)
	t.UserDicList, t.PassDicList = brute.GetDic(t.userpath, t.passpath)
	switch t.Module {
	case "ssh":
		s := brute.NewSSH(t.ScanResult, t.bruteThread, t.Wg, t.lock, &t.UserDicList, &t.PassDicList, &t.dicChan)
		t.BruteResult = s.BruteSSHPool()
	case "redis":
		r := brute.NewRedis(t.ScanResult, t.bruteThread, t.Wg, t.lock)
		t.BruteResult = r.BruteRedisPool()
	case "mysql":
		m := brute.NewMysql(t.ScanResult, t.bruteThread, t.Wg, t.lock, &t.UserDicList, &t.PassDicList, &t.dicChan)
		t.BruteResult = m.BruteMysqlPool()
	case "smb":
		s := brute.NewSMB(t.ScanResult, t.bruteThread, t.Wg, t.lock, &t.UserDicList, &t.PassDicList, &t.dicChan)
		t.BruteResult = s.BruteSMBPool()
	case "ftp":
		f := brute.NewFTP(t.ScanResult, t.bruteThread, t.Wg, t.lock, &t.UserDicList, &t.PassDicList, &t.dicChan)
		t.BruteResult = f.BruteFtpPool()
	case "postgres":
		p := brute.NewPostgres(t.ScanResult, t.bruteThread, t.Wg, t.lock, &t.UserDicList, &t.PassDicList, &t.dicChan)
		t.BruteResult = p.BrutePostgresPool()
	case "mongo":
		m := brute.NewMongo(t.ScanResult, t.bruteThread, t.Wg, t.lock, &t.UserDicList, &t.PassDicList, &t.dicChan)
		t.BruteResult = m.BruteMongoPool()
	case "mssql":
		m := brute.NewMssql(t.ScanResult, t.bruteThread, t.Wg, t.lock, &t.UserDicList, &t.PassDicList, &t.dicChan)
		t.BruteResult = m.BruteMssqlPool()

	}
	glg.Success("[+]弱口令扫描已完成")
}
