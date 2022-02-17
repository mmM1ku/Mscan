package ScanTask

import (
	"Mscan/common/brute"
	"Mscan/common/portscan"
	"Mscan/common/util"
	"fmt"
	"github.com/kpango/glg"
	"github.com/malfunkt/iprange"
	"strconv"
	"strings"
	"sync"
)

type Task struct {
	AddrList        string
	PortList        string
	Thread          int
	Module          string
	ScanIpList      []string
	ScanPortList    []int
	ScanTaskMap     map[string]int
	ScanResult      []string
	scantotal       int64
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

func (t *Task) getIpList() error {
	list, err := iprange.ParseList(t.AddrList)
	if err != nil {
		return err
	}
	rangeList := list.Expand()
	for _, ip := range rangeList {
		t.ScanIpList = append(t.ScanIpList, ip.String())
	}
	return nil
}

func (t *Task) getPortList() error {
	//处理端口为空的情况，为空默认扫全端口
	if t.PortList == "" {
		t.ScanPortList = util.MakeRangeSlice(1, 65535)
	}
	commaSplit := strings.Split(t.PortList, ",")
	for _, str := range commaSplit {
		str = strings.TrimSpace(str)
		if strings.Contains(str, "-") {
			parts := strings.Split(str, "-")
			if len(parts) != 2 {
				return fmt.Errorf("格式错误: %s", str)
			}
			port1, err := strconv.Atoi(parts[0])
			if err != nil {
				return fmt.Errorf("端口号错误: %s", parts[0])
			}
			port2, err := strconv.Atoi(parts[1])
			if err != nil {
				return fmt.Errorf("端口号错误: %s", parts[1])
			}
			if port1 > port2 {
				return fmt.Errorf("端口范围错误: %d-%d", port1, port2)
			}
			for i := port1; i <= port2; i++ {
				t.ScanPortList = append(t.ScanPortList, i)
			}
		} else {
			if port, err := strconv.Atoi(str); err != nil {
				return fmt.Errorf("端口号错误: %s", str)
			} else {
				t.ScanPortList = append(t.ScanPortList, port)
			}
		}
	}
	return nil
}

func (t *Task) getScanTaskList() error {
	t.ScanTaskMap = make(map[string]int)
	if err := t.getIpList(); err != nil {
		return err
	}
	if err := t.getPortList(); err != nil {
		return err
	}
	for _, ip := range t.ScanIpList {
		for _, port := range t.ScanPortList {
			t.ScanTaskMap[ip] = port
		}
	}
	t.scantotal = int64(len(t.ScanTaskMap))
	return nil
}

func (t *Task) Run() {
	//初始化，解析参数
	if err := t.getScanTaskList(); err != nil {
		glg.Error(err)
		return
	}
	//端口扫描
	t.Scan()
	//弱口令爆破
	if t.Module != "" {
		t.Brute()
	}
	//导出结果
	if t.outputMode != "" {
		glg.Log("[+]开始导出结果...")
		util.Output(t.outputMode, t.BruteResult)
		glg.Success("[+]结果已生成")
	}
}

func (t *Task) Scan() {
	glg.Info("[+]开始端口扫描")
	s := portscan.NewScan(t.ScanTaskMap, t.Thread, t.scantotal, t.Wg, t.lock)
	t.ScanResult = s.ScanPool()
	glg.Success("[+]端口扫描已完成")
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
