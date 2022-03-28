package ScanTask

import (
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
	//导出结果
	if t.outputMode != "" {
		glg.Log("[+]开始导出结果...")
		util.Output(t.outputMode, t.Reuslt)
		glg.Success("[+]结果已生成")
	}
}

func (t *Task) Scan() {
	glg.Info("[+]开始扫描")
	s := portscan.NewScan(t.AddrList, t.PortList, t.Thread, t.Wg, t.lock, t.Module)
	t.Reuslt = s.ScanPool()
	s.BruteResult.Range(func(key, value interface{}) bool {
		target := key.(string)
		vul := value.(string)
		glg.Warnf("[!]%s存在 %s", target, vul)
		return true
	})
	glg.Success("[+]扫描已完成")
}
