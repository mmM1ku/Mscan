package portscan

import (
	"github.com/kpango/glg"
	"os/exec"
	"runtime"
	"sync"
)

func ping(addr string) bool {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	//linux、mac ping 超时单位为s,windows为ms
	case "windows":
		cmd = exec.Command("ping", addr, "-n", "1", "-w", "2000")
	case "linux":
		cmd = exec.Command("ping", addr, "-c", "1", "-w", "2", "-W", "2")
	case "darwin":
		cmd = exec.Command("ping", addr, "-c", "1", "-W", "2")
	}
	if cmd == nil {
		return false
	}
	err := cmd.Run()
	if err != nil {
		return false
	}
	return true
}

func (s *Scan) hostScan() {
	var wg = &sync.WaitGroup{}
	workChan := make(chan struct{}, 20)
	for _, ip := range s.ipList {
		ip := ip
		wg.Add(1)
		workChan <- struct{}{}
		go func() {
			glg.Logf("[+]对主机%s进行存活探测", ip)
			if ping(ip) {
				s.hostChan <- ip
			}
			<-workChan
			wg.Done()
		}()
	}
	wg.Wait()
	close(workChan)
	close(s.hostChan)
}
