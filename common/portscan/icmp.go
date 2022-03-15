package portscan

import (
	"os/exec"
	"runtime"
	"sync"
)

func ping(addr string) bool {
	var cmd *exec.Cmd
	var timeout string = "200"
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("ping", addr, "-n", "1", "-w", timeout)
	case "linux":
		cmd = exec.Command("ping", addr, "-c", "1", "-w", timeout, "-W", timeout)
	case "darwin":
		cmd = exec.Command("ping", addr, "-c", "1", "-W", timeout)
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
