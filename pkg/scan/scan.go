package scan

import (
	"Mscan/configs"
	"Mscan/internal/scan"
	"sync"
)

type Scan struct {
}

func Run(targetList []string) {
	var wg sync.WaitGroup
	taskCH := make(chan struct{}, configs.Thread)
	for _, target := range targetList {
		target := target
		wg.Add(1)
		taskCH <- struct{}{}
		go func() {
			_ = scan.TcpConn(target)
			wg.Done()
			<-taskCH
		}()
	}
	wg.Wait()
}
