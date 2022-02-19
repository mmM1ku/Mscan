package portscan

import (
	"Mscan/common/util"
	"fmt"
	"github.com/kpango/glg"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type Scan struct {
	taskList   []string
	thread     int
	wg         *sync.WaitGroup
	lock       *sync.Mutex
	workerChan chan struct{}
	scanResult []string
	Finish     int64
	total      int64
}

func NewScan(taskList []string, threat int, total int64, group *sync.WaitGroup, mutex *sync.Mutex) *Scan {
	return &Scan{
		taskList: taskList,
		thread:   threat,
		wg:       group,
		lock:     mutex,
		Finish:   0,
		total:    total,
	}
}

func (s *Scan) scanWorker() {
	for _, tasks := range s.taskList {
		task := strings.Split(tasks, ":")
		ip := task[0]
		port, _ := strconv.Atoi(task[1])
		s.wg.Add(1)
		s.workerChan <- struct{}{}
		go func() {
			result, err := TcpScan(ip, port)
			if err != nil {
			}
			if result != nil {
				glg.Infof("[+]发现端口：%s:%v/open", ip, port)
				s.lock.Lock()
				s.scanResult = append(s.scanResult, ip+":"+strconv.Itoa(port))
				s.lock.Unlock()
			}
			atomic.AddInt64(&s.Finish, 1)
			<-s.workerChan
			s.wg.Done()
		}()
	}
	close(s.workerChan)
}

func (s *Scan) ScanPool() []string {
	s.workerChan = make(chan struct{}, s.thread)
	s.wg.Add(2)
	go func() {
		s.scanWorker()
		s.wg.Done()
	}()
	go func() {
		for {
			if atomic.LoadInt64(&s.Finish) == s.total {
				util.GetProgress(atomic.LoadInt64(&s.Finish), s.total)
				break
			} else {
				time.Sleep(1 * time.Second)
				util.GetProgress(atomic.LoadInt64(&s.Finish), s.total)
			}
		}
		s.wg.Done()
	}()
	s.wg.Wait()
	return s.scanResult
}

func TcpScan(ip string, port int) (net.Conn, error) {
	conn, err := net.DialTimeout("tcp4", fmt.Sprintf("%v:%v", ip, port), 3*time.Second)
	defer func() {
		if conn != nil {
			err := conn.Close()
			if err != nil {
				return
			}
		}
	}()
	return conn, err
}
