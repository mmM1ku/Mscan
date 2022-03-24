package portscan

import (
	"Mscan/common/util"
	"github.com/kpango/glg"
	"net"
	"strconv"
	"sync"
	"time"
)

type Scan struct {
	addrs         string
	ports         string
	ipList        []string
	portList      []int
	hostChan      chan string
	targetChan    chan string
	thread        int
	wg            *sync.WaitGroup
	lock          *sync.Mutex
	workerChan    chan struct{}
	scanResult    []string
	Finish        int64
	total         int64
	respData      chan *util.HttpRes
	defaultFinger []util.WebFinger
	customFinger  []util.WebFinger
	WebResult     util.WebResult
	Result        map[string]*util.DetailResult
	sendChan      chan *ServiceRep
	openChan      chan *ServiceRep
	repChan       chan *ServiceRep
}

func NewScan(add, port string, threat int, group *sync.WaitGroup, mutex *sync.Mutex) *Scan {
	return &Scan{
		addrs:  add,
		ports:  port,
		thread: threat,
		wg:     group,
		lock:   mutex,
		Finish: 0,
	}
}

func (s *Scan) scanWorker() {
	var wg = &sync.WaitGroup{}
	for ip := range s.hostChan {
		ip := ip
		s.lock.Lock()
		s.Result[ip] = &util.DetailResult{}
		s.Result[ip].WebInfo = make(map[string]*util.WebResult)
		s.lock.Unlock()
		for _, port := range s.portList {
			wg.Add(1)
			s.workerChan <- struct{}{}
			port := port
			go func() {
				target := net.JoinHostPort(ip, strconv.Itoa(port))
				var service = &ServiceRep{}
				service.Ip = ip
				service.Port = port
				service.Target = target
				s.sendChan <- service
				<-s.workerChan
				wg.Done()
			}()
		}
	}
	wg.Wait()
	close(s.workerChan)
	close(s.sendChan)
}

func (s *Scan) ScanPool() map[string]*util.DetailResult {
	//init
	s.Result = make(map[string]*util.DetailResult)
	s.hostChan = make(chan string, 10)
	s.repChan = make(chan *ServiceRep, s.thread)
	s.sendChan = make(chan *ServiceRep, s.thread)
	s.openChan = make(chan *ServiceRep, s.thread)
	s.targetChan = make(chan string, s.thread)
	s.respData = make(chan *util.HttpRes, s.thread)
	s.workerChan = make(chan struct{}, s.thread)
	s.genScanTarget()
	s.getFinger()
	s.wg.Add(7)
	go func() {
		s.hostScan()
		s.wg.Done()
	}()
	go func() {
		s.scanWorker()
		s.wg.Done()
	}()
	go func() {
		s.checkWorker()
		s.wg.Done()
	}()
	go func() {
		s.sendWorker()
		s.wg.Done()
	}()
	go func() {
		s.serviceWorker()
		s.wg.Done()
	}()
	go func() {
		s.identifyFinger()
		s.wg.Done()
	}()
	go func() {
		s.checkFinger()
		s.wg.Done()
	}()
	s.wg.Wait()
	for k, v := range s.Result {
		glg.Infof("[+]ip: %s, ports: %v, service: %v, ", k, &v.Ports, &v.Service)
		for url, value := range v.WebInfo {
			glg.Infof("[+]url: %v, webTitle: %v, webStatus: %v, webFinger: %v", url, value.Title, value.StatusCode, util.RemoveRepByLoop(value.Finger))
		}
	}
	return s.Result
}

func tcpConn(target string) (net.Conn, error) {
	conn, err := net.DialTimeout("tcp", target, time.Duration(2)*time.Second)
	if err != nil {
		return nil, err
	}
	err = conn.SetDeadline(time.Now().Add(time.Duration(2) * time.Second))
	if err != nil {
		if conn != nil {
			_ = conn.Close()
		}
		return nil, err
	}
	return conn, nil
}
