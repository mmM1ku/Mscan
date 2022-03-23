package portscan

import (
	"Mscan/common/util"
	"github.com/kpango/glg"
	"strconv"
)

type ServiceRep struct {
	Ip     string
	Port   int
	Target string
	Rep    [][]byte
}

func (s *Scan) serviceWorker() {
	for repStruct := range s.repChan {
		if len(repStruct.Rep) > 0 {
			glg.Infof("[+]发现端口：%s/open", repStruct.Target)
			s.lock.Lock()
			s.Result[repStruct.Ip].Ports = append(s.Result[repStruct.Ip].Ports, repStruct.Port)
			s.lock.Unlock()
		}
		//判断是否http
		if identifyHttp(repStruct.Rep) {
			glg.Infof("[+]发现web服务：%s:%v", repStruct.Ip, repStruct.Port)
			s.lock.Lock()
			s.Result[repStruct.Ip].Service = append(s.Result[repStruct.Ip].Service, strconv.Itoa(repStruct.Port)+":web")
			s.lock.Unlock()
			s.targetChan <- repStruct.Target
		}
		//主机服务识别
		for _, service := range util.Service {
			if identifyService(service.Pattern, repStruct.Rep) {
				glg.Infof("[+]发现%s服务: %s:%v", service.Service, repStruct.Ip, repStruct.Port)
				s.lock.Lock()
				s.Result[repStruct.Ip].Service = append(s.Result[repStruct.Ip].Service, strconv.Itoa(repStruct.Port)+":"+service.Service)
				s.lock.Unlock()
			}
		}
		s.lock.Lock()
		s.Result[repStruct.Ip].Service = util.RemoveRepByLoop(s.Result[repStruct.Ip].Service)
		s.lock.Unlock()
	}
	close(s.targetChan)
}
