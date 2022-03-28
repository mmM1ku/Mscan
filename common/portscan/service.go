package portscan

import (
	"Mscan/common/util"
	"github.com/kpango/glg"
	"strconv"
	"sync"
)

type ServiceRep struct {
	Ip     string
	Port   int
	Target string
	Tag    string
	Rep    []byte
}

func (s *Scan) serviceWorker() {
	var wg = &sync.WaitGroup{}
	var cache sync.Map
	for repStruct := range s.repChan {
		repStruct := repStruct
		wg.Add(2)
		//判断是否http
		go func() {
			if identifyHttp(repStruct.Rep) {
				//去重
				web, _ := cache.Load(repStruct.Target)
				if web == "web" {
					wg.Done()
					return
				} else {
					cache.Store(repStruct.Target, "web")
				}
				glg.Infof("[+]发现web服务：%s:%v", repStruct.Ip, repStruct.Port)
				s.lock.Lock()
				s.Result[repStruct.Ip].Service = append(s.Result[repStruct.Ip].Service, strconv.Itoa(repStruct.Port)+":web")
				s.lock.Unlock()
				s.targetChan <- repStruct.Target
			}
			wg.Done()
		}()

		//主机服务识别
		go func() {
			for _, service := range util.Service {
				if identifyService(service.Pattern, repStruct.Rep) {
					//去重
					srv, _ := cache.Load(repStruct.Target)
					if srv == service.Service {
						wg.Done()
						return
					} else {
						cache.Store(repStruct.Target, service.Service)
					}
					if s.bruteModule != "nb" {
						s.sendBruteTarget(service.Service, repStruct.Target)
					}
					glg.Infof("[+]发现%s服务: %s:%v", service.Service, repStruct.Ip, repStruct.Port)
					s.lock.Lock()
					s.Result[repStruct.Ip].Service = append(s.Result[repStruct.Ip].Service, strconv.Itoa(repStruct.Port)+":"+service.Service)
					s.lock.Unlock()
				}
			}
			s.lock.Lock()
			s.Result[repStruct.Ip].Service = util.RemoveRepByLoop(s.Result[repStruct.Ip].Service)
			s.lock.Unlock()
			wg.Done()
		}()

	}
	glg.Success("[+]指纹匹配已完成")
	wg.Wait()
	close(s.targetChan)
	if s.bruteModule != "nb" {
		close(s.bruteChan)
	}
}
