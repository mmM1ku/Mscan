package portscan

import (
	"Mscan/common/brute"
	"Mscan/common/util"
	"fmt"
	"github.com/kpango/glg"
	"github.com/malfunkt/iprange"
	"strconv"
	"strings"
	"sync"
)

//gen ip slice
func (s *Scan) getIpList() error {
	list, err := iprange.ParseList(s.addrs)
	if err != nil {
		return err
	}
	rangeList := list.Expand()
	for _, ip := range rangeList {
		s.ipList = append(s.ipList, ip.String())
	}
	return nil
}

//gen port slice
func (s *Scan) getPortList() error {
	//处理端口为空的情况，为空默认扫全端口
	if s.ports == "" {
		//s.portList = util.MakeRangeSlice(1, 65535)
		s.portList = util.DefaultPorts
		return nil
	}
	commaSplit := strings.Split(s.ports, ",")
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
				s.portList = append(s.portList, i)
			}
		} else {
			if port, err := strconv.Atoi(str); err != nil {
				return fmt.Errorf("端口号错误: %s", str)
			} else {
				s.portList = append(s.portList, port)
			}
		}
	}
	return nil
}

//gen all
func (s *Scan) genScanTarget() {
	if err := s.getIpList(); err != nil {
		glg.Error(err)
	}
	if err := s.getPortList(); err != nil {
		glg.Error(err)
	}
}

//get finger slice
func (s *Scan) getFinger() {
	for _, finger := range util.Fingers {
		if finger.Path == "/" && finger.Method == "GET" {
			s.defaultFinger = append(s.defaultFinger, finger)
		} else {
			s.customFinger = append(s.customFinger, finger)
		}
	}
}

//init brute chan
func (s *Scan) initBruteChan() sync.Map {
	brt := brute.NewBrute(s.bruteModule, s.thread, s.bruteChan)
	//glg.Info("[+]准备弱口令扫描")
	brt.BrutePool()
	glg.Success("[+]弱口令扫描已完成")
	return brt.BruteResult
}

//send brute target
func (s *Scan) sendBruteTarget(service, target string) {
	//通用情况
	if s.bruteModule == service {
		s.bruteChan <- util.Target{Service: service, Target: target}
	}
	//mssql
	if s.bruteModule == "mssql" && service == "ms-sql-s" {
		s.bruteChan <- util.Target{Service: service, Target: target}
	}
	//smb
	if s.bruteModule == "smb" && service == "microsoft-ds" {
		s.bruteChan <- util.Target{Service: service, Target: target}
	}
	//mongo
	if s.bruteModule == "mongo" && service == "mongodb" {
		s.bruteChan <- util.Target{Service: service, Target: target}
	}
	//postgre
	if s.bruteModule == "postgre" && service == "postgresql" {
		s.bruteChan <- util.Target{Service: service, Target: target}
	}
	//all
	if s.bruteModule == "all" && service != "rdp" {
		s.bruteChan <- util.Target{Service: service, Target: target}
	}
}
