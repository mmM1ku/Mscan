package portscan

import (
	"Mscan/common/util"
	"bytes"
	"github.com/kpango/glg"
	"sync"
	"time"
)

func defaultSend(target string) ([]byte, error) {
	conn, err := tcpConn(target)
	if err != nil {
		return nil, err
	}
	_ = conn.SetDeadline(time.Now().Add(time.Duration(2) * time.Second))
	rep := make([]byte, 256)
	_, err = conn.Read(rep)
	var buf [256]byte
	if err == nil && bytes.Equal(rep[:], buf[:]) == false {
		if conn != nil {
			_ = conn.Close()
		}
		return rep, nil
	}

	conn, err = tcpConn(target)
	if err != nil {
		return nil, err
	}
	_ = conn.SetDeadline(time.Now().Add(time.Duration(2) * time.Second))
	msg := "GET / HTTP/1.1\r\n\r\n"
	_, err = conn.Write([]byte(msg))
	if err != nil {
		return nil, err
	}
	rep = make([]byte, 256)
	_, _ = conn.Read(rep)
	if conn != nil {
		_ = conn.Close()
	}
	return rep, nil
}

func commonSend(target string) ([]byte, error) {
	conn, err := tcpConn(target)
	if err != nil {
		return nil, err
	}
	msg := "\r\n\r\n"
	_, err = conn.Write([]byte(msg))
	if err != nil {
		return nil, err
	}
	_ = conn.SetDeadline(time.Now().Add(time.Duration(3) * time.Second))
	rep := make([]byte, 256)
	_, _ = conn.Read(rep)
	if conn != nil {
		_ = conn.Close()
	}
	if rep != nil {
		return rep, nil
	}
	return nil, nil
}

func redisSend(target string) ([]byte, error) {
	conn, err := tcpConn(target)
	if err != nil {
		return nil, err
	}
	msg := "*1\n$4\ninfo\n"
	_, err = conn.Write([]byte(msg))
	if err != nil {
		return nil, err
	}
	_ = conn.SetDeadline(time.Now().Add(time.Duration(3) * time.Second))
	rep := make([]byte, 256)
	_, _ = conn.Read(rep)
	if conn != nil {
		_ = conn.Close()
	}
	if rep != nil {
		return rep, nil
	}
	return nil, nil
}

func mssqlSend(target string) ([]byte, error) {
	conn, err := tcpConn(target)
	if err != nil {
		return nil, err
	}
	msg := "\x12\x01\x00\x34\x00\x00\x00\x00\x00\x00\x15\x00\x06\x01\x00\x1b\x00\x01\x02\x00\x1c\x00\x0c\x03\x00\x28\x00\x04\xff\x08\x00\x01\x55\x00\x00\x00\x4d\x53\x53\x51\x4c\x53\x65\x72\x76\x65\x72\x00\x48\x0f\x00\x00"
	_, err = conn.Write([]byte(msg))
	if err != nil {
		return nil, err
	}
	_ = conn.SetDeadline(time.Now().Add(time.Duration(3) * time.Second))
	rep := make([]byte, 256)
	_, _ = conn.Read(rep)
	if conn != nil {
		_ = conn.Close()
	}
	if rep != nil {
		return rep, nil
	}
	return nil, nil
}

func smbProgNegSend(target string) ([]byte, error) {
	conn, err := tcpConn(target)
	if err != nil {
		return nil, err
	}
	msg := "\x00\x00\x00\xa4\xff\x53\x4d\x42\x72\x00\x00\x00\x00\x08\x01\x40\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x40\x06\x00\x00\x01\x00\x00\x81\x00\x02PC NETWORK PROGRAM 1.0\x00\x02MICROSOFT NETWORKS 1.03\x00\x02MICROSOFT NETWORKS 3.0\x00\x02LANMAN1.0\x00\x02LM1.2X002\x00\x02Samba\x00\x02NT LANMAN 1.0\x00\x02NT LM 0.12\x00"
	_, err = conn.Write([]byte(msg))
	if err != nil {
		return nil, err
	}
	_ = conn.SetDeadline(time.Now().Add(time.Duration(3) * time.Second))
	rep := make([]byte, 256)
	_, _ = conn.Read(rep)
	if conn != nil {
		_ = conn.Close()
	}
	if rep != nil {
		return rep, nil
	}
	return nil, nil
}

func mongoSend(target string) ([]byte, error) {
	conn, err := tcpConn(target)
	if err != nil {
		return nil, err
	}
	msg := "\x41\x00\x00\x00\x3a\x30\x00\x00\xff\xff\xff\xff\xd4\x07\x00\x00\x00\x00\x00\x00test.$cmd\x00\x00\x00\x00\x00\xff\xff\xff\xff\x1b\x00\x00\x00\x01serverStatus\x00\x00\x00\x00\x00\x00\x00\xf0\x3f\x00"
	_, err = conn.Write([]byte(msg))
	if err != nil {
		return nil, err
	}
	_ = conn.SetDeadline(time.Now().Add(time.Duration(3) * time.Second))
	rep := make([]byte, 256)
	_, _ = conn.Read(rep)
	if conn != nil {
		_ = conn.Close()
	}
	if rep != nil {
		return rep, nil
	}
	return nil, nil
}

func rdpSend(target string) ([]byte, error) {
	conn, err := tcpConn(target)
	if err != nil {
		return nil, err
	}
	msg := "\x03\x00\x00\x2b\x26\xe0\x00\x00\x00\x00\x00\x43\x6f\x6f\x6b\x69\x65\x3a\x20\x6d\x73\x74\x73\x68\x61\x73\x68\x3d\x75\x73\x65\x72\x30\x0d\x0a\x01\x00\x08\x00\x00\x00\x00\x00"
	_, err = conn.Write([]byte(msg))
	if err != nil {
		return nil, err
	}
	_ = conn.SetDeadline(time.Now().Add(time.Duration(3) * time.Second))
	rep := make([]byte, 256)
	_, _ = conn.Read(rep)
	if conn != nil {
		_ = conn.Close()
	}
	if rep != nil {
		return rep, nil
	}
	return nil, nil
}

func (s *Scan) checkWorker() {
	var wg = &sync.WaitGroup{}
	workChan := make(chan struct{}, s.thread/4)
	for service := range s.sendChan {
		service := service
		wg.Add(1)
		workChan <- struct{}{}
		go func() {
			rep, err := defaultSend(service.Target)
			if err != nil {
				wg.Done()
				<-workChan
				return
			}
			if rep != nil {
				s.lock.Lock()
				glg.Infof("[+]发现端口：%s/open", service.Target)
				s.Result[service.Ip].Ports = append(s.Result[service.Ip].Ports, service.Port)
				//service.Rep = append(service.Rep, rep)
				service.Tag = "default"
				service.Rep = []byte(util.Convert(string(rep)))
				s.lock.Unlock()
				//s.repChan <- service
				s.openChan <- service
			}
			wg.Done()
			<-workChan
		}()
	}
	wg.Wait()
	glg.Success("[+]端口扫描已完成！")
	close(s.openChan)
	close(workChan)
}

func (s *Scan) sendWorker() {
	var wg = &sync.WaitGroup{}
	workChan := make(chan struct{}, s.thread/6)
	for openTarget := range s.openChan {
		openTarget := openTarget
		wg.Add(6)
		workChan <- struct{}{}
		go func() {
			rep, err := commonSend(openTarget.Target)
			if err != nil {
				wg.Done()
				return
			}
			if rep != nil {
				var newTarget = &ServiceRep{}
				newTarget.Ip = openTarget.Ip
				newTarget.Port = openTarget.Port
				newTarget.Target = openTarget.Target
				newTarget.Tag = "common"
				newTarget.Rep = []byte(util.Convert(string(rep)))
				s.repChan <- openTarget
			}
			wg.Done()
			<-workChan
		}()
		workChan <- struct{}{}
		go func() {
			rep, err := redisSend(openTarget.Target)
			if err != nil {
				wg.Done()
				return
			}
			if rep != nil {
				var newTarget = &ServiceRep{}
				newTarget.Ip = openTarget.Ip
				newTarget.Port = openTarget.Port
				newTarget.Target = openTarget.Target
				newTarget.Tag = "redis"
				newTarget.Rep = []byte(util.Convert(string(rep)))
				s.repChan <- newTarget
			}
			wg.Done()
			<-workChan
		}()
		workChan <- struct{}{}
		go func() {
			rep, err := mssqlSend(openTarget.Target)
			if err != nil {
				wg.Done()
				return
			}
			if rep != nil {
				var newTarget = &ServiceRep{}
				newTarget.Ip = openTarget.Ip
				newTarget.Port = openTarget.Port
				newTarget.Target = openTarget.Target
				newTarget.Tag = "mssql"
				newTarget.Rep = []byte(util.Convert(string(rep)))
				s.repChan <- newTarget
			}
			wg.Done()
			<-workChan
		}()
		workChan <- struct{}{}
		go func() {
			rep, err := smbProgNegSend(openTarget.Target)
			if err != nil {
				wg.Done()
				return
			}
			if rep != nil {
				var newTarget = &ServiceRep{}
				newTarget.Ip = openTarget.Ip
				newTarget.Port = openTarget.Port
				newTarget.Target = openTarget.Target
				newTarget.Tag = "smb"
				newTarget.Rep = []byte(util.Convert(string(rep)))
				s.repChan <- newTarget
			}
			wg.Done()
			<-workChan
		}()
		workChan <- struct{}{}
		go func() {
			rep, err := mongoSend(openTarget.Target)
			if err != nil {
				wg.Done()
				return
			}
			if rep != nil {
				var newTarget = &ServiceRep{}
				newTarget.Ip = openTarget.Ip
				newTarget.Port = openTarget.Port
				newTarget.Target = openTarget.Target
				newTarget.Tag = "mongo"
				newTarget.Rep = []byte(util.Convert(string(rep)))
				s.repChan <- newTarget
			}
			wg.Done()
			<-workChan
		}()
		workChan <- struct{}{}
		go func() {
			rep, err := rdpSend(openTarget.Target)
			if err != nil {
				wg.Done()
				return
			}
			if rep != nil {
				var newTarget = &ServiceRep{}
				newTarget.Ip = openTarget.Ip
				newTarget.Port = openTarget.Port
				newTarget.Target = openTarget.Target
				newTarget.Tag = "rdp"
				newTarget.Rep = []byte(util.Convert(string(rep)))
				s.repChan <- newTarget
			}
			wg.Done()
			<-workChan
		}()
	}
	wg.Wait()
	close(s.repChan)
	close(workChan)
}
