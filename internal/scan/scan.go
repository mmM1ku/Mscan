package scan

import (
	"Mscan/internal/logger"
	"bytes"
	"fmt"
	"net"
	"os/exec"
	"runtime"
	"time"
)

// ping 使用ping进行主机探活
func ping(addr string) bool {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	//linux、mac ping 超时单位为s,windows为ms
	case "windows":
		cmd = exec.Command("ping", addr, "-n", "1", "-w", "3000")
	case "linux":
		cmd = exec.Command("ping", addr, "-c", "1", "-w", "3", "-W", "3")
	case "darwin":
		cmd = exec.Command("ping", addr, "-c", "1", "-W", "3")
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

// TcpConn 建立TCP连接
func TcpConn(target string) error {
	conn, err := net.DialTimeout("tcp", target, time.Duration(2)*time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()
	err = conn.SetDeadline(time.Now().Add(time.Duration(2) * time.Second))
	//探测端口是否存活
	rep := make([]byte, 256)
	var buf [256]byte
	/*_, err = conn.Read(rep)
	fmt.Println(string(rep))
	if err == nil && bytes.Equal(rep[:], buf[:]) == false {
		if conn != nil {
			logger.Logger.Infof("发现存活端口:%v", target)
			return nil
		}
	}*/
	msg := "OPTIONS / HTTP/1.1\r\n\r\n"
	_, err = conn.Write([]byte(msg))
	if err != nil {
		return err
	}
	rep = make([]byte, 256)
	_, err = conn.Read(rep)
	fmt.Println(string(rep))
	if err == nil && bytes.Equal(rep[:], buf[:]) == false {
		if conn != nil {
			logger.Logger.Infof("发现存活端口:%v", target)
			return nil
		}
	}
	return err
}
