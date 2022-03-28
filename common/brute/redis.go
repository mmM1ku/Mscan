package brute

import (
	"github.com/gomodule/redigo/redis"
	"github.com/kpango/glg"
	"net"
	"strings"
	"time"
)

func redisUnauth(addr string) bool {
	conn, err := tcpConn(addr)
	if err != nil {
		return false
	}
	msg := "*1\r\n$4\r\ninfo\r\n"
	_, err = conn.Write([]byte(msg))
	if err != nil {
		return false
	}
	_ = conn.SetDeadline(time.Now().Add(time.Duration(3) * time.Second))
	rep := make([]byte, 256)
	_, _ = conn.Read(rep)
	if conn != nil {
		_ = conn.Close()
	}
	if rep != nil {
		if strings.Contains(string(rep), "redis_version") {
			return true
		}
	}
	return false
}

func redisCon(addr string) error {
	client, err := redis.Dial("tcp", addr)
	if err != nil {
		return err
	}
	defer client.Close()
	if client.Err() != nil {
		return client.Err()
	}
	return nil
}

func (b *Brute) redisBrute(target string) {
	//test unauth
	if redisUnauth(target) {
		glg.Warnf("[!]%s 存在redis未授权漏洞", target)
		b.BruteResult.Store(target, "redis未授权访问")
	}
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
