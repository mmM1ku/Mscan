package util

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"github.com/kpango/glg"
	mail "github.com/xhit/go-simple-mail/v2"
	"io/ioutil"
	"net/http"
	"os"
	"time"
)

// MakeRangeSlice 生成连续切片，给全端口号使用
func MakeRangeSlice(min, max int) []int {
	s := make([]int, max-min+1)
	for i := range s {
		s[i] = min + i
	}
	return s
}

// ReadDicFile 读取字典文件
func ReadDicFile(dir string) []string {
	var list []string
	file, err := os.Open(dir)
	if err != nil {
		glg.Error(err)
	}
	defer file.Close()

	buf := bufio.NewScanner(file)
	for {
		if !buf.Scan() {
			break
		}
		line := buf.Text()
		list = append(list, line)
	}
	return list
}

// GetProgress 获取当前完成扫描队列
func GetProgress(now int64, total int64) {
	if now == total {
		glg.Logf("[+]当前已完成队列: %v/%v", now, total)
	} else {
		glg.Logf("[+]当前已完成队列: %v/%v", now, total)
	}
}

// TimeCost 计算扫描耗时
func TimeCost() func() {
	start := time.Now()
	return func() {
		cost := time.Since(start)
		glg.Successf("[+]本次扫描耗时：%v", cost)
	}
}

// InitLogo 初始化logo
func InitLogo() {
	var str = "███╗   ███╗███████╗ ██████╗ █████╗ ███╗   ██╗\n████╗ ████║██╔════╝██╔════╝██╔══██╗████╗  ██║\n██╔████╔██║███████╗██║     ███████║██╔██╗ ██║\n██║╚██╔╝██║╚════██║██║     ██╔══██║██║╚██╗██║\n██║ ╚═╝ ██║███████║╚██████╗██║  ██║██║ ╚████║\n╚═╝     ╚═╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝\n\nauthor: M1ku    Version:0.1\n"
	fmt.Println(str)
}

// 读取config配置文件
func readConfig() ([]byte, error) {
	content, err := ioutil.ReadFile("./config.yaml")
	if err != nil {
		return nil, err
	}
	return content, nil
}

// Email 发送email功能
func Email(addr, user, pass, to string, port int, result []Result) {
	server := mail.NewSMTPClient()
	server.Host = addr
	server.Port = port
	server.Username = user
	server.Password = pass

	var htmlBody = "<table border=\"1\"><tr><td>地址</td><td>用户名</td><td>密码</td></tr>"
	for _, res := range result {
		htmlBody = htmlBody + "<tr><td>" + *res.Addr + "</td><td>" + res.User + "</td><td>" + res.Pass + "</td></tr>"
	}
	htmlBody = htmlBody + "</table>"

	server.ConnectTimeout = 6 * time.Second
	server.SendTimeout = 6 * time.Second
	server.TLSConfig = &tls.Config{InsecureSkipVerify: true}

	client, err := server.Connect()
	if err != nil {
		glg.Error(err)
	}

	email := mail.NewMSG()
	email.SetFrom(user).AddTo(to).SetSubject("WeakPass")
	email.SetBody(mail.TextHTML, htmlBody)

	err = email.Send(client)
	if err != nil {
		glg.Error(err)
	} else {
		glg.Success("Email sent successfully")
	}
}

func Client() *http.Client {
	//log.SetOutput(ioutil.Discard)
	return &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
			/*DialContext: (&net.Dialer{
				Timeout: 10 * time.Second,
			}).DialContext,*/
			MaxResponseHeaderBytes: 5 * 1024,
			MaxIdleConns:           100,
			//TLSHandshakeTimeout:    5 * time.Second,
		},
		/*CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},*/
	}
}
